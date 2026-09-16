<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Api\V1\Concerns\LogsApiErrors;

use App\Data\Api\V1\GatewayData;
use App\Exceptions\ApiException;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\StoreGatewayRequest;
use App\Http\Requests\Api\V1\UpdateGatewayRequest;
use App\Models\Domain;
use App\Models\Gateways;
use App\Services\AccessControlService;
use App\Services\FreeswitchEslService;
use App\Services\GatewayService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class GatewayController extends Controller
{
    use LogsApiErrors;

    /**
     * Columns of v_gateways that GatewayService::saveData() reads as input.
     * Used to rebuild the full payload on a PATCH: saveData() turns every key it
     * does not find into null, which would wipe the fields absent from the body.
     */
    private const INPUT_FIELDS = [
        'gateway', 'username', 'password', 'distinct_to', 'auth_username', 'realm',
        'from_user', 'from_domain', 'proxy', 'register_proxy', 'outbound_proxy',
        'expire_seconds', 'register', 'register_transport', 'contact_params',
        'retry_seconds', 'extension', 'ping', 'ping_min', 'ping_max', 'contact_in_ping',
        'channels', 'caller_id_in_from', 'supress_cng', 'sip_cid_type', 'codec_prefs',
        'extension_in_contact', 'context', 'profile', 'hostname', 'enabled', 'description',
    ];

    /** Fields the API takes as JSON booleans and v_gateways stores as TEXT. */
    private const TEXT_BOOLEAN_FIELDS = [
        'register', 'enabled', 'distinct_to', 'contact_in_ping',
        'caller_id_in_from', 'supress_cng', 'extension_in_contact',
    ];

    /**
     * Create a gateway
     *
     * Creates a SIP gateway in the given domain, then, outside the transaction,
     * reloads the access control lists, rescans the Sofia profile and starts the
     * gateway when `enabled` is true.
     *
     * The `{domain_uuid}` of the route is the only source of truth for the
     * attachment: a `domain_uuid` sent in the body is ignored.
     *
     * The SIP `password` is write-only and is never returned.
     *
     * @group Gateways
     * @authenticated
     *
     * @urlParam domain_uuid string required The domain UUID. Example: 4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b
     *
     * @response 400 scenario="Invalid domain UUID" {"error":{"type":"invalid_request_error","message":"Invalid domain UUID.","code":"invalid_request","param":"domain_uuid"}}
     * @response 401 scenario="Unauthenticated" {"error":{"type":"authentication_error","message":"Unauthenticated.","code":"unauthenticated"}}
     * @response 404 scenario="Domain not found" {"error":{"type":"invalid_request_error","message":"Domain not found.","code":"resource_missing","param":"domain_uuid"}}
     * @response 500 scenario="Internal server error" {"error":{"type":"api_error","message":"Internal server error.","code":"internal_error"}}
     */
    public function store(
        StoreGatewayRequest $request,
        string $domain_uuid,
        GatewayService $service,
        AccessControlService $accessControlService,
        FreeswitchEslService $eslService
    ) {
        $this->guardDomain($request, $domain_uuid);

        $validated = $request->validated();
        $data = $service->saveData($this->toTextBooleans($validated));

        // saveData() resolves both of these through userCheckPermission()/session(),
        // which are inert under a Bearer token: without this the gateway would be
        // created with a null domain and channels forced to 0.
        $data['domain_uuid'] = $domain_uuid;
        $data['channels'] = (int) ($validated['channels'] ?? 0);

        try {
            $gateway = DB::transaction(function () use ($data, $validated, $accessControlService) {
                $gateway = new Gateways();
                $gateway->forceFill($data)->save();
                $accessControlService->syncGatewayProviderIps($gateway, $validated['gateway_acl_cidrs'] ?? null);

                return $gateway;
            });

            // Outside the transaction: FreeSWITCH side effects.
            $aclResponse = $accessControlService->sync();
            $service->sync(collect([$gateway->profile]));
            $switchResponse = $gateway->enabled === 'true'
                ? $service->executeGatewayCommand('start', $gateway)
                : 'Skipped: gateway is disabled.';

            $payload = GatewayData::fromModel(
                $gateway,
                $this->switchStatus($eslService, (string) $gateway->gateway_uuid),
                $switchResponse,
                $aclResponse
            );

            return response()
                ->json($payload->toArray(), 201)
                ->header('Location', "/api/v1/domains/{$domain_uuid}/gateways/{$gateway->gateway_uuid}");
        } catch (\Throwable $e) {
            $this->logApiError('API Gateway store error', $e);
            throw new ApiException(500, 'api_error', 'Internal server error.', 'internal_error');
        }
    }

    /**
     * Retrieve a gateway
     *
     * Returns the stored configuration together with the state seen by the
     * telephony engine, read over the event socket (`sofia xmlstatus gateway`)
     * and matched on `gateway_uuid`.
     *
     * When the event socket is unreachable, `state` is `UNKNOWN` and
     * `ping_state` / `ping_time_ms` are null: no state is not a missing gateway.
     *
     * @group Gateways
     * @authenticated
     *
     * @urlParam domain_uuid string required The domain UUID. Example: 4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b
     * @urlParam gateway_uuid string required The gateway UUID. Example: 47aa96db-3f70-46ce-bb9a-79ccef396f2b
     *
     * @response 404 scenario="Gateway not found" {"error":{"type":"invalid_request_error","message":"Gateway not found.","code":"resource_missing","param":"gateway_uuid"}}
     */
    public function show(
        Request $request,
        string $domain_uuid,
        string $gateway_uuid,
        FreeswitchEslService $eslService
    ) {
        $gateway = $this->findGateway($request, $domain_uuid, $gateway_uuid);

        try {
            $payload = GatewayData::fromModel(
                $gateway,
                $this->switchStatus($eslService, (string) $gateway->gateway_uuid)
            );

            return response()->json($payload->toArray(), 200);
        } catch (\Throwable $e) {
            $this->logApiError('API Gateway show error', $e);
            throw new ApiException(500, 'api_error', 'Internal server error.', 'internal_error');
        }
    }

    /**
     * Update a gateway
     *
     * Partial update: only the fields present in the body are applied, the others
     * keep their stored value. When `profile` changes, both the old and the new
     * Sofia profile are rescanned.
     *
     * Sending `gateway_acl_cidrs` replaces the whole provider IP allow-list of
     * this gateway; an empty array clears it. Omitting it leaves it untouched.
     *
     * @group Gateways
     * @authenticated
     *
     * @urlParam domain_uuid string required The domain UUID. Example: 4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b
     * @urlParam gateway_uuid string required The gateway UUID. Example: 47aa96db-3f70-46ce-bb9a-79ccef396f2b
     */
    public function update(
        UpdateGatewayRequest $request,
        string $domain_uuid,
        string $gateway_uuid,
        GatewayService $service,
        AccessControlService $accessControlService,
        FreeswitchEslService $eslService
    ) {
        $gateway = $this->findGateway($request, $domain_uuid, $gateway_uuid);

        $validated = $request->validated();

        // Capture the profile BEFORE forceFill: both profiles must be rescanned.
        $oldProfile = $gateway->profile;

        $merged = array_merge(
            $gateway->only(self::INPUT_FIELDS),
            $this->toTextBooleans($validated)
        );

        $data = $service->saveData($merged, $gateway);
        $data['domain_uuid'] = $domain_uuid;
        $data['channels'] = array_key_exists('channels', $validated)
            ? (int) $validated['channels']
            : (int) ($gateway->channels ?? 0);

        try {
            DB::transaction(function () use ($gateway, $data, $validated, $accessControlService) {
                $gateway->forceFill($data)->save();

                // Only when the caller submitted the field: syncGatewayProviderIps()
                // treats null as "no CIDR" and would delete the stored allow-list.
                if (array_key_exists('gateway_acl_cidrs', $validated)) {
                    $accessControlService->syncGatewayProviderIps($gateway, $validated['gateway_acl_cidrs']);
                }
            });

            $aclResponse = $accessControlService->sync();
            $service->sync(collect([$oldProfile, $gateway->profile]));

            $payload = GatewayData::fromModel(
                $gateway,
                $this->switchStatus($eslService, (string) $gateway->gateway_uuid),
                null,
                $aclResponse
            );

            return response()->json($payload->toArray(), 200);
        } catch (\Throwable $e) {
            $this->logApiError('API Gateway update error', $e);
            throw new ApiException(500, 'api_error', 'Internal server error.', 'internal_error');
        }
    }

    /**
     * Delete a gateway
     *
     * Stops the gateway on the engine (`sofia profile <profile> killgw <uuid>`)
     * before deleting it, removes the allow-list nodes it owned, then reloads the
     * access control lists and rescans the profile.
     *
     * @group Gateways
     * @authenticated
     *
     * @urlParam domain_uuid string required The domain UUID. Example: 4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b
     * @urlParam gateway_uuid string required The gateway UUID. Example: 47aa96db-3f70-46ce-bb9a-79ccef396f2b
     *
     * @response 204 scenario="Deleted" {}
     */
    public function destroy(
        Request $request,
        string $domain_uuid,
        string $gateway_uuid,
        GatewayService $service,
        AccessControlService $accessControlService
    ) {
        $gateway = $this->findGateway($request, $domain_uuid, $gateway_uuid);
        $profile = $gateway->profile;

        try {
            DB::transaction(function () use ($gateway, $service, $accessControlService) {
                $service->executeGatewayCommand('stop', $gateway);
                $gateway->delete();
                $accessControlService->removeGatewayProviderIps($gateway);
            });

            $accessControlService->sync();
            $service->sync(collect([$profile]));

            return response()->noContent();
        } catch (\Throwable $e) {
            $this->logApiError('API Gateway delete error', $e);
            throw new ApiException(500, 'api_error', 'Internal server error.', 'internal_error');
        }
    }

    /**
     * Restart a gateway on the telephony engine
     *
     * Rescans the Sofia profile, then restarts the gateway. Nothing is written to
     * the database. `202` means the command was accepted, not that the gateway is
     * registered again: poll `GET /gateways/{gateway_uuid}` to watch it reach
     * `REGED`.
     *
     * A disabled gateway answers `202` with
     * `switch_response = "Skipped: gateway is disabled."` — no command is sent.
     * An engine answer starting with `-ERR` (unreachable event socket included)
     * answers `422`.
     *
     * @group Gateways
     * @authenticated
     *
     * @urlParam domain_uuid string required The domain UUID. Example: 4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b
     * @urlParam gateway_uuid string required The gateway UUID. Example: 47aa96db-3f70-46ce-bb9a-79ccef396f2b
     *
     * @response 202 scenario="Accepted" {"object":"gateway","gateway_uuid":"47aa96db-3f70-46ce-bb9a-79ccef396f2b","switch_response":"+OK"}
     * @response 422 scenario="Switch error" {"error":{"type":"invalid_request_error","message":"-ERR Could not connect to FreeSWITCH event socket.","code":"switch_error"}}
     */
    public function restart(
        Request $request,
        string $domain_uuid,
        string $gateway_uuid,
        GatewayService $service
    ) {
        $gateway = $this->findGateway($request, $domain_uuid, $gateway_uuid);

        // Rescan before the start, as the SPA does in bulkGatewayCommand().
        $service->sync(collect([$gateway->profile]));

        $switchResponse = $service->executeGatewayCommand('start', $gateway) ?: 'No response from FreeSWITCH.';

        if (str_starts_with(trim($switchResponse), '-ERR')) {
            throw new ApiException(422, 'invalid_request_error', $switchResponse, 'switch_error');
        }

        return response()->json([
            'object' => 'gateway',
            'gateway_uuid' => (string) $gateway->gateway_uuid,
            'switch_response' => $switchResponse,
        ], 202);
    }

    /**
     * 401 / 400 / 404 guards on the domain. The permission and the domain scope
     * are already enforced by the `user.authorize` middleware.
     */
    private function guardDomain(Request $request, string $domain_uuid): void
    {
        $this->guardRequest($request, $domain_uuid);
        $this->requireDomain($domain_uuid);
    }

    /**
     * Same guards plus the gateway itself, scoped to the domain of the route.
     * Format checks come before any query, as DeviceController does.
     */
    private function findGateway(Request $request, string $domain_uuid, string $gateway_uuid): Gateways
    {
        $this->guardRequest($request, $domain_uuid);

        if (! preg_match('/^[0-9a-fA-F-]{36}$/', $gateway_uuid)) {
            throw new ApiException(400, 'invalid_request_error', 'Invalid gateway UUID.', 'invalid_request', 'gateway_uuid');
        }

        $this->requireDomain($domain_uuid);

        $gateway = Gateways::query()
            ->where('domain_uuid', $domain_uuid)
            ->where('gateway_uuid', $gateway_uuid)
            ->first();

        if (! $gateway) {
            throw new ApiException(404, 'invalid_request_error', 'Gateway not found.', 'resource_missing', 'gateway_uuid');
        }

        return $gateway;
    }

    /**
     * 401 and the domain UUID format — no query yet.
     */
    private function guardRequest(Request $request, string $domain_uuid): void
    {
        if (! $request->user()) {
            throw new ApiException(401, 'authentication_error', 'Unauthenticated.', 'unauthenticated');
        }

        if (! preg_match('/^[0-9a-fA-F-]{36}$/', $domain_uuid)) {
            throw new ApiException(400, 'invalid_request_error', 'Invalid domain UUID.', 'invalid_request', 'domain_uuid');
        }
    }

    private function requireDomain(string $domain_uuid): void
    {
        $domain = Domain::query()
            ->where('domain_uuid', $domain_uuid)
            ->first(['domain_uuid']);

        if (! $domain) {
            throw new ApiException(404, 'invalid_request_error', 'Domain not found.', 'resource_missing', 'domain_uuid');
        }
    }

    /**
     * Turns the JSON booleans of the contract into the TEXT values v_gateways holds.
     */
    private function toTextBooleans(array $validated): array
    {
        foreach (self::TEXT_BOOLEAN_FIELDS as $field) {
            if (! array_key_exists($field, $validated) || $validated[$field] === null) {
                continue;
            }

            $validated[$field] = filter_var($validated[$field], FILTER_VALIDATE_BOOLEAN) ? 'true' : 'false';
        }

        return $validated;
    }

    /**
     * Reads the gateway state from the engine, the same source as the admin UI.
     * An unreachable event socket yields an empty status, which GatewayData turns
     * into `UNKNOWN` — never a 500.
     *
     * @return array{state?: string, ping_state?: string, ping_time_ms?: string}
     */
    private function switchStatus(FreeswitchEslService $eslService, string $gateway_uuid): array
    {
        try {
            if (! $eslService->isConnected()) {
                return [];
            }

            $response = $eslService->executeCommand('sofia xmlstatus gateway', false);
            $eslService->disconnect();

            if (! $response instanceof \SimpleXMLElement || ! isset($response->gateway)) {
                return [];
            }

            foreach ($response->gateway as $row) {
                if (strtolower(trim((string) $row->name)) !== strtolower($gateway_uuid)) {
                    continue;
                }

                return array_filter([
                    'state' => trim((string) $row->state),
                    'ping_state' => trim((string) $row->pingstate),
                    'ping_time_ms' => trim((string) $row->pingtime),
                ], 'strlen');
            }

            return [];
        } catch (\Throwable $e) {
            $this->logApiError('API Gateway switch status error', $e);

            return [];
        }
    }
}
