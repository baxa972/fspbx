<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Api\V1\Concerns\LogsApiErrors;

use App\Data\Api\V1\DialplanData;
use App\Data\Api\V1\DialplanListResponseData;
use App\Exceptions\ApiException;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\StoreDialplanRequest;
use App\Http\Requests\Api\V1\UpdateDialplanRequest;
use App\Models\DialplanDetails;
use App\Models\Dialplans;
use App\Models\Domain;
use App\Services\DialplanService;
use App\Services\FreeswitchEslService;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Http\Request;

/**
 * Dialplans of a domain: v_dialplans and its lines in v_dialplan_details.
 *
 * DialplanService::save() writes both tables in one transaction and clears the
 * dialplan cache of the context, but it does NOT reload the engine. Every write
 * here therefore issues `bgapi reloadxml` afterwards, outside the transaction,
 * and returns its raw answer in `switch_response`: a plan written but never
 * reloaded is a plan FreeSWITCH does not route yet.
 */
class DialplanController extends Controller
{
    use LogsApiErrors;

    /** Fields the API takes as JSON booleans and v_dialplans stores as TEXT. */
    private const TEXT_BOOLEAN_FIELDS = ['dialplan_continue', 'dialplan_enabled', 'dialplan_destination'];

    /**
     * Attributes DialplanService::save() reads WITHOUT a fallback, or with a
     * `?? null` that empties the column. On a PATCH they are all refilled from
     * the stored plan, otherwise a partial body would erase what it omits.
     */
    private const INPUT_FIELDS = [
        'dialplan_name', 'dialplan_number', 'dialplan_destination', 'dialplan_context',
        'dialplan_continue', 'dialplan_order', 'dialplan_enabled', 'dialplan_description',
        'hostname',
    ];

    private const SWITCH_UNREACHABLE = '-ERR Could not connect to FreeSWITCH event socket.';

    private const RELOAD_COMMAND = 'bgapi reloadxml';

    /**
     * List the dialplans of a domain
     *
     * Cursor pagination: `limit` (1–100, 50 by default) and `starting_after`, the
     * `dialplan_uuid` of the last entry of the previous page. There is no `page`.
     *
     * The entries do not carry their lines: read one plan to get them.
     *
     * @group Dialplans
     * @authenticated
     *
     * @urlParam domain_uuid string required The domain UUID. Example: 4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b
     * @queryParam limit integer Optional. Number of results (1–100). Defaults to 50. Example: 50
     * @queryParam starting_after string Optional. Return results after this dialplan UUID (cursor). Example: 8c0f2b1d-1f2e-4a3b-9c4d-5e6f7a8b9c0d
     *
     * @response 200 scenario="Success" {
     *   "object": "list",
     *   "url": "/api/v1/domains/4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b/dialplans",
     *   "has_more": false,
     *   "data": [
     *     {
     *       "dialplan_uuid": "8c0f2b1d-1f2e-4a3b-9c4d-5e6f7a8b9c0d",
     *       "object": "dialplan",
     *       "domain_uuid": "4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b",
     *       "dialplan_name": "callpulse_ai_9001",
     *       "dialplan_number": "9001",
     *       "dialplan_context": "client.exemple.fr",
     *       "dialplan_order": 100,
     *       "dialplan_enabled": true,
     *       "dialplan_continue": false,
     *       "dialplan_destination": false,
     *       "dialplan_description": "Extension IA CallPulse"
     *     }
     *   ]
     * }
     * @response 400 scenario="Invalid starting_after UUID" {"error":{"type":"invalid_request_error","message":"Invalid starting_after UUID.","code":"invalid_request","param":"starting_after"}}
     * @response 401 scenario="Unauthenticated" {"error":{"type":"authentication_error","message":"Unauthenticated.","code":"unauthenticated"}}
     * @response 404 scenario="Domain not found" {"error":{"type":"invalid_request_error","message":"Domain not found.","code":"resource_missing","param":"domain_uuid"}}
     */
    public function index(Request $request, string $domain_uuid)
    {
        $this->guardDomain($request, $domain_uuid);

        $limit = max(1, min(100, (int) $request->input('limit', 50)));
        $startingAfter = (string) $request->input('starting_after', '');

        if ($startingAfter !== '' && ! $this->isUuid($startingAfter)) {
            throw new ApiException(400, 'invalid_request_error', 'Invalid starting_after UUID.', 'invalid_request', 'starting_after');
        }

        try {
            $query = Dialplans::query()
                ->where('domain_uuid', $domain_uuid)
                ->orderBy('dialplan_uuid')
                ->limit($limit + 1)
                // dialplan_xml is never selected: it is not exposed, and it is the
                // heaviest column of the table.
                ->select([
                    'dialplan_uuid', 'domain_uuid', 'dialplan_name', 'dialplan_number',
                    'dialplan_context', 'dialplan_order', 'dialplan_enabled',
                    'dialplan_continue', 'dialplan_destination', 'dialplan_description',
                ]);

            if ($startingAfter !== '') {
                $query->where('dialplan_uuid', '>', $startingAfter);
            }

            $rows = $query->get();
            $hasMore = $rows->count() > $limit;

            $payload = new DialplanListResponseData(
                object: 'list',
                url: "/api/v1/domains/{$domain_uuid}/dialplans",
                has_more: $hasMore,
                data: $rows->take($limit)
                    ->map(fn (Dialplans $dialplan) => DialplanData::summary($dialplan))
                    ->values()
                    ->all(),
            );

            return response()->json($payload->toArray(), 200);
        } catch (\Throwable $e) {
            $this->logApiError('API Dialplan index error', $e);
            throw new ApiException(500, 'api_error', 'Internal server error.', 'internal_error');
        }
    }

    /**
     * Create a dialplan and its lines
     *
     * Writes v_dialplans AND v_dialplan_details from `details`, in the single
     * transaction DialplanService::save() opens, then issues `bgapi reloadxml`.
     *
     * A creation that writes no line produces a plan that routes nothing, so
     * `details` is required and must hold at least one line in builder mode.
     *
     * The `{domain_uuid}` of the route is the only source of truth; a
     * `domain_uuid` in the body is ignored.
     *
     * @group Dialplans
     * @authenticated
     *
     * @urlParam domain_uuid string required The domain UUID. Example: 4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b
     *
     * @response 400 scenario="Invalid parameter" {"error":{"type":"invalid_request_error","message":"This FreeSWITCH application is not allowed.","code":"invalid_parameter","param":"details.1.dialplan_detail_type"}}
     * @response 401 scenario="Unauthenticated" {"error":{"type":"authentication_error","message":"Unauthenticated.","code":"unauthenticated"}}
     * @response 404 scenario="Domain not found" {"error":{"type":"invalid_request_error","message":"Domain not found.","code":"resource_missing","param":"domain_uuid"}}
     * @response 500 scenario="Internal server error" {"error":{"type":"api_error","message":"Internal server error.","code":"internal_error"}}
     */
    public function store(
        StoreDialplanRequest $request,
        string $domain_uuid,
        DialplanService $service,
        FreeswitchEslService $eslService
    ) {
        $this->guardDomain($request, $domain_uuid);

        $payload = self::toServicePayload($request->validated(), $domain_uuid);

        try {
            // save() opens its OWN transaction: never wrap it in a second one.
            $dialplan = $service->save($payload);

            // session('user_uuid') is null under a Bearer token, so the service
            // writes no author: it is stamped here instead.
            $this->stampAuthor($dialplan, $request, 'insert_user');

            // Outside the transaction: the engine still serves the previous XML
            // until it is told to re-read it.
            $switchResponse = $this->reloadXml($eslService);

            $data = DialplanData::fromModel($dialplan, $this->storedDetails($dialplan), $switchResponse);

            return response()
                ->json($data->toArray(), 201)
                ->header('Location', "/api/v1/domains/{$domain_uuid}/dialplans/{$dialplan->dialplan_uuid}");
        } catch (\Throwable $e) {
            $this->logApiError('API Dialplan store error', $e);
            throw new ApiException(500, 'api_error', 'Internal server error.', 'internal_error');
        }
    }

    /**
     * Retrieve a dialplan and its lines
     *
     * The plan must belong to the domain of the route: a valid UUID attached to
     * another domain answers 404, not 403.
     *
     * The lines come back sorted by `dialplan_detail_group` then
     * `dialplan_detail_order` — the order the engine reads them in.
     *
     * @group Dialplans
     * @authenticated
     *
     * @urlParam domain_uuid string required The domain UUID. Example: 4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b
     * @urlParam dialplan_uuid string required The dialplan UUID. Example: 8c0f2b1d-1f2e-4a3b-9c4d-5e6f7a8b9c0d
     *
     * @response 400 scenario="Invalid dialplan UUID" {"error":{"type":"invalid_request_error","message":"Invalid dialplan UUID.","code":"invalid_request","param":"dialplan_uuid"}}
     * @response 404 scenario="Not found" {"error":{"type":"invalid_request_error","message":"Dialplan not found.","code":"resource_missing","param":"dialplan_uuid"}}
     */
    public function show(Request $request, string $domain_uuid, string $dialplan_uuid)
    {
        $dialplan = $this->findDialplan($request, $domain_uuid, $dialplan_uuid);

        try {
            return response()->json(
                DialplanData::fromModel($dialplan, $this->storedDetails($dialplan))->toArray(),
                200
            );
        } catch (\Throwable $e) {
            $this->logApiError('API Dialplan show error', $e);
            throw new ApiException(500, 'api_error', 'Internal server error.', 'internal_error');
        }
    }

    /**
     * Update a dialplan
     *
     * Partial update: only the attributes present in the body are applied, the
     * others keep their stored value.
     *
     * `details` is a WHOLE-SET replacement: sending it deletes every stored line
     * and re-inserts exactly the ones received, then rebuilds the XML. There is
     * no line-by-line edit — read the plan, change the array, send it back whole.
     * `details: []` therefore leaves the plan with no line at all.
     *
     * Omitting `details` keeps the stored lines: this controller resends them to
     * the service, which would otherwise rebuild the plan without a single line.
     *
     * The same guards as the creation apply (dangerous applications, XML
     * validation). `bgapi reloadxml` is issued and reported in `switch_response`.
     *
     * @group Dialplans
     * @authenticated
     *
     * @urlParam domain_uuid string required The domain UUID. Example: 4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b
     * @urlParam dialplan_uuid string required The dialplan UUID. Example: 8c0f2b1d-1f2e-4a3b-9c4d-5e6f7a8b9c0d
     */
    public function update(
        UpdateDialplanRequest $request,
        string $domain_uuid,
        string $dialplan_uuid,
        DialplanService $service,
        FreeswitchEslService $eslService
    ) {
        $dialplan = $this->findDialplan($request, $domain_uuid, $dialplan_uuid);

        $payload = array_merge(
            $this->storedPayload($dialplan),
            self::toServicePayload($request->validated(), $domain_uuid)
        );

        try {
            $dialplan = $service->save($payload, $dialplan);
            $this->stampAuthor($dialplan, $request, 'update_user');

            $switchResponse = $this->reloadXml($eslService);

            return response()->json(
                DialplanData::fromModel($dialplan, $this->storedDetails($dialplan), $switchResponse)->toArray(),
                200
            );
        } catch (\Throwable $e) {
            $this->logApiError('API Dialplan update error', $e);
            throw new ApiException(500, 'api_error', 'Internal server error.', 'internal_error');
        }
    }

    /**
     * Delete a dialplan
     *
     * Deletes the plan AND all of its lines, clears the cache of the context,
     * then issues `bgapi reloadxml`.
     *
     * Answers 204 with no body, so the result of the reload is not observable
     * here: to check that the engine took it into account, call
     * `POST /domains/{domain_uuid}/dialplans/reload`, which answers 422 when the
     * engine is unreachable.
     *
     * @group Dialplans
     * @authenticated
     *
     * @urlParam domain_uuid string required The domain UUID. Example: 4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b
     * @urlParam dialplan_uuid string required The dialplan UUID. Example: 8c0f2b1d-1f2e-4a3b-9c4d-5e6f7a8b9c0d
     *
     * @response 204 scenario="Deleted" {}
     */
    public function destroy(
        Request $request,
        string $domain_uuid,
        string $dialplan_uuid,
        DialplanService $service,
        FreeswitchEslService $eslService
    ) {
        $dialplan = $this->findDialplan($request, $domain_uuid, $dialplan_uuid);

        try {
            // delete() removes the lines then the plan, in its own transaction.
            $service->delete(new Collection([$dialplan]));

            $this->reloadXml($eslService);

            return response()->noContent();
        } catch (\Throwable $e) {
            $this->logApiError('API Dialplan delete error', $e);
            throw new ApiException(500, 'api_error', 'Internal server error.', 'internal_error');
        }
    }

    /**
     * Reload the dialplan XML in FreeSWITCH
     *
     * Issues `bgapi reloadxml` on the event socket. Nothing is written.
     *
     * An engine answer carrying `-ERR` — an unreachable event socket included —
     * answers 422: a reload that did not happen is never reported as a success,
     * which is what would let one believe a new extension is reachable while the
     * engine still serves the previous plan.
     *
     * The reload is asynchronous on the FreeSWITCH side (`bgapi`), so a 200 only
     * attests that the command was delivered.
     *
     * @group Dialplans
     * @authenticated
     *
     * @urlParam domain_uuid string required The domain UUID. Example: 4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b
     *
     * @response 200 scenario="Reloaded" {"object":"dialplan_reload","switch_response":"+OK Job-UUID: 4f2c..."}
     * @response 422 scenario="Switch error" {"error":{"type":"invalid_request_error","message":"-ERR Could not connect to FreeSWITCH event socket.","code":"switch_error"}}
     */
    public function reload(Request $request, string $domain_uuid, FreeswitchEslService $eslService)
    {
        $this->guardDomain($request, $domain_uuid);

        $switchResponse = $this->reloadXml($eslService);

        if (str_contains($switchResponse, '-ERR')) {
            throw new ApiException(422, 'invalid_request_error', $switchResponse, 'switch_error');
        }

        return response()->json([
            'object' => 'dialplan_reload',
            'switch_response' => $switchResponse,
        ], 200);
    }

    /**
     * Turns a validated body into what DialplanService::save() expects.
     *
     * Two translations, and the whole endpoint depends on them:
     *
     *  - `details` (the name of the contract) becomes `dialplan_details` (the key
     *    the service reads). Without it, save() receives no line, writes the plan
     *    with ZERO detail row and still answers 201 — the inert plan.
     *  - the JSON booleans become the TEXT 'true' / 'false' of v_dialplans. Only
     *    `dialplan_enabled` has a model mutator; `dialplan_continue` and
     *    `dialplan_destination` are force-filled raw, and a PHP false would land
     *    in the column as an empty string.
     *
     * Public and static so both translations can be proven by a test that needs
     * no database.
     *
     * @param  array<string, mixed>  $validated
     * @return array<string, mixed>
     */
    public static function toServicePayload(array $validated, string $domain_uuid): array
    {
        foreach (self::TEXT_BOOLEAN_FIELDS as $field) {
            if (array_key_exists($field, $validated) && $validated[$field] !== null) {
                $validated[$field] = filter_var($validated[$field], FILTER_VALIDATE_BOOLEAN) ? 'true' : 'false';
            }
        }

        if (array_key_exists('details', $validated)) {
            $validated['dialplan_details'] = $validated['details'];
        }

        unset($validated['details']);

        // The route is the only source of truth for the attachment.
        $validated['domain_uuid'] = $domain_uuid;

        return $validated;
    }

    /**
     * Everything save() would erase if the PATCH does not mention it, read from
     * the stored plan: the attributes, the raw XML and the lines.
     *
     * @return array<string, mixed>
     */
    private function storedPayload(Dialplans $dialplan): array
    {
        $details = $this->storedDetails($dialplan);

        return [
            'dialplan_name' => $dialplan->dialplan_name,
            'dialplan_number' => $dialplan->dialplan_number,
            // Raw values: these columns hold the TEXT 'true' / 'false'.
            'dialplan_destination' => $dialplan->getRawOriginal('dialplan_destination'),
            'dialplan_context' => $dialplan->dialplan_context,
            'dialplan_continue' => $dialplan->getRawOriginal('dialplan_continue'),
            'dialplan_order' => $dialplan->dialplan_order,
            'dialplan_enabled' => $dialplan->getRawOriginal('dialplan_enabled'),
            'dialplan_description' => $dialplan->dialplan_description,
            'hostname' => $dialplan->hostname,
            'dialplan_xml' => $dialplan->dialplan_xml,
            'editor_mode' => $this->storedEditorMode($dialplan, $details),
            'dialplan_details' => $details
                ->map(fn (DialplanDetails $detail) => [
                    'dialplan_detail_tag' => $detail->getRawOriginal('dialplan_detail_tag'),
                    'dialplan_detail_type' => $detail->getRawOriginal('dialplan_detail_type'),
                    'dialplan_detail_data' => $detail->getRawOriginal('dialplan_detail_data'),
                    'dialplan_detail_break' => $detail->getRawOriginal('dialplan_detail_break'),
                    'dialplan_detail_inline' => $detail->getRawOriginal('dialplan_detail_inline'),
                    'dialplan_detail_group' => (int) $detail->getRawOriginal('dialplan_detail_group'),
                    'dialplan_detail_order' => (int) $detail->getRawOriginal('dialplan_detail_order'),
                    'dialplan_detail_enabled' => $detail->getRawOriginal('dialplan_detail_enabled'),
                ])
                ->values()
                ->all(),
        ];
    }

    /**
     * v_dialplans has no editor_mode column, so the mode is read from the shape
     * of the stored plan: a plan with no line and some XML was written as raw
     * XML. Defaulting to builder instead would turn that XML into a plan rebuilt
     * from no line at all on the first PATCH.
     *
     * @param  Collection<int, DialplanDetails>  $details
     */
    private function storedEditorMode(Dialplans $dialplan, Collection $details): string
    {
        return $details->isEmpty() && filled($dialplan->dialplan_xml) ? 'xml' : 'builder';
    }

    /**
     * The stored lines, in the order the engine reads them: group first, then
     * order inside the group. The relation itself carries no ordering.
     *
     * @return Collection<int, DialplanDetails>
     */
    private function storedDetails(Dialplans $dialplan): Collection
    {
        return $dialplan->dialplan_details()
            ->orderBy('dialplan_detail_group')
            ->orderBy('dialplan_detail_order')
            ->get();
    }

    /**
     * DialplanService::save() fills insert_user / update_user from the session,
     * which a Bearer call does not have. The author is written here instead, and
     * only when the token really carries one.
     */
    private function stampAuthor(Dialplans $dialplan, Request $request, string $column): void
    {
        $userUuid = (string) ($request->user()?->user_uuid ?? '');

        if ($userUuid === '') {
            return;
        }

        $dialplan->forceFill([$column => $userUuid])->save();
    }

    /**
     * Asks the engine to re-read its XML and returns its raw answer.
     *
     * FreeswitchEslService never throws: its constructor swallows a failed
     * connection and executeCommand() returns null on any exception. Silence is
     * therefore turned into an explicit `-ERR`, which is what the callers test.
     */
    private function reloadXml(FreeswitchEslService $eslService): string
    {
        if (! $eslService->isConnected()) {
            return self::SWITCH_UNREACHABLE;
        }

        $response = $eslService->executeCommand(self::RELOAD_COMMAND);

        if ($response === null) {
            return self::SWITCH_UNREACHABLE;
        }

        // executeCommand() short-circuits '+OK …' and '-ERR …' as a string; a
        // structured answer would not concern reloadxml.
        $text = is_string($response) ? trim($response) : '';

        return $text !== '' ? $text : 'No response from FreeSWITCH.';
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
     * Same guards plus the plan itself, scoped to the domain of the route.
     * Both UUID formats are checked before any query, as DeviceController does.
     */
    private function findDialplan(Request $request, string $domain_uuid, string $dialplan_uuid): Dialplans
    {
        $this->guardRequest($request, $domain_uuid);

        if (! $this->isUuid($dialplan_uuid)) {
            throw new ApiException(400, 'invalid_request_error', 'Invalid dialplan UUID.', 'invalid_request', 'dialplan_uuid');
        }

        $this->requireDomain($domain_uuid);

        $dialplan = Dialplans::query()
            ->where('domain_uuid', $domain_uuid)
            ->where('dialplan_uuid', $dialplan_uuid)
            ->first();

        if (! $dialplan) {
            throw new ApiException(404, 'invalid_request_error', 'Dialplan not found.', 'resource_missing', 'dialplan_uuid');
        }

        return $dialplan;
    }

    /**
     * 401 and the domain UUID format — no query yet.
     */
    private function guardRequest(Request $request, string $domain_uuid): void
    {
        if (! $request->user()) {
            throw new ApiException(401, 'authentication_error', 'Unauthenticated.', 'unauthenticated');
        }

        if (! $this->isUuid($domain_uuid)) {
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

    private function isUuid(string $value): bool
    {
        return (bool) preg_match('/^[0-9a-fA-F-]{36}$/', $value);
    }
}
