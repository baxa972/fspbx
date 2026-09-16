<?php

namespace App\Http\Controllers\Api\V1;

use App\Data\Api\V1\AccessControlData;
use App\Data\Api\V1\AccessControlListResponseData;
use App\Exceptions\ApiException;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\UpdateAccessControlRequest;
use App\Models\AccessControl;
use App\Services\AccessControlService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

/**
 * Access control lists are GLOBAL to the instance: v_access_controls carries no
 * domain_uuid, so these routes live outside /domains/. A caller sees, and can
 * change, the lists of every tenant of the instance.
 *
 * Neither creating nor deleting a list is exposed here: the lists that matter
 * (`providers` and the per-gateway ones) are created and removed by the gateway
 * endpoints, which keep them in step with the gateways they protect.
 */
class AccessControlController extends Controller
{
    /**
     * List the access control lists of the instance
     *
     * Returns every list WITHOUT its nodes. Use
     * `GET /access-controls/{access_control_uuid}` to read them.
     *
     * This collection is not paginated: `has_more` is always false.
     *
     * @group Access Controls
     * @authenticated
     *
     * @response 200 scenario="Success" {
     *   "object": "list",
     *   "url": "/api/v1/access-controls",
     *   "has_more": false,
     *   "data": [
     *     {
     *       "access_control_uuid": "2b6a9f41-7c3d-4e58-9a10-3f5b8c7d6e21",
     *       "object": "access_control",
     *       "access_control_name": "providers",
     *       "access_control_default": "deny",
     *       "access_control_description": "Provider IP access control list."
     *     }
     *   ]
     * }
     * @response 401 scenario="Unauthenticated" {"error":{"type":"authentication_error","message":"Unauthenticated.","code":"unauthenticated"}}
     * @response 500 scenario="Internal server error" {"error":{"type":"api_error","message":"Internal server error.","code":"internal_error"}}
     */
    public function index(Request $request)
    {
        $this->requireUser($request);

        try {
            $lists = AccessControl::query()
                ->orderBy('access_control_name')
                ->get([
                    'access_control_uuid',
                    'access_control_name',
                    'access_control_default',
                    'access_control_description',
                ]);

            $payload = new AccessControlListResponseData(
                object: 'list',
                url: '/api/v1/access-controls',
                has_more: false,
                data: $lists->map(fn (AccessControl $list) => AccessControlData::summary($list))->all(),
            );

            return response()->json($payload->toArray(), 200);
        } catch (\Throwable $e) {
            logger('API AccessControl index error: ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine());
            throw new ApiException(500, 'api_error', 'Internal server error.', 'internal_error');
        }
    }

    /**
     * Retrieve an access control list and all of its nodes
     *
     * This is the read to perform before any change: a PATCH replaces the whole
     * set of nodes, so it has to start from the complete one.
     *
     * @group Access Controls
     * @authenticated
     *
     * @urlParam access_control_uuid string required The access control list UUID. Example: 2b6a9f41-7c3d-4e58-9a10-3f5b8c7d6e21
     *
     * @response 400 scenario="Invalid UUID" {"error":{"type":"invalid_request_error","message":"Invalid access control UUID.","code":"invalid_request","param":"access_control_uuid"}}
     * @response 404 scenario="Not found" {"error":{"type":"invalid_request_error","message":"Access control list not found.","code":"resource_missing","param":"access_control_uuid"}}
     */
    public function show(Request $request, string $access_control_uuid)
    {
        $accessControl = $this->findAccessControl($request, $access_control_uuid);

        return response()->json(AccessControlData::fromModel($accessControl)->toArray(), 200);
    }

    /**
     * Update an access control list — the nodes are REPLACED IN FULL
     *
     * `nodes` carries the complete and final set of nodes: the service deletes
     * every existing node of the list, then re-inserts exactly the ones received.
     * Any node left out is DELETED — including another tenant's, since the lists
     * are global. `[]` empties the list; omitting the key keeps the stored nodes,
     * which this controller resends unchanged.
     *
     * `access_control_name`, `access_control_default` and
     * `access_control_description` are rewritten on every call, so the fields
     * absent from the body are filled with the values the list already holds.
     *
     * A node whose CIDR the service cannot normalize would be dropped without a
     * word, so UpdateAccessControlRequest refuses it beforehand — along with
     * 0.0.0.0/0, the private and reserved ranges, and any prefix wider than /24
     * on a list that denies by default.
     *
     * Once written, the acl.conf cache is cleared and `reloadacl` is issued
     * OUTSIDE the transaction; its raw answer is returned in `switch_response`.
     * A `switch_response` starting with `-ERR` means the database is up to date
     * but the engine still applies the previous list — the write itself succeeded,
     * hence the 200. Use `POST /access-controls/reload` to retry the reload and
     * get a 422 if it still fails.
     *
     * @group Access Controls
     * @authenticated
     *
     * @urlParam access_control_uuid string required The access control list UUID. Example: 2b6a9f41-7c3d-4e58-9a10-3f5b8c7d6e21
     *
     * @response 400 scenario="Refused CIDR" {"error":{"type":"invalid_request_error","message":"This range overlaps the private or reserved block 10.0.0.0/8, which must not appear in an access control list.","code":"invalid_parameter","param":"nodes.0.node_cidr"}}
     */
    public function update(
        UpdateAccessControlRequest $request,
        string $access_control_uuid,
        AccessControlService $service
    ) {
        $accessControl = $this->findAccessControl($request, $access_control_uuid);

        $validated = $request->validated();

        // saveAccessControl() rewrites the three attributes from what it receives
        // and hands `$validated['nodes'] ?? []` to replaceNodes(): a payload that
        // does not mention the nodes would empty the list. Everything absent is
        // therefore rebuilt from the stored list, read BEFORE the replacement.
        $payload = [
            'access_control_name' => $validated['access_control_name'] ?? $accessControl->access_control_name,
            'access_control_default' => $validated['access_control_default'] ?? $accessControl->access_control_default,
            'access_control_description' => array_key_exists('access_control_description', $validated)
                ? $validated['access_control_description']
                : $accessControl->access_control_description,
            'nodes' => array_key_exists('nodes', $validated)
                ? $validated['nodes']
                : $this->currentNodes($accessControl),
        ];

        try {
            // saveAccessControl() also calls mirrorManagedGatewayList(), which reads
            // $accessControl->nodes as a PROPERTY to find out which gateway the list
            // belongs to. The eager load of findAccessControl() is load-bearing here:
            // the gateway is read from the nodes as they stood BEFORE the replacement,
            // so the mirror kept in the global `providers` list is rebuilt from the new
            // CIDRs even when the caller drops the "Managed gateway:<uuid>" descriptions.
            // Letting the relation reload after the replacement, as the SPA controller
            // does, would leave the removed IPs mirrored in `providers`.
            DB::transaction(function () use ($service, $accessControl, $payload) {
                $service->saveAccessControl($accessControl, $payload);
            });

            // Outside the transaction: FreeSWITCH side effects.
            $switchResponse = $service->sync();

            $accessControl->load('nodes');

            return response()->json(
                AccessControlData::fromModel($accessControl, $switchResponse)->toArray(),
                200
            );
        } catch (\Throwable $e) {
            logger('API AccessControl update error: ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine());
            throw new ApiException(500, 'api_error', 'Internal server error.', 'internal_error');
        }
    }

    /**
     * Reload the access control lists in FreeSWITCH
     *
     * Clears the `acl.conf` configuration cache then issues `reloadacl` on the
     * event socket. Nothing is written to the database.
     *
     * An engine answer containing `-ERR` — an unreachable event socket included —
     * answers 422: a reload that did not happen is never reported as a success,
     * which is what would let one believe an allow-list is in force while iptables
     * still blocks the provider.
     *
     * @group Access Controls
     * @authenticated
     *
     * @response 200 scenario="Reloaded" {"object":"access_control_reload","switch_response":"+OK"}
     * @response 422 scenario="Switch error" {"error":{"type":"invalid_request_error","message":"-ERR Could not connect to FreeSWITCH event socket.","code":"switch_error"}}
     */
    public function reload(Request $request, AccessControlService $service)
    {
        $this->requireUser($request);

        $switchResponse = $service->sync() ?: 'No response from FreeSWITCH.';

        if (str_contains($switchResponse, '-ERR')) {
            throw new ApiException(422, 'invalid_request_error', $switchResponse, 'switch_error');
        }

        return response()->json([
            'object' => 'access_control_reload',
            'switch_response' => $switchResponse,
        ], 200);
    }

    /**
     * 401, then the UUID format — before any query, as DeviceController does —
     * then the list itself. The permission is already enforced by the
     * `user.authorize` middleware.
     */
    private function findAccessControl(Request $request, string $access_control_uuid): AccessControl
    {
        $this->requireUser($request);

        if (! preg_match('/^[0-9a-fA-F-]{36}$/', $access_control_uuid)) {
            throw new ApiException(400, 'invalid_request_error', 'Invalid access control UUID.', 'invalid_request', 'access_control_uuid');
        }

        // 'nodes' is eager loaded on purpose: update() needs the stored nodes before
        // they are replaced, and the service reads the same relation (see update()).
        $accessControl = AccessControl::query()
            ->with('nodes')
            ->where('access_control_uuid', $access_control_uuid)
            ->first();

        if (! $accessControl) {
            throw new ApiException(404, 'invalid_request_error', 'Access control list not found.', 'resource_missing', 'access_control_uuid');
        }

        return $accessControl;
    }

    private function requireUser(Request $request): void
    {
        if (! $request->user()) {
            throw new ApiException(401, 'authentication_error', 'Unauthenticated.', 'unauthenticated');
        }
    }

    /**
     * The stored nodes, in the shape AccessControlService::replaceNodes() expects,
     * so that a PATCH which does not mention them puts back exactly what was there.
     *
     * @return array<int, array{node_type: string|null, node_cidr: string|null, node_description: string|null}>
     */
    private function currentNodes(AccessControl $accessControl): array
    {
        return $accessControl->nodes
            ->map(fn ($node) => [
                'node_type' => $node->node_type,
                'node_cidr' => $node->node_cidr,
                'node_description' => $node->node_description,
            ])
            ->values()
            ->all();
    }
}
