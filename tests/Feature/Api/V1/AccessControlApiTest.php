<?php

namespace Tests\Feature\Api\V1;

use App\Data\Api\V1\AccessControlData;
use App\Models\AccessControl;
use App\Models\AccessControlNode;
use App\Models\User;
use App\Services\AccessControlService;
use App\Services\Auth\PermissionService;
use Illuminate\Support\Facades\Route;
use Laravel\Sanctum\Sanctum;
use Mockery;
use Tests\TestCase;

/**
 * Coverage for the Api\V1\AccessControlController endpoints (NOV-1008).
 *
 * WHAT ACTUALLY RUNS HERE, and why the rest does not:
 *
 * This repository ships no test database. `phpunit.xml` leaves DB_CONNECTION
 * commented out, the 90 migrations target the FusionPBX PostgreSQL schema, there
 * is no AccessControl factory and the only other Api/V1 tests skip their
 * DB-backed cases for the same reason.
 *
 * So this file splits in two:
 *
 *  - Tests that prove something WITHOUT a database, and really run:
 *      * the four routes are mounted with their permission middleware;
 *      * 401 without a token, 403 without the permission, 400 on a malformed UUID;
 *      * a refused CIDR really answers 400 through the whole HTTP stack — the
 *        FormRequest runs before the controller touches the database;
 *      * the reload endpoint, with AccessControlService mocked: `-ERR` answers
 *        422, never a silent success;
 *      * the serialization: what a list exposes, and nothing else.
 *
 *  - Tests that need the schema (a PATCH really replacing the nodes, the listing).
 *    They are written in full and call markTestSkipped() with an explicit reason.
 *    They are NOT proof of anything until they run where the database exists.
 *
 * The CIDR rules themselves are covered one family at a time in
 * tests/Unit/Api/V1/UpdateAccessControlRequestTest.php.
 */
class AccessControlApiTest extends TestCase
{
    private const ACL_UUID = '2b6a9f41-7c3d-4e58-9a10-3f5b8c7d6e21';
    private const DOMAIN_UUID = '4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b';

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    // -----------------------------------------------------------------------
    // Routing — guards the "route declared but never mounted" defect
    // -----------------------------------------------------------------------

    /**
     * @dataProvider accessControlRoutes
     */
    public function test_route_is_mounted_with_its_permission_middleware(
        string $method,
        string $uri,
        string $action,
        string $permission
    ): void {
        $route = collect(Route::getRoutes()->getRoutes())
            ->first(fn ($route) => $route->uri() === $uri && in_array($method, $route->methods(), true));

        $this->assertNotNull($route, "Route {$method} {$uri} is not registered.");
        $this->assertSame('App\Http\Controllers\Api\V1\AccessControlController@' . $action, $route->getActionName());

        $middleware = $route->gatherMiddleware();
        $this->assertContains('auth:sanctum', $middleware);
        $this->assertContains('api.token.auth', $middleware);
        $this->assertContains('throttle:api', $middleware);
        $this->assertContains('user.authorize:' . $permission, $middleware);
    }

    public static function accessControlRoutes(): array
    {
        return [
            'list' => ['GET', 'api/v1/access-controls', 'index', 'access_control_view'],
            'read' => ['GET', 'api/v1/access-controls/{access_control_uuid}', 'show', 'access_control_view'],
            'update' => ['PATCH', 'api/v1/access-controls/{access_control_uuid}', 'update', 'access_control_edit'],
            'reload' => ['POST', 'api/v1/access-controls/reload', 'reload', 'access_control_view'],
        ];
    }

    /**
     * The lists are global to the instance: routing them under /domains/ would
     * suggest a tenant isolation that the table cannot provide.
     */
    public function test_the_routes_are_outside_the_domain_scope(): void
    {
        foreach (self::accessControlRoutes() as [$method, $uri, , ]) {
            $this->assertStringStartsWith('api/v1/access-controls', $uri);
            $this->assertStringNotContainsString('{domain_uuid}', $uri);
        }
    }

    /**
     * /access-controls/reload must win over /access-controls/{uuid}; it is a
     * different verb today, so this pins the declaration order that keeps it true.
     */
    public function test_the_reload_route_is_declared_before_the_uuid_route(): void
    {
        $uris = collect(Route::getRoutes()->getRoutes())
            ->map(fn ($route) => $route->uri())
            ->values()
            ->all();

        $this->assertLessThan(
            array_search('api/v1/access-controls/{access_control_uuid}', $uris, true),
            array_search('api/v1/access-controls/reload', $uris, true)
        );
    }

    // -----------------------------------------------------------------------
    // Authentication and authorization — no database needed
    // -----------------------------------------------------------------------

    public function test_unauthenticated_returns_401(): void
    {
        $this->getJson('/api/v1/access-controls')
            ->assertStatus(401)
            ->assertJsonPath('error.type', 'authentication_error')
            ->assertJsonPath('error.code', 'unauthenticated');
    }

    public function test_reload_is_unauthenticated_without_a_token(): void
    {
        $this->postJson('/api/v1/access-controls/reload')
            ->assertStatus(401)
            ->assertJsonPath('error.code', 'unauthenticated');
    }

    public function test_bearer_without_the_view_permission_is_forbidden(): void
    {
        $this->actingAsApiUser(hasPermission: false);

        $this->getJson('/api/v1/access-controls')
            ->assertStatus(403)
            ->assertJsonPath('error.code', 'forbidden_permission')
            ->assertJsonPath('error.permission', 'access_control_view');
    }

    public function test_bearer_without_the_edit_permission_cannot_patch(): void
    {
        $this->actingAsApiUser(hasPermission: false);

        $this->patchJson($this->itemEndpoint(), ['nodes' => []])
            ->assertStatus(403)
            ->assertJsonPath('error.code', 'forbidden_permission')
            ->assertJsonPath('error.permission', 'access_control_edit');
    }

    public function test_malformed_access_control_uuid_returns_400(): void
    {
        $this->actingAsApiUser();

        $this->getJson($this->itemEndpoint('not-a-uuid'))
            ->assertStatus(400)
            ->assertJsonPath('error.code', 'invalid_request')
            ->assertJsonPath('error.param', 'access_control_uuid');
    }

    public function test_malformed_access_control_uuid_returns_400_on_patch_too(): void
    {
        $this->actingAsApiUser();

        // Empty body: validation passes, so what answers is the UUID guard,
        // which runs before any query.
        $this->patchJson($this->itemEndpoint('not-a-uuid'), [])
            ->assertStatus(400)
            ->assertJsonPath('error.code', 'invalid_request')
            ->assertJsonPath('error.param', 'access_control_uuid');
    }

    // -----------------------------------------------------------------------
    // The CIDR guard end to end — validation runs before any query
    // -----------------------------------------------------------------------

    /**
     * @dataProvider refusedCidrs
     */
    public function test_a_refused_cidr_answers_400_through_the_http_stack(string $cidr): void
    {
        $this->actingAsApiUser();

        $this->patchJson($this->itemEndpoint(), [
            'access_control_default' => 'deny',
            'nodes' => [['node_type' => 'allow', 'node_cidr' => $cidr]],
        ])
            ->assertStatus(400)
            ->assertJsonPath('error.type', 'invalid_request_error')
            ->assertJsonPath('error.code', 'invalid_parameter')
            ->assertJsonPath('error.param', 'nodes.0.node_cidr');
    }

    public static function refusedCidrs(): array
    {
        return [
            'private 10/8' => ['10.0.0.0/8'],
            'private 172.16/12' => ['172.16.0.0/12'],
            'private 192.168/16' => ['192.168.0.0/16'],
            'loopback 127/8' => ['127.0.0.0/8'],
            'carrier grade nat 100.64/10' => ['100.64.0.0/10'],
            'the whole internet' => ['0.0.0.0/0'],
            'wider than /24 on a deny list' => ['198.51.100.0/23'],
            'not an address' => ['pas-une-ip'],
        ];
    }

    // -----------------------------------------------------------------------
    // Reload — an engine error is never a silent success
    // -----------------------------------------------------------------------

    public function test_reload_returns_the_engine_answer(): void
    {
        $this->actingAsApiUser();
        $this->mockAccessControlService('+OK');

        $this->postJson('/api/v1/access-controls/reload')
            ->assertStatus(200)
            ->assertJsonPath('object', 'access_control_reload')
            ->assertJsonPath('switch_response', '+OK');
    }

    public function test_reload_answers_422_when_the_event_socket_is_down(): void
    {
        $this->actingAsApiUser();
        $this->mockAccessControlService('-ERR Could not connect to FreeSWITCH event socket.');

        $this->postJson('/api/v1/access-controls/reload')
            ->assertStatus(422)
            ->assertJsonPath('error.code', 'switch_error')
            ->assertJsonPath('error.message', '-ERR Could not connect to FreeSWITCH event socket.');
    }

    /**
     * The engine can answer several lines, the error not being the first one:
     * a reload that failed halfway is still a failure.
     */
    public function test_reload_answers_422_when_the_error_is_not_the_first_line(): void
    {
        $this->actingAsApiUser();
        $this->mockAccessControlService("+OK\n-ERR acl.conf reload failed");

        $this->postJson('/api/v1/access-controls/reload')
            ->assertStatus(422)
            ->assertJsonPath('error.code', 'switch_error');
    }

    public function test_reload_reports_an_empty_engine_answer_instead_of_an_empty_string(): void
    {
        $this->actingAsApiUser();
        $this->mockAccessControlService(null);

        $this->postJson('/api/v1/access-controls/reload')
            ->assertStatus(200)
            ->assertJsonPath('switch_response', 'No response from FreeSWITCH.');
    }

    // -----------------------------------------------------------------------
    // Serialization — what a list exposes, and nothing else
    // -----------------------------------------------------------------------

    public function test_the_api_representation_exposes_exactly_the_documented_fields(): void
    {
        $payload = AccessControlData::fromModel($this->accessControlWithNodes())->toArray();

        $this->assertEqualsCanonicalizing([
            'access_control_uuid', 'object', 'access_control_name',
            'access_control_default', 'access_control_description',
            'nodes', 'switch_response',
        ], array_keys($payload));

        $this->assertSame('access_control', $payload['object']);
        $this->assertSame('providers', $payload['access_control_name']);
        $this->assertSame('deny', $payload['access_control_default']);
        $this->assertNull($payload['switch_response']);
    }

    public function test_a_node_exposes_exactly_the_three_documented_fields(): void
    {
        $payload = AccessControlData::fromModel($this->accessControlWithNodes())->toArray();

        $this->assertCount(2, $payload['nodes']);
        $this->assertEqualsCanonicalizing(
            ['node_type', 'node_cidr', 'node_description'],
            array_keys($payload['nodes'][0])
        );

        // The FusionPBX bookkeeping columns stay inside the database.
        $serialized = json_encode($payload);
        $this->assertStringNotContainsString('insert_user', $serialized);
        $this->assertStringNotContainsString('access_control_node_uuid', $serialized);

        $this->assertSame('allow', $payload['nodes'][0]['node_type']);
        $this->assertSame('192.0.2.10/32', $payload['nodes'][0]['node_cidr']);
        $this->assertSame('Carrier SBC 1', $payload['nodes'][0]['node_description']);
        $this->assertNull($payload['nodes'][1]['node_description']);
    }

    /**
     * A list entry omits the `nodes` key rather than claiming the list is empty.
     */
    public function test_a_list_entry_carries_no_nodes_key(): void
    {
        $payload = AccessControlData::summary($this->accessControlWithNodes())->toArray();

        $this->assertArrayNotHasKey('nodes', $payload);
        $this->assertArrayNotHasKey('switch_response', $payload);
        $this->assertSame('providers', $payload['access_control_name']);
    }

    public function test_the_switch_answer_is_carried_by_the_patch_response(): void
    {
        $payload = AccessControlData::fromModel($this->accessControlWithNodes(), '+OK')->toArray();

        $this->assertSame('+OK', $payload['switch_response']);
    }

    /**
     * @dataProvider defaultPolicies
     */
    public function test_the_default_policy_enumeration_is_closed(mixed $stored, string $expected): void
    {
        $this->assertSame($expected, AccessControlData::normalizeDefault($stored));
    }

    public static function defaultPolicies(): array
    {
        return [
            'deny' => ['deny', 'deny'],
            'allow' => ['allow', 'allow'],
            'padded' => [" ALLOW\n", 'allow'],
            'empty column' => ['', 'deny'],
            'null column' => [null, 'deny'],
            // Anything unreadable is reported as deny, never as allow.
            'unknown value' => ['maybe', 'deny'],
            'unexpected type' => [['allow'], 'deny'],
        ];
    }

    /**
     * A node type FusionPBX may hold outside the enum is reported the way the
     * service would store it back, so that a GET then PATCH round trip is stable.
     */
    public function test_an_unreadable_node_type_is_reported_as_the_service_would_store_it(): void
    {
        $accessControl = new AccessControl();
        $accessControl->forceFill([
            'access_control_uuid' => self::ACL_UUID,
            'access_control_name' => 'legacy',
            'access_control_default' => 'deny',
        ]);
        $accessControl->setRelation('nodes', collect([
            $this->node('192.0.2.10/32', 'sometimes', null),
        ]));

        $payload = AccessControlData::fromModel($accessControl)->toArray();

        $this->assertSame('allow', $payload['nodes'][0]['node_type']);
    }

    // -----------------------------------------------------------------------
    // Cases that need the FusionPBX schema — written, not proven
    // -----------------------------------------------------------------------

    public function test_the_listing_returns_the_v1_envelope_without_the_nodes(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $response = $this->getJson('/api/v1/access-controls')
            ->assertStatus(200)
            ->assertJsonPath('object', 'list')
            ->assertJsonPath('url', '/api/v1/access-controls')
            ->assertJsonPath('has_more', false);

        $this->assertArrayNotHasKey('nodes', $response->json('data.0'));
    }

    public function test_reading_a_list_returns_all_of_its_nodes(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $expected = AccessControl::query()->findOrFail(self::ACL_UUID)->nodes()->count();

        $this->getJson($this->itemEndpoint())
            ->assertStatus(200)
            ->assertJsonPath('object', 'access_control')
            ->assertJsonCount($expected, 'nodes');
    }

    public function test_an_unknown_list_returns_404(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $this->getJson($this->itemEndpoint('11111111-2222-3333-4444-555555555555'))
            ->assertStatus(404)
            ->assertJsonPath('error.code', 'resource_missing')
            ->assertJsonPath('error.param', 'access_control_uuid');
    }

    /**
     * The whole point of the endpoint: what is sent IS the list. A node that was
     * there and is not in the payload is gone.
     */
    public function test_patch_replaces_the_whole_set_of_nodes(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $accessControl = AccessControl::query()->findOrFail(self::ACL_UUID);
        $this->assertGreaterThan(1, $accessControl->nodes()->count());

        $response = $this->patchJson($this->itemEndpoint(), [
            'nodes' => [
                ['node_type' => 'allow', 'node_cidr' => '192.0.2.10/32', 'node_description' => 'Carrier SBC 1'],
            ],
        ])->assertStatus(200);

        $this->assertCount(1, $response->json('nodes'));
        $this->assertSame(1, $accessControl->fresh()->nodes()->count());
        $this->assertSame('192.0.2.10/32', $accessControl->fresh()->nodes()->first()->node_cidr);
    }

    public function test_patch_with_an_empty_array_empties_the_list(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $this->patchJson($this->itemEndpoint(), ['nodes' => []])
            ->assertStatus(200)
            ->assertJsonCount(0, 'nodes');

        $this->assertSame(0, AccessControl::query()->findOrFail(self::ACL_UUID)->nodes()->count());
    }

    /**
     * A PATCH that does not mention the nodes must not delete them:
     * AccessControlService::saveAccessControl() hands `$validated['nodes'] ?? []`
     * to replaceNodes(), so the controller resends the stored ones.
     */
    public function test_patch_without_nodes_keeps_the_stored_ones(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $before = AccessControl::query()->findOrFail(self::ACL_UUID)->nodes()->pluck('node_cidr')->sort()->values();
        $this->assertGreaterThan(0, $before->count());

        $this->patchJson($this->itemEndpoint(), ['access_control_description' => 'Renamed by the API'])
            ->assertStatus(200)
            ->assertJsonPath('access_control_description', 'Renamed by the API');

        $after = AccessControl::query()->findOrFail(self::ACL_UUID)->nodes()->pluck('node_cidr')->sort()->values();

        $this->assertSame($before->all(), $after->all());
    }

    /**
     * Same trap on the attributes: the service rewrites all three on every call.
     */
    public function test_patch_keeps_the_attributes_absent_from_the_body(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $before = AccessControl::query()->findOrFail(self::ACL_UUID);

        $this->patchJson($this->itemEndpoint(), ['nodes' => []])
            ->assertStatus(200)
            ->assertJsonPath('access_control_name', $before->access_control_name)
            ->assertJsonPath('access_control_default', $before->access_control_default);

        $after = AccessControl::query()->findOrFail(self::ACL_UUID);

        $this->assertSame($before->access_control_name, $after->access_control_name);
        $this->assertSame($before->access_control_default, $after->access_control_default);
        $this->assertSame($before->access_control_description, $after->access_control_description);
    }

    /**
     * The write is committed and only then reloaded: an engine that refuses the
     * reload does not roll back the list, it is reported in switch_response.
     */
    public function test_patch_stays_200_and_reports_an_engine_error_in_switch_response(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();
        $this->mockAccessControlService('-ERR Could not connect to FreeSWITCH event socket.');

        $this->patchJson($this->itemEndpoint(), ['nodes' => []])
            ->assertStatus(200)
            ->assertJsonPath('switch_response', '-ERR Could not connect to FreeSWITCH event socket.');
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private function skipWithoutDatabase(): void
    {
        $this->markTestSkipped(
            'Requires the FusionPBX schema and an AccessControl factory, which this '
            . 'repository does not ship: phpunit.xml leaves DB_CONNECTION commented out, '
            . 'the 90 migrations target PostgreSQL/FusionPBX and database/factories/ only '
            . 'holds UserFactory. To be run on an environment that has the database.'
        );
    }

    private function itemEndpoint(string $uuid = self::ACL_UUID): string
    {
        return "/api/v1/access-controls/{$uuid}";
    }

    /**
     * Sanctum-authenticated caller with PermissionService stubbed out: the
     * permission tables live in the FusionPBX schema, which the test environment
     * does not have. What is exercised here is the middleware wiring of the
     * routes, not PermissionService itself.
     */
    private function actingAsApiUser(bool $hasPermission = true): User
    {
        $permissions = Mockery::mock(PermissionService::class);
        $permissions->shouldReceive('userCanAccessDomain')->andReturn(true);
        $permissions->shouldReceive('userHasPermission')->andReturn($hasPermission);
        $this->app->instance(PermissionService::class, $permissions);

        $user = new User();
        $user->user_uuid = 'b2c5a9de-0f47-4a1e-9b64-1f5a9f0c7a11';
        $user->domain_uuid = self::DOMAIN_UUID;

        Sanctum::actingAs($user);

        $this->withHeader('Authorization', 'Bearer test-token');

        return $user;
    }

    private function mockAccessControlService(?string $switchResponse): void
    {
        $service = Mockery::mock(AccessControlService::class);
        $service->shouldReceive('sync')->andReturn($switchResponse);
        $service->shouldReceive('saveAccessControl')->andReturnUsing(fn ($accessControl) => $accessControl);
        $this->app->instance(AccessControlService::class, $service);
    }

    private function accessControlWithNodes(): AccessControl
    {
        $accessControl = new AccessControl();
        $accessControl->forceFill([
            'access_control_uuid' => self::ACL_UUID,
            'access_control_name' => 'providers',
            'access_control_default' => 'deny',
            'access_control_description' => 'Provider IP access control list.',
            'insert_user' => 'b2c5a9de-0f47-4a1e-9b64-1f5a9f0c7a11',
        ]);

        $accessControl->setRelation('nodes', collect([
            $this->node('192.0.2.10/32', 'allow', 'Carrier SBC 1'),
            $this->node('198.51.100.0/24', 'allow', null),
        ]));

        return $accessControl;
    }

    private function node(string $cidr, string $type, ?string $description): AccessControlNode
    {
        $node = new AccessControlNode();
        $node->forceFill([
            'access_control_node_uuid' => 'd9d1a6f0-6b2f-4f3a-8f1a-0b7c2d3e4f50',
            'access_control_uuid' => self::ACL_UUID,
            'node_type' => $type,
            'node_cidr' => $cidr,
            'node_description' => $description,
            'insert_user' => 'b2c5a9de-0f47-4a1e-9b64-1f5a9f0c7a11',
        ]);

        return $node;
    }
}
