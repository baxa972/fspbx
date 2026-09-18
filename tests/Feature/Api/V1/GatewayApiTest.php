<?php

namespace Tests\Feature\Api\V1;

use App\Data\Api\V1\GatewayData;
use App\Http\Requests\Api\V1\StoreGatewayRequest;
use App\Http\Requests\Api\V1\UpdateGatewayRequest;
use App\Models\Gateways;
use App\Models\User;
use App\Services\Auth\PermissionService;
use App\Services\AccessControlService;
use App\Services\FreeswitchEslService;
use App\Services\GatewayService;
use Illuminate\Contracts\Validation\Validator as ValidatorContract;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use Laravel\Sanctum\Sanctum;
use Mockery;
use Tests\TestCase;

/**
 * Coverage for the Api\V1\GatewayController endpoints (NOV-1007).
 *
 * WHAT ACTUALLY RUNS HERE, and why the rest does not:
 *
 * This repository ships no test database. `phpunit.xml` leaves DB_CONNECTION
 * commented out, the 90 migrations target the FusionPBX PostgreSQL schema, there
 * is no `Domain` / `Gateways` factory and the only other Api/V1 test
 * (CdrRecordingUrlTest) skips its own DB-backed cases for the same reason.
 *
 * So this file splits in two:
 *
 *  - Tests that prove something WITHOUT a database, and really run:
 *      * the five routes are mounted with their permission middleware;
 *      * 401 without a token, 403 without the permission, 403 outside the
 *        domain scope, 400 on a malformed UUID;
 *      * the FormRequest rules, exercised through Laravel's validator;
 *      * the serialization: the SIP password never leaves the API;
 *      * the engine state falls back to UNKNOWN instead of leaking a raw value.
 *
 *  - Tests that need the schema. They are written in full and call
 *    markTestSkipped() with an explicit reason. They are NOT proof of anything
 *    until they are run on an environment that has the database.
 */
class GatewayApiTest extends TestCase
{
    private const DOMAIN_UUID = '4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b';
    private const GATEWAY_UUID = '47aa96db-3f70-46ce-bb9a-79ccef396f2b';

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    // -----------------------------------------------------------------------
    // Routing — guards the "route declared but never mounted" defect
    // -----------------------------------------------------------------------

    /**
     * @dataProvider gatewayRoutes
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
        $this->assertSame('App\Http\Controllers\Api\V1\GatewayController@' . $action, $route->getActionName());

        $middleware = $route->gatherMiddleware();
        $this->assertContains('auth:sanctum', $middleware);
        $this->assertContains('api.token.auth', $middleware);
        $this->assertContains('throttle:api', $middleware);
        $this->assertContains('user.authorize:' . $permission, $middleware);
    }

    public static function gatewayRoutes(): array
    {
        return [
            'create' => ['POST', 'api/v1/domains/{domain_uuid}/gateways', 'store', 'gateway_add'],
            'read' => ['GET', 'api/v1/domains/{domain_uuid}/gateways/{gateway_uuid}', 'show', 'gateway_view'],
            'update' => ['PATCH', 'api/v1/domains/{domain_uuid}/gateways/{gateway_uuid}', 'update', 'gateway_edit'],
            'delete' => ['DELETE', 'api/v1/domains/{domain_uuid}/gateways/{gateway_uuid}', 'destroy', 'gateway_delete'],
            'restart' => ['POST', 'api/v1/domains/{domain_uuid}/gateways/{gateway_uuid}/restart', 'restart', 'gateway_edit'],
        ];
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
            ->assertJsonPath('error.permission', 'gateway_add');
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

        $this->getJson("/api/v1/domains/not-a-uuid/gateways/" . self::GATEWAY_UUID)
            ->assertStatus(400)
            ->assertJsonPath('error.code', 'invalid_request')
            ->assertJsonPath('error.param', 'domain_uuid');
    }

    public function test_malformed_gateway_uuid_returns_400(): void
    {
        $this->actingAsApiUser();

        $this->getJson($this->itemEndpoint(self::DOMAIN_UUID, 'not-a-uuid'))
            ->assertStatus(400)
            ->assertJsonPath('error.code', 'invalid_request')
            ->assertJsonPath('error.param', 'gateway_uuid');
    }

    // -----------------------------------------------------------------------
    // Validation rules — the security logic of this batch, no database needed
    // -----------------------------------------------------------------------

    public function test_create_requires_the_documented_fields(): void
    {
        $validator = $this->validateStore([]);

        $this->assertTrue($validator->fails());
        $this->assertEqualsCanonicalizing(
            ['gateway', 'proxy', 'register', 'profile', 'enabled'],
            array_keys($validator->errors()->toArray())
        );
    }

    public function test_create_requires_credentials_when_the_gateway_registers(): void
    {
        $payload = $this->validCreatePayload();
        unset($payload['username'], $payload['password']);

        $validator = $this->validateStore($payload);

        $this->assertTrue($validator->fails());
        $this->assertArrayHasKey('username', $validator->errors()->toArray());
        $this->assertArrayHasKey('password', $validator->errors()->toArray());
    }

    public function test_create_does_not_require_credentials_without_registration(): void
    {
        $payload = $this->validCreatePayload();
        $payload['register'] = false;
        unset($payload['username'], $payload['password']);

        $this->assertFalse($this->validateStore($payload)->fails());
    }

    public function test_create_accepts_a_valid_payload(): void
    {
        $validator = $this->validateStore($this->validCreatePayload());

        $this->assertFalse($validator->fails(), json_encode($validator->errors()->toArray()));
    }

    public function test_create_ignores_a_domain_uuid_sent_in_the_body(): void
    {
        $payload = $this->validCreatePayload();
        $payload['domain_uuid'] = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

        $validated = $this->validateStore($payload)->validated();

        $this->assertArrayNotHasKey(
            'domain_uuid',
            $validated,
            'The route domain_uuid is the only source of truth; a body one must never reach the service.'
        );
    }

    public function test_create_rejects_an_unknown_transport(): void
    {
        $payload = $this->validCreatePayload();
        $payload['register_transport'] = 'sctp';

        $this->assertArrayHasKey('register_transport', $this->validateStore($payload)->errors()->toArray());
    }

    public function test_create_rejects_a_non_boolean_enabled(): void
    {
        $payload = $this->validCreatePayload();
        $payload['enabled'] = 'oui';

        $this->assertArrayHasKey('enabled', $this->validateStore($payload)->errors()->toArray());
    }

    /**
     * The profile name is interpolated into `sofia profile %s startgw / killgw
     * / rescan` on the event socket: a space, a newline or a shell metachar
     * would smuggle a second command. Letters, digits, _ and - only.
     *
     * @dataProvider unsafeProfileNames
     */
    public function test_create_rejects_an_unsafe_profile_name(string $profile): void
    {
        $payload = $this->validCreatePayload();
        $payload['profile'] = $profile;

        $this->assertArrayHasKey(
            'profile',
            $this->validateStore($payload)->errors()->toArray(),
            "Profile '{$profile}' should have been refused."
        );
    }

    public static function unsafeProfileNames(): array
    {
        return [
            'space' => ['ext ernal'],
            'newline' => ["external\nreloadxml"],
            'semicolon' => ['external;reloadxml'],
            'backtick' => ['external`id`'],
            'command substitution' => ['external$(id)'],
            'quote' => ["external'"],
            'empty' => [''],
        ];
    }

    /**
     * @dataProvider safeProfileNames
     */
    public function test_create_accepts_a_safe_profile_name(string $profile): void
    {
        $payload = $this->validCreatePayload();
        $payload['profile'] = $profile;

        $this->assertArrayNotHasKey('profile', $this->validateStore($payload)->errors()->toArray());
    }

    public static function safeProfileNames(): array
    {
        return [
            'external' => ['external'],
            'internal' => ['internal'],
            'ipv6 variant' => ['internal-ipv6'],
            'underscore variant' => ['external_ipv6'],
        ];
    }

    public function test_update_rejects_an_unsafe_profile_name(): void
    {
        $this->assertArrayHasKey(
            'profile',
            $this->validateUpdate(['profile' => "external\nreloadxml"])->errors()->toArray()
        );
    }

    /**
     * Defense in depth below the validation: even a profile name already in
     * the database never reaches the event socket if it does not fit the
     * alphabet — the command is refused before any connection attempt.
     */
    public function test_an_unsafe_stored_profile_never_reaches_the_event_socket(): void
    {
        $gateway = new Gateways();
        $gateway->forceFill([
            'gateway_uuid' => self::GATEWAY_UUID,
            'profile' => "external\nreloadxml",
            'enabled' => 'true',
        ]);

        $answer = app(GatewayService::class)->executeGatewayCommand('start', $gateway);

        $this->assertSame('-ERR Refused: unsafe Sofia profile name.', $answer);
    }

    /**
     * These CIDRs are written to the instance-wide `providers` ACL: the same rule
     * as the PATCH access-controls endpoint applies — IPv4 with an explicit
     * prefix, no private or reserved block, no /0, nothing wider than /24.
     *
     * @dataProvider unusableCidrs
     */
    public function test_create_rejects_an_unusable_acl_cidr(string $cidr): void
    {
        $payload = $this->validCreatePayload();
        $payload['gateway_acl_cidrs'] = [$cidr];

        $this->assertArrayHasKey(
            'gateway_acl_cidrs.0',
            $this->validateStore($payload)->errors()->toArray(),
            "CIDR '{$cidr}' should have been refused."
        );
    }

    public static function unusableCidrs(): array
    {
        return [
            'not an address' => ['pas-une-ip'],
            'ipv4 prefix out of range' => ['192.0.2.10/33'],
            'empty' => [''],
            'host name' => ['sip.example.com/32'],
            'negative prefix' => ['192.0.2.10/-1'],
            // The ACL guard, applied to what syncGatewayProviderIps() writes:
            'private 10/8' => ['10.0.0.0/8'],
            'private host inside 10/8' => ['10.1.2.3/32'],
            'private 172.16/12' => ['172.16.0.0/12'],
            'private 192.168/16' => ['192.168.0.0/16'],
            'loopback' => ['127.0.0.1/32'],
            'carrier grade nat' => ['100.64.0.0/10'],
            'the whole internet' => ['0.0.0.0/0'],
            'wider than /24' => ['192.0.2.0/23'],
            'ipv4 without prefix' => ['192.0.2.10'],
            'ipv6' => ['2001:db8::1/128'],
            'ipv6 whole internet' => ['::/0'],
            'numeric-looking float prefix' => ['192.0.2.1/24e0'],
        ];
    }

    /**
     * @dataProvider usableCidrs
     */
    public function test_create_accepts_a_usable_acl_cidr(string $cidr): void
    {
        $payload = $this->validCreatePayload();
        $payload['gateway_acl_cidrs'] = [$cidr];

        $this->assertArrayNotHasKey('gateway_acl_cidrs.0', $this->validateStore($payload)->errors()->toArray());
    }

    public static function usableCidrs(): array
    {
        return [
            'ipv4 host' => ['192.0.2.10/32'],
            'ipv4 range' => ['198.51.100.0/24'],
            'narrower than /24' => ['203.0.113.0/28'],
        ];
    }

    public function test_update_accepts_a_partial_payload(): void
    {
        $this->assertFalse($this->validateUpdate(['enabled' => false])->fails());
        $this->assertFalse($this->validateUpdate([])->fails());
    }

    /**
     * On a PATCH the stored credentials stay in place: turning registration back
     * on must not demand a password the caller already provided once.
     */
    public function test_update_does_not_demand_credentials_again_when_registration_is_turned_on(): void
    {
        $this->assertFalse($this->validateUpdate(['register' => true])->fails());
    }

    public function test_update_still_rejects_an_unknown_transport(): void
    {
        $this->assertArrayHasKey(
            'register_transport',
            $this->validateUpdate(['register_transport' => 'sctp'])->errors()->toArray()
        );
    }

    public function test_update_rejects_an_unusable_acl_cidr(): void
    {
        $this->assertArrayHasKey(
            'gateway_acl_cidrs.0',
            $this->validateUpdate(['gateway_acl_cidrs' => ['192.0.2.10/33']])->errors()->toArray()
        );
    }

    /**
     * A PATCH is a whole-list replacement too: a private block must be refused
     * here exactly as on creation.
     */
    public function test_update_rejects_a_private_acl_cidr(): void
    {
        $this->assertArrayHasKey(
            'gateway_acl_cidrs.0',
            $this->validateUpdate(['gateway_acl_cidrs' => ['10.0.0.0/8']])->errors()->toArray()
        );
    }

    // -----------------------------------------------------------------------
    // ACL list naming — unique per gateway, across tenants
    // -----------------------------------------------------------------------

    /**
     * access_control_name is not scoped by domain_uuid: two tenants calling
     * their trunk "ovh" must NOT share one list. The name is derived from the
     * immutable UUID, never from the display name.
     */
    public function test_the_acl_list_is_named_after_the_uuid_not_the_display_name(): void
    {
        $service = app(AccessControlService::class);

        $first = new Gateways();
        $first->forceFill(['gateway_uuid' => self::GATEWAY_UUID, 'gateway' => 'ovh']);

        $second = new Gateways();
        $second->forceFill(['gateway_uuid' => 'eeeeeeee-1111-2222-3333-444444444444', 'gateway' => 'ovh']);

        $this->assertSame('gateway_' . self::GATEWAY_UUID, $service->gatewayListName($first));
        $this->assertSame('gateway_eeeeeeee-1111-2222-3333-444444444444', $service->gatewayListName($second));
        $this->assertNotSame(
            $service->gatewayListName($first),
            $service->gatewayListName($second),
            'Two gateways with the same display name must not share an ACL list.'
        );
    }

    /**
     * mirrorManagedGatewayList() parses the UUID back out of the list name
     * (gatewayUuidFromListName): the format is part of the contract.
     */
    public function test_the_acl_list_name_keeps_the_parseable_format(): void
    {
        $service = app(AccessControlService::class);

        $gateway = new Gateways();
        // An upper-case UUID must normalize to the lower-case canonical form.
        $gateway->forceFill(['gateway_uuid' => strtoupper(self::GATEWAY_UUID), 'gateway' => 'ovh']);

        $this->assertMatchesRegularExpression(
            '/^gateway_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/',
            $service->gatewayListName($gateway)
        );
    }

    // -----------------------------------------------------------------------
    // Serialization — the SIP password never leaves the API
    // -----------------------------------------------------------------------

    public function test_the_sip_password_is_absent_from_the_api_representation(): void
    {
        $secret = 'mot-de-passe-sip-tres-secret';

        $gateway = new Gateways();
        $gateway->forceFill([
            'gateway_uuid' => self::GATEWAY_UUID,
            'domain_uuid' => self::DOMAIN_UUID,
            'gateway' => 'client_poste_250',
            'username' => '250',
            'password' => $secret,
            'proxy' => 'sip.example.com:5060',
            'register' => 'true',
            'enabled' => 'true',
            'profile' => 'external',
            'context' => 'public',
            'expire_seconds' => '800',
            'channels' => '0',
        ]);

        $payload = GatewayData::fromModel($gateway, ['state' => 'REGED'])->toArray();

        $this->assertArrayNotHasKey('password', $payload);
        $this->assertStringNotContainsString($secret, json_encode($payload));
        $this->assertSame('250', $payload['username']);
        $this->assertSame('REGED', $payload['state']);
        $this->assertTrue($payload['register']);
        $this->assertTrue($payload['enabled']);
        $this->assertSame(800, $payload['expire_seconds']);
    }

    public function test_the_api_representation_exposes_exactly_the_documented_fields(): void
    {
        $gateway = new Gateways();
        $gateway->forceFill([
            'gateway_uuid' => self::GATEWAY_UUID,
            'domain_uuid' => self::DOMAIN_UUID,
            'gateway' => 'client_poste_250',
            'password' => 'secret',
            'register' => 'false',
            'enabled' => 'false',
        ]);

        $this->assertEqualsCanonicalizing([
            'gateway_uuid', 'object', 'domain_uuid', 'gateway', 'username', 'proxy',
            'register', 'register_transport', 'from_user', 'from_domain',
            'expire_seconds', 'retry_seconds', 'ping', 'channels', 'context',
            'profile', 'hostname', 'enabled', 'description', 'state',
            'ping_state', 'ping_time_ms', 'switch_response', 'acl_response',
        ], array_keys(GatewayData::fromModel($gateway)->toArray()));
    }

    // -----------------------------------------------------------------------
    // Engine state — an unreachable engine is UNKNOWN, never a 500
    // -----------------------------------------------------------------------

    /**
     * @dataProvider switchStates
     */
    public function test_the_engine_state_is_normalized(mixed $raw, string $expected): void
    {
        $this->assertSame($expected, GatewayData::normalizeState($raw));
    }

    public static function switchStates(): array
    {
        return [
            'registered' => ['REGED', 'REGED'],
            'lower case' => ['reged', 'REGED'],
            'padded' => [" NOREG\n", 'NOREG'],
            'no registration' => ['NOREG', 'NOREG'],
            'waiting after failure' => ['FAIL_WAIT', 'FAIL_WAIT'],
            'down' => ['DOWN', 'DOWN'],
            'unregistered' => ['UNREGED', 'UNREGED'],
            'transient state outside the enum' => ['TRYING', 'UNKNOWN'],
            'failure state outside the enum' => ['REG_FAILED', 'UNKNOWN'],
            'engine unreachable' => [null, 'UNKNOWN'],
            'empty' => ['', 'UNKNOWN'],
            'unexpected type' => [['REGED'], 'UNKNOWN'],
        ];
    }

    public function test_an_unreachable_engine_yields_unknown_rather_than_an_error(): void
    {
        $gateway = new Gateways();
        $gateway->forceFill([
            'gateway_uuid' => self::GATEWAY_UUID,
            'domain_uuid' => self::DOMAIN_UUID,
            'register' => 'true',
            'enabled' => 'true',
        ]);

        // No status at all is what the controller hands over when the event
        // socket is down: the state is unknown, the gateway is still returned.
        $payload = GatewayData::fromModel($gateway, [])->toArray();

        $this->assertSame('UNKNOWN', $payload['state']);
        $this->assertNull($payload['ping_state']);
        $this->assertNull($payload['ping_time_ms']);
    }

    // -----------------------------------------------------------------------
    // Cases that need the FusionPBX schema — written, not proven
    // -----------------------------------------------------------------------

    public function test_create_returns_the_uuid_and_the_state(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $response = $this->postJson($this->collectionEndpoint(), $this->validCreatePayload());

        $response->assertStatus(201)
            ->assertJsonPath('object', 'gateway')
            ->assertJsonPath('domain_uuid', self::DOMAIN_UUID)
            ->assertJsonStructure(['gateway_uuid', 'gateway', 'state', 'switch_response', 'acl_response'])
            ->assertHeader('Location');

        $this->assertArrayNotHasKey('password', $response->json());
        $this->assertContains($response->json('state'), [...GatewayData::SWITCH_STATES, GatewayData::STATE_UNKNOWN]);

        // The route domain wins over the session-derived one GatewayService reads.
        $this->assertSame(self::DOMAIN_UUID, Gateways::query()
            ->where('gateway_uuid', $response->json('gateway_uuid'))
            ->value('domain_uuid'));
    }

    public function test_read_reports_the_state_seen_by_the_engine(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();
        $this->mockEventSocket(<<<XML
            <gateways>
              <gateway>
                <name>{$this->gatewayUuid()}</name>
                <state>REGED</state>
                <status>UP</status>
                <pingstate>UP</pingstate>
                <pingtime>12.4</pingtime>
              </gateway>
            </gateways>
            XML);

        $this->getJson($this->itemEndpoint())
            ->assertStatus(200)
            ->assertJsonPath('state', 'REGED')
            ->assertJsonPath('ping_state', 'UP')
            ->assertJsonPath('ping_time_ms', 12.4);
    }

    public function test_read_reports_unknown_when_the_event_socket_is_down(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $esl = Mockery::mock(FreeswitchEslService::class);
        $esl->shouldReceive('isConnected')->andReturn(false);
        $esl->shouldNotReceive('executeCommand');
        $this->app->instance(FreeswitchEslService::class, $esl);

        $this->getJson($this->itemEndpoint())
            ->assertStatus(200)
            ->assertJsonPath('state', 'UNKNOWN')
            ->assertJsonPath('ping_state', null);
    }

    public function test_update_keeps_the_fields_absent_from_the_patch(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $before = Gateways::query()->find(self::GATEWAY_UUID);

        $this->patchJson($this->itemEndpoint(), ['enabled' => false])
            ->assertStatus(200)
            ->assertJsonPath('enabled', false)
            ->assertJsonPath('proxy', $before->proxy);

        $after = Gateways::query()->find(self::GATEWAY_UUID);

        // A partial PATCH must not empty what it did not mention.
        $this->assertSame($before->username, $after->username);
        $this->assertSame($before->password, $after->password);
        $this->assertSame($before->proxy, $after->proxy);
        $this->assertSame('false', $after->enabled);
    }

    public function test_delete_returns_204_and_removes_the_gateway(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $this->deleteJson($this->itemEndpoint())
            ->assertStatus(204)
            ->assertNoContent();

        $this->assertNull(Gateways::query()->find(self::GATEWAY_UUID));
    }

    public function test_restart_is_accepted_with_202(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        $this->postJson($this->itemEndpoint() . '/restart')
            ->assertStatus(202)
            ->assertJsonPath('object', 'gateway')
            ->assertJsonPath('gateway_uuid', self::GATEWAY_UUID)
            ->assertJsonStructure(['switch_response']);
    }

    public function test_restart_surfaces_an_engine_error_as_422(): void
    {
        $this->skipWithoutDatabase();

        $this->actingAsApiUser();

        // GatewayService::executeGatewayCommand() answers
        // '-ERR Could not connect to FreeSWITCH event socket.' when the socket is
        // down: a restart that did not happen must not read as a success.
        $this->postJson($this->itemEndpoint() . '/restart')
            ->assertStatus(422)
            ->assertJsonPath('error.code', 'switch_error');
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private function skipWithoutDatabase(): void
    {
        $this->markTestSkipped(
            'Requires the FusionPBX schema and Domain / Gateways factories, which this '
            . 'repository does not ship: phpunit.xml leaves DB_CONNECTION commented out, '
            . 'the 90 migrations target PostgreSQL/FusionPBX and database/factories/ only '
            . 'holds UserFactory. To be run on an environment that has the database.'
        );
    }

    private function collectionEndpoint(string $domain = self::DOMAIN_UUID): string
    {
        return "/api/v1/domains/{$domain}/gateways";
    }

    private function itemEndpoint(string $domain = self::DOMAIN_UUID, string $gateway = self::GATEWAY_UUID): string
    {
        return "/api/v1/domains/{$domain}/gateways/{$gateway}";
    }

    private function gatewayUuid(): string
    {
        return self::GATEWAY_UUID;
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

    private function mockEventSocket(string $xml): void
    {
        $esl = Mockery::mock(FreeswitchEslService::class);
        $esl->shouldReceive('isConnected')->andReturn(true);
        $esl->shouldReceive('executeCommand')
            ->with('sofia xmlstatus gateway', false)
            ->andReturn(simplexml_load_string($xml));
        $esl->shouldReceive('disconnect');
        $this->app->instance(FreeswitchEslService::class, $esl);
    }

    private function validCreatePayload(): array
    {
        return [
            'gateway' => 'client_poste_250',
            'proxy' => 'sip.example.com:5060',
            'register' => true,
            'username' => '250',
            'password' => 'provider-supplied-secret',
            'register_transport' => 'udp',
            'profile' => 'external',
            'context' => 'public',
            'enabled' => true,
        ];
    }

    private function validateStore(array $payload): ValidatorContract
    {
        $form = StoreGatewayRequest::create($this->collectionEndpoint(), 'POST', $payload);
        $validator = Validator::make($form->all(), $form->rules());
        $form->withValidator($validator);

        return $validator;
    }

    private function validateUpdate(array $payload): ValidatorContract
    {
        $form = UpdateGatewayRequest::create($this->itemEndpoint(), 'PATCH', $payload);
        $validator = Validator::make($form->all(), $form->rules());
        $form->withValidator($validator);

        return $validator;
    }
}
