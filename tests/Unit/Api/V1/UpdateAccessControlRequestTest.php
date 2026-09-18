<?php

namespace Tests\Unit\Api\V1;

use App\Http\Requests\Api\V1\UpdateAccessControlRequest;
use Illuminate\Contracts\Validation\Validator as ValidatorContract;
use Illuminate\Support\Facades\Validator;
use Tests\TestCase;

/**
 * The CIDR rules of PATCH /api/v1/access-controls/{uuid} (NOV-1008).
 *
 * EVERYTHING IN THIS FILE REALLY RUNS: validation needs no database.
 *
 * Why it matters: AccessControlService::replaceNodes() deletes every node then
 * re-inserts the ones it receives, and skips without a word any CIDR it cannot
 * normalize. A refusal that does not happen here does not become an error later,
 * it becomes a silently shortened allow-list — or, worse, a private range opened
 * to whoever reaches the switchboard.
 *
 * There is one test per refused family on purpose: a single test covering them
 * all would still pass with one family missing from the implementation.
 */
class UpdateAccessControlRequestTest extends TestCase
{
    private const ACL_UUID = '2b6a9f41-7c3d-4e58-9a10-3f5b8c7d6e21';

    // -----------------------------------------------------------------------
    // Shape: a.b.c.d/m with valid octets
    // -----------------------------------------------------------------------

    /**
     * @dataProvider malformedCidrs
     */
    public function test_a_cidr_that_is_not_an_ipv4_range_with_a_prefix_is_refused(string $cidr): void
    {
        $this->assertRefused($cidr, 'deny');
    }

    public static function malformedCidrs(): array
    {
        return [
            'not an address' => ['pas-une-ip'],
            'empty' => [''],
            'host name' => ['sip.example.com/32'],
            'octet above 255' => ['256.0.2.10/32'],
            'five octets' => ['192.0.2.10.7/32'],
            'three octets' => ['192.0.2/24'],
            'leading zero octet, read as octal by some resolvers' => ['192.000.2.010/32'],
            'no prefix at all' => ['192.0.2.10'],
            'prefix out of range' => ['192.0.2.10/33'],
            'negative prefix' => ['192.0.2.10/-1'],
            'prefix is not a number' => ['192.0.2.10/abc'],
            'ipv6' => ['2001:db8::1/128'],
            'trailing junk' => ['192.0.2.10/32 ; drop'],
        ];
    }

    /**
     * @dataProvider acceptableCidrs
     */
    public function test_a_public_range_narrow_enough_is_accepted(string $cidr): void
    {
        $this->assertAccepted($cidr, 'deny');
    }

    public static function acceptableCidrs(): array
    {
        return [
            'documentation host' => ['192.0.2.10/32'],
            'documentation range' => ['198.51.100.0/24'],
            'another documentation host' => ['203.0.113.42/32'],
            'narrower than /24' => ['203.0.113.0/28'],
        ];
    }

    // -----------------------------------------------------------------------
    // One test per refused family — never a single global one
    // -----------------------------------------------------------------------

    public function test_the_private_block_10_0_0_0_8_is_refused(): void
    {
        $this->assertRefused('10.0.0.0/8', 'allow');
        $this->assertRefused('10.1.2.3/32', 'allow');
        $this->assertRefused('10.255.255.0/24', 'deny');
    }

    public function test_the_private_block_172_16_0_0_12_is_refused(): void
    {
        $this->assertRefused('172.16.0.0/12', 'allow');
        $this->assertRefused('172.20.5.7/32', 'allow');
        $this->assertRefused('172.31.255.0/24', 'deny');

        // Just outside the block: 172.15 and 172.32 are public.
        $this->assertAccepted('172.15.0.0/24', 'deny');
        $this->assertAccepted('172.32.0.0/24', 'deny');
    }

    public function test_the_private_block_192_168_0_0_16_is_refused(): void
    {
        $this->assertRefused('192.168.0.0/16', 'allow');
        $this->assertRefused('192.168.1.42/32', 'allow');
        $this->assertRefused('192.168.10.0/24', 'deny');
    }

    public function test_the_loopback_block_127_0_0_0_8_is_refused(): void
    {
        $this->assertRefused('127.0.0.0/8', 'allow');
        $this->assertRefused('127.0.0.1/32', 'allow');
        $this->assertRefused('127.10.0.0/24', 'deny');
    }

    public function test_the_carrier_grade_nat_block_100_64_0_0_10_is_refused(): void
    {
        $this->assertRefused('100.64.0.0/10', 'allow');
        $this->assertRefused('100.100.1.1/32', 'allow');
        $this->assertRefused('100.127.255.0/24', 'deny');

        // Just outside the block: 100.63 and 100.128 are public.
        $this->assertAccepted('100.63.255.0/24', 'deny');
        $this->assertAccepted('100.128.0.0/24', 'deny');
    }

    public function test_the_whole_internet_0_0_0_0_0_is_refused(): void
    {
        $this->assertRefused('0.0.0.0/0', 'allow');
        $this->assertRefused('0.0.0.0/0', 'deny');

        // A /0 prefix covers everything whatever address carries it.
        $this->assertRefused('203.0.113.7/0', 'allow');
    }

    /**
     * A supernet that swallows a private block is refused too: the rule is an
     * overlap, not a containment in one direction only.
     */
    public function test_a_supernet_that_contains_a_private_block_is_refused(): void
    {
        $this->assertRefused('8.0.0.0/6', 'allow');   // contains 10.0.0.0/8
        $this->assertRefused('192.128.0.0/9', 'allow'); // contains 192.168.0.0/16
    }

    // -----------------------------------------------------------------------
    // Prefix width on a list that denies by default
    // -----------------------------------------------------------------------

    public function test_a_prefix_wider_than_24_is_refused_on_a_deny_list(): void
    {
        $this->assertRefused('198.51.100.0/23', 'deny');
        $this->assertRefused('198.51.100.0/16', 'deny');
        $this->assertRefused('198.51.100.0/8', 'deny');
    }

    public function test_a_prefix_of_24_or_narrower_is_accepted_on_a_deny_list(): void
    {
        $this->assertAccepted('198.51.100.0/24', 'deny');
        $this->assertAccepted('198.51.100.0/25', 'deny');
        $this->assertAccepted('198.51.100.7/32', 'deny');
    }

    public function test_a_wide_prefix_is_only_accepted_when_the_list_explicitly_allows_by_default(): void
    {
        $this->assertAccepted('198.51.100.0/23', 'allow');
        $this->assertRefused('198.51.100.0/23', 'deny');
    }

    /**
     * The fail-closed side: a PATCH that does not say what the default policy is
     * is judged as if the list denied by default.
     */
    public function test_an_omitted_default_is_judged_as_deny(): void
    {
        $form = $this->form(['nodes' => [['node_cidr' => '198.51.100.0/23']]]);

        $this->assertSame('deny', $form->effectiveDefault());
        $this->assertArrayHasKey('nodes.0.node_cidr', $this->validate($form)->errors()->toArray());
    }

    public function test_an_unknown_default_in_the_body_is_refused_by_the_rules(): void
    {
        $validator = $this->validate($this->form(['access_control_default' => 'maybe']));

        $this->assertArrayHasKey('access_control_default', $validator->errors()->toArray());
    }

    // -----------------------------------------------------------------------
    // The rule reaches the validator, and points at the offending node
    // -----------------------------------------------------------------------

    public function test_the_error_names_the_index_of_the_offending_node(): void
    {
        $validator = $this->validate($this->form([
            'access_control_default' => 'deny',
            'nodes' => [
                ['node_type' => 'allow', 'node_cidr' => '192.0.2.10/32'],
                ['node_type' => 'allow', 'node_cidr' => '10.0.0.0/8'],
                ['node_type' => 'allow', 'node_cidr' => '198.51.100.0/24'],
            ],
        ]));

        $errors = $validator->errors()->toArray();

        $this->assertArrayHasKey('nodes.1.node_cidr', $errors);
        $this->assertArrayNotHasKey('nodes.0.node_cidr', $errors);
        $this->assertArrayNotHasKey('nodes.2.node_cidr', $errors);
        $this->assertStringContainsString('10.0.0.0/8', $errors['nodes.1.node_cidr'][0]);
    }

    public function test_a_node_without_a_cidr_is_refused(): void
    {
        $errors = $this->validate($this->form([
            'nodes' => [['node_type' => 'allow', 'node_description' => 'no address']],
        ]))->errors()->toArray();

        $this->assertArrayHasKey('nodes.0.node_cidr', $errors);
    }

    public function test_an_unknown_node_type_is_refused(): void
    {
        $errors = $this->validate($this->form([
            'nodes' => [['node_type' => 'maybe', 'node_cidr' => '192.0.2.10/32']],
        ]))->errors()->toArray();

        $this->assertArrayHasKey('nodes.0.node_type', $errors);
    }

    /**
     * The service applies the same rules to an allow node and to a deny node, and
     * so does this validation: a deny node is refused too, rather than trusting
     * the caller to have meant it.
     */
    public function test_the_rules_apply_whatever_the_node_type(): void
    {
        $errors = $this->validate($this->form([
            'access_control_default' => 'deny',
            'nodes' => [['node_type' => 'deny', 'node_cidr' => '192.168.0.0/16']],
        ]))->errors()->toArray();

        $this->assertArrayHasKey('nodes.0.node_cidr', $errors);
    }

    // -----------------------------------------------------------------------
    // What a legitimate payload looks like
    // -----------------------------------------------------------------------

    public function test_a_complete_legitimate_payload_passes(): void
    {
        $validator = $this->validate($this->form([
            'access_control_name' => 'providers',
            'access_control_default' => 'deny',
            'access_control_description' => 'Provider IP access control list.',
            'nodes' => [
                ['node_type' => 'allow', 'node_cidr' => '192.0.2.10/32', 'node_description' => 'Carrier SBC 1'],
                ['node_type' => 'allow', 'node_cidr' => '198.51.100.0/24', 'node_description' => 'Carrier media range'],
            ],
        ]));

        $this->assertFalse($validator->fails(), json_encode($validator->errors()->toArray()));
    }

    public function test_an_empty_nodes_array_is_accepted_and_means_emptying_the_list(): void
    {
        $this->assertFalse($this->validate($this->form(['nodes' => []]))->fails());
    }

    /**
     * `nodes: null` must NOT pass: the service reads `$validated['nodes'] ?? []`,
     * so a null would wipe the list while looking like "do not touch it".
     */
    public function test_a_null_nodes_key_is_refused(): void
    {
        $this->assertArrayHasKey('nodes', $this->validate($this->form(['nodes' => null]))->errors()->toArray());
    }

    public function test_an_empty_payload_is_accepted_and_changes_nothing(): void
    {
        $this->assertFalse($this->validate($this->form([]))->fails());
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private function assertRefused(string $cidr, string $listDefault): void
    {
        $this->assertNotNull(
            UpdateAccessControlRequest::cidrRejectionReason($cidr, $listDefault),
            "CIDR '{$cidr}' should have been refused on a list whose default is {$listDefault}."
        );

        // And the refusal really comes out of the validator, not only of the rule.
        $errors = $this->validate($this->form([
            'access_control_default' => $listDefault,
            'nodes' => [['node_type' => 'allow', 'node_cidr' => $cidr]],
        ]))->errors()->toArray();

        $this->assertArrayHasKey('nodes.0.node_cidr', $errors, "CIDR '{$cidr}' passed validation.");
    }

    private function assertAccepted(string $cidr, string $listDefault): void
    {
        $this->assertNull(
            UpdateAccessControlRequest::cidrRejectionReason($cidr, $listDefault),
            "CIDR '{$cidr}' should have been accepted on a list whose default is {$listDefault}."
        );

        $errors = $this->validate($this->form([
            'access_control_default' => $listDefault,
            'nodes' => [['node_type' => 'allow', 'node_cidr' => $cidr]],
        ]))->errors()->toArray();

        $this->assertArrayNotHasKey('nodes.0.node_cidr', $errors, "CIDR '{$cidr}' was refused.");
    }

    private function form(array $payload): UpdateAccessControlRequest
    {
        return UpdateAccessControlRequest::create(
            '/api/v1/access-controls/' . self::ACL_UUID,
            'PATCH',
            $payload
        );
    }

    private function validate(UpdateAccessControlRequest $form): ValidatorContract
    {
        $validator = Validator::make($form->all(), $form->rules());
        $form->withValidator($validator);

        return $validator;
    }
}
