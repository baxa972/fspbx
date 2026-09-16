<?php

namespace App\Http\Requests\Api\V1;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;

/**
 * Validation of a PATCH on a global access control list.
 *
 * This class is where the security of the endpoint lives.
 * AccessControlService::replaceNodes() deletes every node then re-inserts the
 * ones it receives, and drops without a word any node whose CIDR it cannot
 * normalize: a typo would not raise an error, it would silently shorten the
 * allow-list. Every node is therefore validated here, before the service sees it.
 *
 * The rules go further than the service: a node that FreeSWITCH would happily
 * accept can still be refused here, because an access control list is what
 * stands between the switchboard and the internal network.
 */
class UpdateAccessControlRequest extends FormRequest
{
    /**
     * Private and reserved IPv4 blocks. A node may not overlap any of them:
     * allowing a private range in a provider list opens the internal network to
     * whoever reaches the switchboard.
     */
    public const FORBIDDEN_BLOCKS = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '100.64.0.0/10',
    ];

    /**
     * Narrowest prefix length still accepted on a list whose default policy is
     * deny: /24 passes, /23 and wider do not.
     */
    public const MIN_PREFIX_ON_DENY_LIST = 24;

    public function authorize(): bool
    {
        // API uses route middleware for permissions.
        return true;
    }

    /**
     * Everything is optional: the controller fills the absent fields with the
     * values the list already holds.
     *
     * `nodes` is NOT nullable on purpose. The service reads `$validated['nodes']
     * ?? []`, so `"nodes": null` would wipe the list while looking like "leave it
     * alone". Emptying a list is written `"nodes": []`, and omitting the key
     * keeps the stored nodes (the controller resends them).
     */
    public function rules(): array
    {
        return [
            'access_control_name' => ['sometimes', 'string', 'max:255'],
            'access_control_default' => ['sometimes', 'in:allow,deny'],
            'access_control_description' => ['sometimes', 'nullable', 'string', 'max:255'],

            // Whole-list replacement: what is sent here IS the list.
            'nodes' => ['sometimes', 'array'],
            'nodes.*.node_type' => ['sometimes', 'nullable', 'in:allow,deny'],
            'nodes.*.node_cidr' => ['required', 'string', 'max:255'],
            'nodes.*.node_description' => ['sometimes', 'nullable', 'string', 'max:255'],
        ];
    }

    public function withValidator(Validator $validator): void
    {
        $validator->after(function (Validator $validator) {
            $listDefault = $this->effectiveDefault();

            foreach ((array) $this->input('nodes', []) as $index => $node) {
                $cidr = is_array($node) ? ($node['node_cidr'] ?? null) : null;

                if (! is_string($cidr)) {
                    // 'nodes.*.node_cidr' => required|string already reported it.
                    continue;
                }

                $reason = self::cidrRejectionReason($cidr, $listDefault);

                if ($reason !== null) {
                    $validator->errors()->add("nodes.{$index}.node_cidr", $reason);
                }
            }
        });
    }

    /**
     * Default policy the nodes are judged against.
     *
     * Only an explicit `"access_control_default": "allow"` in the body relaxes the
     * prefix rule. A PATCH that omits the field is validated as if the list denied
     * by default, which is the fail-closed side: on a list that really allows by
     * default, the caller resends the value read from
     * `GET /access-controls/{uuid}` — the sequence the contract prescribes anyway —
     * and nothing changes in the stored list.
     */
    public function effectiveDefault(): string
    {
        return $this->input('access_control_default') === 'allow' ? 'allow' : 'deny';
    }

    /**
     * The whole rule, as a pure function so it can be exercised — and mutated —
     * without an HTTP request or a database.
     *
     * @return string|null null when the CIDR is acceptable, otherwise the reason
     *                     it is refused.
     */
    public static function cidrRejectionReason(string $cidr, string $listDefault = 'deny'): ?string
    {
        $octet = '(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)';

        // a.b.c.d/m only: the prefix is mandatory, octets carry no leading zero
        // (which some resolvers read as octal), and IPv6 is out of scope of the
        // rules below.
        if (! preg_match("#^({$octet}(?:\\.{$octet}){3})/(\d{1,2})$#", trim($cidr), $matches)) {
            return 'Enter an IPv4 range as a.b.c.d/m, with octets between 0 and 255 and an explicit prefix length.';
        }

        $ip = $matches[1];
        $prefix = (int) $matches[2];

        if ($prefix > 32) {
            return 'The prefix length must be between 1 and 32.';
        }

        if ($prefix === 0) {
            return 'A /0 prefix covers the whole internet (0.0.0.0/0) and is never accepted in an access control list.';
        }

        foreach (self::FORBIDDEN_BLOCKS as $block) {
            if (self::overlaps($ip, $prefix, $block)) {
                return "This range overlaps the private or reserved block {$block}, which must not appear in an access control list.";
            }
        }

        if ($listDefault !== 'allow' && $prefix < self::MIN_PREFIX_ON_DENY_LIST) {
            return 'On a list whose default policy is deny, a prefix wider than /'
                . self::MIN_PREFIX_ON_DENY_LIST . ' is refused: narrow the range down.';
        }

        return null;
    }

    /**
     * True when the two IPv4 ranges share at least one address. Overlap, not
     * containment: 10.0.0.0/8 and 10.1.2.3/32 are both inside the private space,
     * and so is 10.0.0.0/7, which contains it.
     */
    private static function overlaps(string $ip, int $prefix, string $block): bool
    {
        [$blockIp, $blockPrefix] = explode('/', $block);

        $shortest = min($prefix, (int) $blockPrefix);

        return self::network($ip, $shortest) === self::network($blockIp, $shortest);
    }

    private static function network(string $ip, int $prefix): int
    {
        $mask = (-1 << (32 - $prefix)) & 0xFFFFFFFF;

        return ((int) ip2long($ip) & 0xFFFFFFFF) & $mask;
    }

    public function bodyParameters(): array
    {
        return [
            'access_control_default' => [
                'description' => 'Policy applied to what no node covers. Omitted, it keeps its current value.',
                'example' => 'deny',
            ],
            'nodes' => [
                'description' => 'Complete and final list of nodes: every node missing from it is deleted, [] empties the list.',
                'example' => [['node_type' => 'allow', 'node_cidr' => '192.0.2.10/32', 'node_description' => 'Carrier SBC 1']],
            ],
        ];
    }
}
