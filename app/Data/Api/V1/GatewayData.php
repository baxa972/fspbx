<?php

namespace App\Data\Api\V1;

use App\Models\Gateways;
use Spatie\LaravelData\Data;

/**
 * API representation of a gateway.
 *
 * This class is the single place that decides what leaves the API for a gateway.
 * `password` has no property here and no branch of `fromModel()` reads it: the
 * SIP password is written and never read back, on any operation.
 */
class GatewayData extends Data
{
    /** States FreeSWITCH reports that this API exposes as-is. */
    public const SWITCH_STATES = ['REGED', 'NOREG', 'FAIL_WAIT', 'DOWN', 'UNREGED'];

    /**
     * Also covers "the event socket is unreachable": an absence of information,
     * not a state of the gateway.
     */
    public const STATE_UNKNOWN = 'UNKNOWN';

    public function __construct(
        public string $gateway_uuid,
        public string $object,
        public ?string $domain_uuid,
        public ?string $gateway,
        public ?string $username,
        public ?string $proxy,
        public bool $register,
        public ?string $register_transport,
        public ?string $from_user,
        public ?string $from_domain,
        public ?int $expire_seconds,
        public ?int $retry_seconds,
        public ?int $ping,
        public ?int $channels,
        public ?string $context,
        public ?string $profile,
        public ?string $hostname,
        public bool $enabled,
        public ?string $description,
        public string $state,
        public ?string $ping_state = null,
        public ?float $ping_time_ms = null,
        public ?string $switch_response = null,
        public ?string $acl_response = null,
    ) {}

    /**
     * @param  array{state?: mixed, ping_state?: mixed, ping_time_ms?: mixed}  $status
     *         State read from the telephony engine, empty when it is unreachable.
     */
    public static function fromModel(
        Gateways $gateway,
        array $status = [],
        ?string $switchResponse = null,
        ?string $aclResponse = null,
    ): self {
        return new self(
            gateway_uuid: (string) $gateway->gateway_uuid,
            object: 'gateway',
            domain_uuid: self::text($gateway->domain_uuid),
            gateway: self::text($gateway->gateway),
            username: self::text($gateway->username),
            proxy: self::text($gateway->proxy),
            register: self::textBoolean($gateway->register),
            register_transport: self::text($gateway->register_transport),
            from_user: self::text($gateway->from_user),
            from_domain: self::text($gateway->from_domain),
            expire_seconds: self::number($gateway->expire_seconds),
            retry_seconds: self::number($gateway->retry_seconds),
            ping: self::number($gateway->ping),
            channels: self::number($gateway->channels),
            context: self::text($gateway->context),
            profile: self::text($gateway->profile),
            hostname: self::text($gateway->hostname),
            enabled: self::textBoolean($gateway->enabled),
            description: self::text($gateway->description),
            state: self::normalizeState($status['state'] ?? null),
            ping_state: self::text($status['ping_state'] ?? null),
            ping_time_ms: isset($status['ping_time_ms']) && is_numeric($status['ping_time_ms'])
                ? (float) $status['ping_time_ms']
                : null,
            switch_response: self::text($switchResponse),
            acl_response: self::text($aclResponse),
        );
    }

    /**
     * Closes the state enumeration: anything FreeSWITCH reports outside the
     * documented set (TRYING, REG_FAILED, …) becomes UNKNOWN, so a client can
     * treat the value as a finite set.
     */
    public static function normalizeState(mixed $raw): string
    {
        if (! is_string($raw) && ! is_numeric($raw)) {
            return self::STATE_UNKNOWN;
        }

        $state = strtoupper(trim((string) $raw));

        return in_array($state, self::SWITCH_STATES, true) ? $state : self::STATE_UNKNOWN;
    }

    private static function text(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = is_string($value) ? trim($value) : $value;

        return filled($value) ? (string) $value : null;
    }

    private static function number(mixed $value): ?int
    {
        return is_numeric($value) ? (int) $value : null;
    }

    /**
     * v_gateways stores booleans as the TEXT values 'true' / 'false'.
     */
    private static function textBoolean(mixed $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }
}
