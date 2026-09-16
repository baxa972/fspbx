<?php

namespace App\Data\Api\V1;

use App\Models\DialplanDetails;
use App\Models\Dialplans;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Optional;

/**
 * API representation of a dialplan.
 *
 * This class is the single place that decides what leaves the API for a plan.
 *
 * `dialplan_xml` has no property here and no branch reads it: in builder mode the
 * XML is rebuilt from `details` on every write, so returning it would publish a
 * second, derived truth that a client could be tempted to send back. The same
 * goes for the FusionPBX bookkeeping columns (insert_user, update_date, app_uuid).
 *
 * `details` is Optional rather than an empty array: a list entry omits the key
 * instead of claiming a plan has no line.
 */
class DialplanData extends Data
{
    public function __construct(
        public string $dialplan_uuid,
        public string $object,
        public ?string $domain_uuid,
        public ?string $dialplan_name,
        public ?string $dialplan_number,
        public ?string $dialplan_context,
        public ?int $dialplan_order,
        public bool $dialplan_enabled,
        public bool $dialplan_continue,
        public ?bool $dialplan_destination,
        public ?string $dialplan_description,
        public array|Optional $details,
        public string|null|Optional $switch_response,
    ) {}

    /**
     * Full representation: the plan and its lines.
     *
     * @param  iterable<int, DialplanDetails>  $details
     *         Lines already sorted by group then order — the order the engine
     *         reads them in, which is not the order they were sent in.
     */
    public static function fromModel(
        Dialplans $dialplan,
        iterable $details = [],
        ?string $switchResponse = null
    ): self {
        $rows = [];

        foreach ($details as $detail) {
            $rows[] = self::detail($detail);
        }

        return new self(
            dialplan_uuid: (string) $dialplan->dialplan_uuid,
            object: 'dialplan',
            domain_uuid: self::text($dialplan->domain_uuid),
            dialplan_name: self::text($dialplan->dialplan_name),
            dialplan_number: self::text($dialplan->dialplan_number),
            dialplan_context: self::text($dialplan->dialplan_context),
            dialplan_order: self::number($dialplan->dialplan_order),
            dialplan_enabled: self::textBoolean($dialplan->dialplan_enabled),
            dialplan_continue: self::textBoolean($dialplan->dialplan_continue),
            dialplan_destination: self::nullableTextBoolean($dialplan->dialplan_destination),
            dialplan_description: self::text($dialplan->dialplan_description),
            details: $rows,
            switch_response: self::text($switchResponse),
        );
    }

    /**
     * List entry: the same plan without its lines. Reading them is what
     * GET /domains/{domain_uuid}/dialplans/{dialplan_uuid} is for.
     */
    public static function summary(Dialplans $dialplan): self
    {
        return new self(
            dialplan_uuid: (string) $dialplan->dialplan_uuid,
            object: 'dialplan',
            domain_uuid: self::text($dialplan->domain_uuid),
            dialplan_name: self::text($dialplan->dialplan_name),
            dialplan_number: self::text($dialplan->dialplan_number),
            dialplan_context: self::text($dialplan->dialplan_context),
            dialplan_order: self::number($dialplan->dialplan_order),
            dialplan_enabled: self::textBoolean($dialplan->dialplan_enabled),
            dialplan_continue: self::textBoolean($dialplan->dialplan_continue),
            dialplan_destination: self::nullableTextBoolean($dialplan->dialplan_destination),
            dialplan_description: self::text($dialplan->dialplan_description),
            details: new Optional(),
            switch_response: new Optional(),
        );
    }

    /**
     * One line, in the very shape a PATCH sends back: what a GET shows can be
     * modified and returned as `details` without any translation.
     *
     * @return array<string, mixed>
     */
    public static function detail(DialplanDetails $detail): array
    {
        return [
            'dialplan_detail_uuid' => self::text($detail->dialplan_detail_uuid),
            'dialplan_detail_tag' => self::text($detail->dialplan_detail_tag),
            'dialplan_detail_type' => self::text($detail->dialplan_detail_type),
            'dialplan_detail_data' => self::text($detail->dialplan_detail_data),
            'dialplan_detail_break' => self::text($detail->dialplan_detail_break),
            'dialplan_detail_inline' => self::nullableTextBoolean($detail->dialplan_detail_inline),
            'dialplan_detail_group' => (int) self::number($detail->dialplan_detail_group),
            'dialplan_detail_order' => (int) self::number($detail->dialplan_detail_order),
            'dialplan_detail_enabled' => self::textBoolean($detail->dialplan_detail_enabled),
        ];
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
     * v_dialplans and v_dialplan_details store booleans as the TEXT values
     * 'true' / 'false'. Two of those columns are already cast to bool by their
     * model accessor, which filter_var() handles just the same.
     */
    private static function textBoolean(mixed $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * Same, for the columns where "not set" is a third value and must not be
     * reported as false.
     */
    private static function nullableTextBoolean(mixed $value): ?bool
    {
        if ($value === null || $value === '') {
            return null;
        }

        return filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }
}
