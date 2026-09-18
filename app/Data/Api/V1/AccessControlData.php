<?php

namespace App\Data\Api\V1;

use App\Models\AccessControl;
use App\Models\AccessControlNode;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Optional;

/**
 * API representation of an access control list.
 *
 * This class is the single place that decides what leaves the API for a list.
 * The columns FusionPBX keeps for bookkeeping (insert_user, update_date, the node
 * UUIDs) have no property here and no branch reads them: a node is exactly the
 * triplet the contract documents, which is also what a PATCH sends back.
 *
 * `nodes` is Optional rather than nullable: the list endpoint omits the key
 * entirely instead of claiming a list has no node.
 */
class AccessControlData extends Data
{
    public const DEFAULT_POLICIES = ['allow', 'deny'];

    public function __construct(
        public string $access_control_uuid,
        public string $object,
        public ?string $access_control_name,
        public string $access_control_default,
        public ?string $access_control_description,
        public array|Optional $nodes,
        public string|null|Optional $switch_response,
    ) {}

    /**
     * Full representation: the list and ALL its nodes.
     *
     * `$accessControl->nodes` must be loaded by the caller; the relation is
     * ordered by node_cidr by the model.
     */
    public static function fromModel(AccessControl $accessControl, ?string $switchResponse = null): self
    {
        return new self(
            access_control_uuid: (string) $accessControl->access_control_uuid,
            object: 'access_control',
            access_control_name: self::text($accessControl->access_control_name),
            access_control_default: self::normalizeDefault($accessControl->access_control_default),
            access_control_description: self::text($accessControl->access_control_description),
            nodes: self::nodes($accessControl),
            switch_response: self::text($switchResponse),
        );
    }

    /**
     * List entry: same list, without its nodes. Reading them is what
     * GET /access-controls/{access_control_uuid} is for.
     */
    public static function summary(AccessControl $accessControl): self
    {
        return new self(
            access_control_uuid: (string) $accessControl->access_control_uuid,
            object: 'access_control',
            access_control_name: self::text($accessControl->access_control_name),
            access_control_default: self::normalizeDefault($accessControl->access_control_default),
            access_control_description: self::text($accessControl->access_control_description),
            nodes: new Optional(),
            switch_response: new Optional(),
        );
    }

    /**
     * Closes the policy enumeration. Anything else stored in the column is
     * reported as `deny`, the fail-closed side — never as `allow`.
     */
    public static function normalizeDefault(mixed $raw): string
    {
        $default = is_string($raw) ? strtolower(trim($raw)) : '';

        return in_array($default, self::DEFAULT_POLICIES, true) ? $default : 'deny';
    }

    /**
     * @return array<int, array{node_type: string, node_cidr: string, node_description: string|null}>
     */
    private static function nodes(AccessControl $accessControl): array
    {
        return $accessControl->nodes
            ->map(fn (AccessControlNode $node) => [
                // Same coercion as AccessControlService::replaceNodes() applies on
                // write, so that what a GET shows is what a PATCH would store back.
                'node_type' => in_array($node->node_type, self::DEFAULT_POLICIES, true)
                    ? (string) $node->node_type
                    : 'allow',
                'node_cidr' => (string) $node->node_cidr,
                'node_description' => self::text($node->node_description),
            ])
            ->values()
            ->all();
    }

    private static function text(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = is_string($value) ? trim($value) : $value;

        return filled($value) ? (string) $value : null;
    }
}
