<?php

namespace App\Data\Api\V1;

use Spatie\LaravelData\Data;

/**
 * List envelope of the v1 API, cursor paginated. The entries are
 * DialplanData::summary(), so no list ever carries the lines of a plan.
 */
class DialplanListResponseData extends Data
{
    /**
     * @param array<int, DialplanData> $data
     */
    public function __construct(
        public string $object,
        public string $url,
        public bool $has_more,
        /** @var array<int, DialplanData> */
        public array $data,
    ) {}
}
