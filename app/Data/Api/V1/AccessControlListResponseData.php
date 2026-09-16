<?php

namespace App\Data\Api\V1;

use Spatie\LaravelData\Data;

class AccessControlListResponseData extends Data
{
    /**
     * @param array<int, AccessControlData> $data
     */
    public function __construct(
        public string $object,
        public string $url,
        public bool $has_more,
        /** @var array<int, AccessControlData> */
        public array $data,
    ) {}
}
