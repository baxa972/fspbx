<?php

namespace App\Http\Requests\Api\V1;

use Illuminate\Validation\Rule;

/**
 * Validation of PATCH /api/v1/domains/{domain_uuid}/dialplans/{dialplan_uuid}.
 *
 * Partial update: nothing is required. The lines keep the rules of the creation
 * as soon as `details` is present, because sending them REPLACES the stored ones
 * in full — there is no line-by-line edit.
 *
 * `details: []` is accepted and means exactly that: replace the lines with none.
 * Omitting the key keeps the stored lines, which the controller resends.
 */
class UpdateDialplanRequest extends StoreDialplanRequest
{
    public function rules(): array
    {
        return [
            'dialplan_name' => ['sometimes', 'string', 'max:255'],
            'dialplan_context' => ['sometimes', 'string', 'max:255'],
            'dialplan_continue' => ['sometimes', 'boolean'],
            'dialplan_order' => ['sometimes', 'integer', 'min:0', 'max:999'],
            'dialplan_enabled' => ['sometimes', 'boolean'],

            'dialplan_number' => ['sometimes', 'nullable', 'string', 'max:255'],
            'dialplan_destination' => ['sometimes', 'nullable', 'boolean'],
            'dialplan_description' => ['sometimes', 'nullable', 'string', 'max:255'],
            'hostname' => ['sometimes', 'nullable', 'string', 'max:255'],
            'editor_mode' => ['sometimes', Rule::in(self::EDITOR_MODES)],
            'dialplan_xml' => ['sometimes', 'nullable', 'string'],

            // Whole-line-set replacement: what is sent here IS the set of lines.
            'details' => ['sometimes', 'array'],
        ] + $this->detailRules();
    }

    /**
     * The stored write mode is not in the body — there is no editor_mode column,
     * and the controller infers it from the stored plan. Any XML that COULD end
     * up written is therefore inspected, instead of trusting an absent mode.
     */
    protected function shouldValidateXml(): bool
    {
        return is_string($this->input('dialplan_xml')) && filled($this->input('dialplan_xml'));
    }
}
