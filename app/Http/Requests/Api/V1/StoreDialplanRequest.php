<?php

namespace App\Http\Requests\Api\V1;

use App\Services\DialplanService;
use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * Validation of POST /api/v1/domains/{domain_uuid}/dialplans.
 *
 * This class is where the security and the usefulness of the endpoint are decided.
 *
 *  - DialplanService::normalizedDetails() DROPS WITHOUT A WORD every line that
 *    carries no `dialplan_detail_tag`. A payload full of typos would therefore be
 *    written as a dialplan with zero detail line and still answer 201: an inert
 *    plan, which routes nothing and is only noticed when a call fails. Every line
 *    is validated here, before the service ever sees it.
 *
 *  - The FreeSWITCH applications `system`, `bgsystem`, `spawn`, `bg_spawn` and
 *    `spawn_stream` execute a shell command on the PBX. They are refused in the
 *    builder lines and in the raw XML alike.
 *
 * The contract names the lines `details`; DialplanService reads them under the
 * key `dialplan_details`. The rename happens in
 * Api\V1\DialplanController::toServicePayload(), which is the one place that
 * knows both names.
 */
class StoreDialplanRequest extends FormRequest
{
    /** Line kinds v_dialplan_details accepts. */
    public const DETAIL_TAGS = ['condition', 'regex', 'action', 'anti-action'];

    /** Lines that carry a FreeSWITCH application, hence the dangerous-application check. */
    public const ACTION_TAGS = ['action', 'anti-action'];

    public const BREAK_VALUES = ['on-true', 'on-false', 'always', 'never'];

    public const EDITOR_MODES = ['builder', 'xml'];

    public function authorize(): bool
    {
        // API uses route middleware for permissions + domain scope.
        return true;
    }

    /**
     * `domain_uuid` is deliberately absent: the attachment comes from the route
     * only, so a body one can never reach the service.
     */
    public function rules(): array
    {
        $rules = [
            'dialplan_name' => ['required', 'string', 'max:255'],
            'dialplan_context' => ['required', 'string', 'max:255'],
            'dialplan_continue' => ['required', 'boolean'],
            'dialplan_order' => ['required', 'integer', 'min:0', 'max:999'],
            'dialplan_enabled' => ['required', 'boolean'],

            'dialplan_number' => ['sometimes', 'nullable', 'string', 'max:255'],
            'dialplan_destination' => ['sometimes', 'nullable', 'boolean'],
            'dialplan_description' => ['sometimes', 'nullable', 'string', 'max:255'],
            'hostname' => ['sometimes', 'nullable', 'string', 'max:255'],
            'editor_mode' => ['sometimes', Rule::in(self::EDITOR_MODES)],
        ];

        if ($this->isXmlMode()) {
            // The XML is stored as received: it is the only source of the plan.
            $rules['dialplan_xml'] = ['required', 'string'];
            $rules['details'] = ['sometimes', 'array'];
        } else {
            // Builder mode: the XML is rebuilt from the lines, so there must be lines.
            // An empty array here is what produces the inert plan described above.
            $rules['dialplan_xml'] = ['sometimes', 'nullable', 'string'];
            $rules['details'] = ['required', 'array', 'min:1'];
        }

        return $rules + $this->detailRules();
    }

    public function withValidator(Validator $validator): void
    {
        $validator->after(function (Validator $validator) {
            $service = app(DialplanService::class);

            if ($this->hasAmbiguousEditorMode()) {
                $validator->errors()->add(
                    'editor_mode',
                    'Send editor_mode explicitly when both dialplan_xml and details are present: '
                    . '"builder" builds the XML from details and ignores dialplan_xml, '
                    . '"xml" stores dialplan_xml and ignores details.'
                );
            }

            if ($this->shouldValidateXml()) {
                foreach ($service->validateXml((string) $this->input('dialplan_xml')) as $message) {
                    $validator->errors()->add('dialplan_xml', $message);
                }
            }

            if ($this->isXmlMode()) {
                // The service ignores the lines in this mode; judging them would
                // refuse a payload on a field that is never written.
                return;
            }

            foreach ($this->detailLines() as $index => $detail) {
                $tag = $detail['dialplan_detail_tag'] ?? null;

                if (! in_array($tag, self::ACTION_TAGS, true)) {
                    continue;
                }

                // Both the application and its argument are inspected: `set` with
                // `execute_on_answer=system …` is as dangerous as `system` itself.
                if ($service->containsDangerousApplication(self::asText($detail['dialplan_detail_type'] ?? null))
                    || $service->containsDangerousApplication(self::asText($detail['dialplan_detail_data'] ?? null))) {
                    $validator->errors()->add(
                        "details.{$index}.dialplan_detail_type",
                        'This FreeSWITCH application is not allowed.'
                    );
                }
            }
        });
    }

    /**
     * Per-line rules, shared with UpdateDialplanRequest.
     *
     * `dialplan_detail_tag`, `_type`, `_data` and `_order` are required on every
     * line: a line without a tag is dropped by the service, and a line without a
     * type or data is written but does nothing. `_order` carries the position in
     * the group — the order of the array itself is never read.
     */
    protected function detailRules(): array
    {
        return [
            'details.*' => ['array'],
            'details.*.dialplan_detail_uuid' => ['sometimes', 'nullable', 'uuid'],
            'details.*.dialplan_detail_tag' => ['required', Rule::in(self::DETAIL_TAGS)],
            'details.*.dialplan_detail_type' => ['required', 'string', 'max:255'],
            'details.*.dialplan_detail_data' => ['required', 'string', 'max:4096'],
            'details.*.dialplan_detail_break' => ['sometimes', 'nullable', Rule::in(self::BREAK_VALUES)],
            'details.*.dialplan_detail_inline' => ['sometimes', 'nullable', 'boolean'],
            'details.*.dialplan_detail_group' => ['sometimes', 'integer', 'min:0', 'max:999'],
            'details.*.dialplan_detail_order' => ['required', 'integer', 'min:0', 'max:9999'],
            'details.*.dialplan_detail_enabled' => ['sometimes', 'boolean'],
        ];
    }

    /**
     * True when the body writes raw XML. Absent editor_mode means `builder`,
     * which is the default of the contract and of DialplanService::save().
     */
    public function isXmlMode(): bool
    {
        return $this->input('editor_mode') === 'xml';
    }

    /**
     * The two write modes are exclusive and silent about each other: in builder
     * mode the XML sent is thrown away, in xml mode the lines are never written.
     * Rather than pick one for the caller, a body carrying both without saying
     * which is refused.
     */
    public function hasAmbiguousEditorMode(): bool
    {
        return blank($this->input('editor_mode'))
            && filled($this->input('dialplan_xml'))
            && filled($this->input('details'));
    }

    /**
     * On a creation the XML is only stored in xml mode, so that is the only mode
     * where it is inspected. UpdateDialplanRequest widens this.
     */
    protected function shouldValidateXml(): bool
    {
        return $this->isXmlMode() && is_string($this->input('dialplan_xml'));
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    protected function detailLines(): array
    {
        $details = $this->input('details', []);

        if (! is_array($details)) {
            return [];
        }

        return array_filter($details, 'is_array');
    }

    private static function asText(mixed $value): ?string
    {
        return is_string($value) ? $value : null;
    }
}
