<?php

namespace App\Http\Requests\Api\V1;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;

class UpdateGatewayRequest extends FormRequest
{
    public function authorize(): bool
    {
        // API uses route middleware for permissions + domain scope
        return true;
    }

    /**
     * Partial update: nothing is required, only the submitted fields are applied.
     *
     * `username` / `password` carry no `required_if:register,true` here on purpose:
     * on a PATCH the credentials already stored stay in place, so requiring them
     * again would refuse a legitimate `{"register": true}` on a gateway that
     * already holds them.
     */
    public function rules(): array
    {
        return [
            'gateway'  => ['sometimes', 'string', 'max:255'],
            'proxy'    => ['sometimes', 'string', 'max:255'],
            'register' => ['sometimes', 'boolean'],
            // Interpolated into ESL commands: the alphabet is the guard.
            'profile'  => ['sometimes', 'string', 'max:255', 'regex:/^[a-zA-Z0-9_-]+$/'],
            'enabled'  => ['sometimes', 'boolean'],
            'context'  => ['sometimes', 'string', 'max:255'],

            'username' => ['sometimes', 'nullable', 'string', 'max:255'],
            'password' => ['sometimes', 'nullable', 'string', 'max:255'],

            'auth_username'      => ['sometimes', 'nullable', 'string', 'max:255'],
            'realm'              => ['sometimes', 'nullable', 'string', 'max:255'],
            'from_user'          => ['sometimes', 'nullable', 'string', 'max:255'],
            'from_domain'        => ['sometimes', 'nullable', 'string', 'max:255'],
            'register_proxy'     => ['sometimes', 'nullable', 'string', 'max:255'],
            'outbound_proxy'     => ['sometimes', 'nullable', 'string', 'max:255'],
            'register_transport' => ['sometimes', 'nullable', 'in:udp,tcp,tls'],
            'contact_params'     => ['sometimes', 'nullable', 'string', 'max:255'],
            'extension'          => ['sometimes', 'nullable', 'string', 'max:255'],
            'codec_prefs'        => ['sometimes', 'nullable', 'string', 'max:255'],
            'sip_cid_type'       => ['sometimes', 'nullable', 'in:none,pid,rpid'],
            'hostname'           => ['sometimes', 'nullable', 'string', 'max:255'],
            'description'        => ['sometimes', 'nullable', 'string', 'max:255'],

            'expire_seconds' => ['sometimes', 'integer', 'min:1', 'max:65535'],
            'retry_seconds'  => ['sometimes', 'integer', 'min:1', 'max:65535'],
            'ping'           => ['sometimes', 'nullable', 'integer', 'min:1', 'max:65535'],
            'ping_min'       => ['sometimes', 'nullable', 'integer', 'min:1', 'max:65535'],
            'ping_max'       => ['sometimes', 'nullable', 'integer', 'min:1', 'max:65535'],
            'channels'       => ['sometimes', 'nullable', 'integer', 'min:0', 'max:65535'],

            // Stored as TEXT 'true'/'false' in v_gateways; normalized by the controller.
            'distinct_to'          => ['sometimes', 'nullable', 'boolean'],
            'contact_in_ping'      => ['sometimes', 'nullable', 'boolean'],
            'caller_id_in_from'    => ['sometimes', 'nullable', 'boolean'],
            'supress_cng'          => ['sometimes', 'nullable', 'boolean'],
            'extension_in_contact' => ['sometimes', 'nullable', 'boolean'],

            // Whole-list replacement. Absent: the allow-list is left untouched.
            'gateway_acl_cidrs'   => ['sometimes', 'nullable', 'array'],
            'gateway_acl_cidrs.*' => ['string', 'max:255'],
        ];
    }

    /**
     * Same guard as the creation: these CIDRs are written to the instance-wide
     * `providers` ACL, so the PATCH ACL rule applies (see StoreGatewayRequest).
     */
    public function withValidator(Validator $validator): void
    {
        $validator->after(function (Validator $validator) {
            foreach ((array) $this->input('gateway_acl_cidrs', []) as $index => $cidr) {
                $reason = is_string($cidr)
                    ? UpdateAccessControlRequest::cidrRejectionReason($cidr, 'deny')
                    : 'Enter an IPv4 range as a.b.c.d/m, with octets between 0 and 255 and an explicit prefix length.';

                if ($reason !== null) {
                    $validator->errors()->add("gateway_acl_cidrs.{$index}", $reason);
                }
            }
        });
    }

    public function bodyParameters(): array
    {
        return [
            'proxy'    => ['description' => 'Remote SIP proxy, host or host:port.', 'example' => 'sip.example.com:5060'],
            'password' => ['description' => 'SIP password. Write-only: never returned by this API.', 'example' => 'provider-supplied-secret'],
            'enabled'  => ['description' => 'Whether the gateway is active.', 'example' => false],
            'gateway_acl_cidrs' => ['description' => 'Provider IP allow-list, whole-list replacement. Omit to leave it untouched.', 'example' => ['192.0.2.10/32']],
        ];
    }
}
