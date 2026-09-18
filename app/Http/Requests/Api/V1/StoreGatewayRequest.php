<?php

namespace App\Http\Requests\Api\V1;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;

class StoreGatewayRequest extends FormRequest
{
    public function authorize(): bool
    {
        // API uses route middleware for permissions + domain scope
        return true;
    }

    public function rules(): array
    {
        return [
            // Required by the contract: gateway, proxy, register, profile, enabled.
            'gateway'  => ['required', 'string', 'max:255'],
            'proxy'    => ['required', 'string', 'max:255'],
            'register' => ['required', 'boolean'],
            // Interpolated into ESL commands: the alphabet is the guard.
            'profile'  => ['required', 'string', 'max:255', 'regex:/^[a-zA-Z0-9_-]+$/'],
            'enabled'  => ['required', 'boolean'],

            // Credentials are mandatory as soon as the gateway registers.
            'username' => ['nullable', 'string', 'max:255', 'required_if:register,true'],
            'password' => ['nullable', 'string', 'max:255', 'required_if:register,true'],

            'auth_username'      => ['nullable', 'string', 'max:255'],
            'realm'              => ['nullable', 'string', 'max:255'],
            'from_user'          => ['nullable', 'string', 'max:255'],
            'from_domain'        => ['nullable', 'string', 'max:255'],
            'register_proxy'     => ['nullable', 'string', 'max:255'],
            'outbound_proxy'     => ['nullable', 'string', 'max:255'],
            'register_transport' => ['nullable', 'in:udp,tcp,tls'],
            'contact_params'     => ['nullable', 'string', 'max:255'],
            'extension'          => ['nullable', 'string', 'max:255'],
            'codec_prefs'        => ['nullable', 'string', 'max:255'],
            'sip_cid_type'       => ['nullable', 'in:none,pid,rpid'],
            'context'            => ['sometimes', 'string', 'max:255'],
            'hostname'           => ['nullable', 'string', 'max:255'],
            'description'        => ['nullable', 'string', 'max:255'],

            'expire_seconds' => ['sometimes', 'integer', 'min:1', 'max:65535'],
            'retry_seconds'  => ['sometimes', 'integer', 'min:1', 'max:65535'],
            'ping'           => ['nullable', 'integer', 'min:1', 'max:65535'],
            'ping_min'       => ['nullable', 'integer', 'min:1', 'max:65535'],
            'ping_max'       => ['nullable', 'integer', 'min:1', 'max:65535'],
            'channels'       => ['nullable', 'integer', 'min:0', 'max:65535'],

            // Stored as TEXT 'true'/'false' in v_gateways; normalized by the controller.
            'distinct_to'          => ['nullable', 'boolean'],
            'contact_in_ping'      => ['nullable', 'boolean'],
            'caller_id_in_from'    => ['nullable', 'boolean'],
            'supress_cng'          => ['nullable', 'boolean'],
            'extension_in_contact' => ['nullable', 'boolean'],

            // Provider IP allow-list. Whole-list replacement, an empty array clears it.
            'gateway_acl_cidrs'   => ['sometimes', 'nullable', 'array'],
            'gateway_acl_cidrs.*' => ['string', 'max:255'],
        ];
    }

    /**
     * These CIDRs land in the instance-wide `providers` access control list via
     * AccessControlService::syncGatewayProviderIps() — the very list the PATCH
     * ACL endpoint guards. They are therefore judged by the SAME rule, with the
     * default policy the service writes on those lists: deny. A private block,
     * 0.0.0.0/0, an IPv6 range or a prefix wider than /24 here would re-open
     * exactly what UpdateAccessControlRequest refuses.
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
            'gateway'  => ['description' => 'Logical gateway name. Sofia names the gateway by its UUID, not by this.', 'example' => 'client_poste_250'],
            'proxy'    => ['description' => 'Remote SIP proxy, host or host:port.', 'example' => 'sip.example.com:5060'],
            'register' => ['description' => 'Whether the gateway registers against the proxy.', 'example' => true],
            'username' => ['description' => 'SIP username. Required when register is true.', 'example' => '250'],
            'password' => ['description' => 'SIP password. Write-only: never returned by this API.', 'example' => 'provider-supplied-secret'],
            'register_transport' => ['description' => 'SIP transport used for registration (udp, tcp, tls).', 'example' => 'udp'],
            'profile'  => ['description' => 'Sofia profile carrying the gateway.', 'example' => 'external'],
            'context'  => ['description' => 'Dialplan context for inbound calls from this gateway.', 'example' => 'public'],
            'enabled'  => ['description' => 'Whether the gateway is active.', 'example' => true],
            'gateway_acl_cidrs' => ['description' => 'Provider IP allow-list, whole-list replacement.', 'example' => ['192.0.2.10/32']],
        ];
    }
}
