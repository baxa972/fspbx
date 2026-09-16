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
            'profile'  => ['required', 'string', 'max:255'],
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
     * AccessControlService::normalizeCidr() silently drops anything it cannot parse,
     * so an unusable CIDR must be refused here rather than vanish without a trace.
     *
     * Public so the rule can be exercised from a test without booting an HTTP request.
     */
    public function withValidator(Validator $validator): void
    {
        $validator->after(function (Validator $validator) {
            foreach ((array) $this->input('gateway_acl_cidrs', []) as $index => $cidr) {
                if (! is_string($cidr) || ! self::isUsableCidr($cidr)) {
                    $validator->errors()->add(
                        "gateway_acl_cidrs.{$index}",
                        'Enter a valid IP address or CIDR range.'
                    );
                }
            }
        });
    }

    /**
     * Mirrors what AccessControlService::normalizeCidr() is able to accept.
     */
    public static function isUsableCidr(string $value): bool
    {
        $parts = explode('/', str_replace('\\', '/', trim($value)), 2);
        $ip = $parts[0] ?? '';

        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        $prefix = $parts[1] ?? null;

        if ($prefix === null) {
            return true;
        }

        $max = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 32 : 128;

        return is_numeric($prefix) && (int) $prefix >= 0 && (int) $prefix <= $max;
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
