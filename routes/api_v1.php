<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\V1\DomainController;
use App\Http\Controllers\Api\V1\ActiveCallController;
use App\Http\Controllers\Api\V1\DeviceController;
use App\Http\Controllers\Api\V1\ExtensionController;
use App\Http\Controllers\Api\V1\ExtensionStatisticController;
use App\Http\Controllers\Api\V1\RegistrationController;
use App\Http\Controllers\Api\V1\RingGroupController;
use App\Http\Controllers\Api\V1\VoicemailController;
use App\Http\Controllers\Api\V1\PhoneNumberController;
use App\Http\Controllers\Api\V1\CdrController;
use App\Http\Controllers\Api\V1\GatewayController;
use App\Http\Controllers\Api\V1\AccessControlController;
use App\Http\Controllers\Api\V1\DialplanController;

/*
|--------------------------------------------------------------------------
| API V1 Routes
|--------------------------------------------------------------------------
|
*/

Route::middleware(['auth:sanctum', 'api.token.auth', 'throttle:api'])->group(function () {

    /*
    |--------------------------------------------------------------------------
    | Domains
    |--------------------------------------------------------------------------
    */

    Route::get('/domains', [DomainController::class, 'index'])
        ->middleware('user.authorize:domain_select');

    Route::get('/domains/{domain_uuid}', [DomainController::class, 'show'])
        ->middleware('user.authorize:domain_view');

    Route::post('/domains', [DomainController::class, 'store'])
        ->middleware('user.authorize:domain_add');

    Route::patch('/domains/{domain_uuid}', [DomainController::class, 'update'])
        ->middleware('user.authorize:domain_edit');

    Route::delete('/domains/{domain_uuid}', [DomainController::class, 'destroy'])
        ->middleware('user.authorize:domain_delete');

    /*
    |--------------------------------------------------------------------------
    | Extensions (domain-scoped)
    |--------------------------------------------------------------------------
    */
    Route::get('/domains/{domain_uuid}/extensions', [ExtensionController::class, 'index'])
        ->middleware('user.authorize:extension_view');

    Route::get('/domains/{domain_uuid}/extensions/{extension_uuid}', [ExtensionController::class, 'show'])
        ->middleware('user.authorize:extension_view');

    Route::get('/domains/{domain_uuid}/extension-statistics', [ExtensionStatisticController::class, 'index'])
        ->middleware('user.authorize:xml_cdr_view');

    Route::post('/domains/{domain_uuid}/extensions', [ExtensionController::class, 'store'])
        ->middleware('user.authorize:extension_add');

    Route::patch('/domains/{domain_uuid}/extensions/{extension_uuid}', [ExtensionController::class, 'update'])
        ->middleware('user.authorize:extension_edit');

    Route::get('/domains/{domain_uuid}/extensions/{extension_uuid}/credentials', [ExtensionController::class, 'credentials'])
        ->middleware('user.authorize:extension_view');

    Route::delete('/domains/{domain_uuid}/extensions/{extension_uuid}', [ExtensionController::class, 'destroy'])
        ->middleware('user.authorize:extension_delete');

    /*
    |--------------------------------------------------------------------------
    | Voicemails (domain-scoped)
    |--------------------------------------------------------------------------
    */
    Route::get('/domains/{domain_uuid}/voicemails', [VoicemailController::class, 'index'])
        ->middleware('user.authorize:voicemail_domain');

    Route::get('/domains/{domain_uuid}/voicemails/{voicemail_uuid}', [VoicemailController::class, 'show'])
        ->middleware('user.authorize:voicemail_view');

    Route::post('/domains/{domain_uuid}/voicemails', [VoicemailController::class, 'store'])
        ->middleware('user.authorize:voicemail_add');

    Route::patch('/domains/{domain_uuid}/voicemails/{voicemail_uuid}', [VoicemailController::class, 'update'])
        ->middleware('user.authorize:voicemail_edit');

    Route::delete('/domains/{domain_uuid}/voicemails/{voicemail_uuid}', [VoicemailController::class, 'destroy'])
        ->middleware('user.authorize:voicemail_delete');

    /*
    |--------------------------------------------------------------------------
    | Ring Groups (domain-scoped)
    |--------------------------------------------------------------------------
    */
    Route::get('/domains/{domain_uuid}/ring-groups', [RingGroupController::class, 'index'])
        ->middleware('user.authorize:ring_group_domain');

    Route::get('/domains/{domain_uuid}/ring-groups/{ring_group_uuid}', [RingGroupController::class, 'show'])
        ->middleware('user.authorize:ring_group_view');

    Route::post('/domains/{domain_uuid}/ring-groups', [RingGroupController::class, 'store'])
        ->middleware('user.authorize:ring_group_add');

    Route::patch('/domains/{domain_uuid}/ring-groups/{ring_group_uuid}', [RingGroupController::class, 'update'])
        ->middleware('user.authorize:ring_group_edit');

    Route::delete('/domains/{domain_uuid}/ring-groups/{ring_group_uuid}', [RingGroupController::class, 'destroy'])
        ->middleware('user.authorize:ring_group_delete');

    /*
    |--------------------------------------------------------------------------
    | Devices (domain-scoped)
    |--------------------------------------------------------------------------
    */
    Route::get('/domains/{domain_uuid}/devices', [DeviceController::class, 'index'])
        ->middleware('user.authorize:device_view');

    Route::get('/domains/{domain_uuid}/devices/{device_uuid}', [DeviceController::class, 'show'])
        ->middleware('user.authorize:device_view');

    Route::post('/domains/{domain_uuid}/devices', [DeviceController::class, 'store'])
        ->middleware('user.authorize:device_add');

    Route::patch('/domains/{domain_uuid}/devices/{device_uuid}', [DeviceController::class, 'update'])
        ->middleware('user.authorize:device_edit');

    Route::delete('/domains/{domain_uuid}/devices/{device_uuid}', [DeviceController::class, 'destroy'])
        ->middleware('user.authorize:device_delete');

    /*
    |--------------------------------------------------------------------------
    | Active Calls (domain-scoped)
    |--------------------------------------------------------------------------
    */
    Route::get('/domains/{domain_uuid}/active-calls', [ActiveCallController::class, 'index'])
        ->middleware('user.authorize:domain_view');

    Route::get('/domains/{domain_uuid}/active-calls/{call_uuid}', [ActiveCallController::class, 'show'])
        ->middleware('user.authorize:domain_view');

    Route::delete('/domains/{domain_uuid}/active-calls/{call_uuid}', [ActiveCallController::class, 'destroy'])
        ->middleware('user.authorize:domain_view');

    /*
    |--------------------------------------------------------------------------
    | Registrations (domain-scoped)
    |--------------------------------------------------------------------------
    */
    Route::get('/domains/{domain_uuid}/registrations', [RegistrationController::class, 'index'])
        ->middleware('user.authorize:domain_view');

    Route::get('/domains/{domain_uuid}/registrations/{call_id}', [RegistrationController::class, 'show'])
        ->middleware('user.authorize:domain_view');

    Route::delete('/domains/{domain_uuid}/registrations/{call_id}', [RegistrationController::class, 'destroy'])
        ->middleware('user.authorize:domain_view');

    Route::post('/domains/{domain_uuid}/registrations/{call_id}/restart', [RegistrationController::class, 'restart'])
        ->middleware('user.authorize:domain_view');

    Route::post('/domains/{domain_uuid}/registrations/{call_id}/sync', [RegistrationController::class, 'sync'])
        ->middleware('user.authorize:domain_view');

    /*
    |--------------------------------------------------------------------------
    | Phone Numbers (domain-scoped)
    |--------------------------------------------------------------------------
    */
    Route::get('/domains/{domain_uuid}/phone-numbers', [PhoneNumberController::class, 'index'])
        ->middleware('user.authorize:ring_group_domain');

    Route::get('/domains/{domain_uuid}/phone-numbers/{destination_uuid}', [PhoneNumberController::class, 'show'])
        ->middleware('user.authorize:ring_group_view');

    Route::post('/domains/{domain_uuid}/phone-numbers', [PhoneNumberController::class, 'store'])
        ->middleware('user.authorize:ring_group_add');

    Route::patch('/domains/{domain_uuid}/phone-numbers/{destination_uuid}', [PhoneNumberController::class, 'update'])
        ->middleware('user.authorize:ring_group_edit');

    Route::delete('/domains/{domain_uuid}/phone-numbers/{destination_uuid}', [PhoneNumberController::class, 'destroy'])
        ->middleware('user.authorize:ring_group_delete');

    /*
    |--------------------------------------------------------------------------
    | CDRs (domain-scoped)
    |--------------------------------------------------------------------------
    */
    Route::get('/domains/{domain_uuid}/cdrs', [CdrController::class, 'index'])
        ->middleware('user.authorize:xml_cdr_view');

    Route::get('/domains/{domain_uuid}/cdrs/{xml_cdr_uuid}', [CdrController::class, 'show'])
        ->middleware('user.authorize:xml_cdr_view');

    Route::get('/domains/{domain_uuid}/cdrs/{xml_cdr_uuid}/recording-url', [CdrController::class, 'recordingUrl'])
        ->middleware('user.authorize:xml_cdr_view');

    // --- CallPulse additions ---

    /*
    |--------------------------------------------------------------------------
    | Gateways (domain-scoped)
    |--------------------------------------------------------------------------
    */
    Route::post('/domains/{domain_uuid}/gateways', [GatewayController::class, 'store'])
        ->middleware('user.authorize:gateway_add');

    Route::get('/domains/{domain_uuid}/gateways/{gateway_uuid}', [GatewayController::class, 'show'])
        ->middleware('user.authorize:gateway_view');

    Route::patch('/domains/{domain_uuid}/gateways/{gateway_uuid}', [GatewayController::class, 'update'])
        ->middleware('user.authorize:gateway_edit');

    Route::delete('/domains/{domain_uuid}/gateways/{gateway_uuid}', [GatewayController::class, 'destroy'])
        ->middleware('user.authorize:gateway_delete');

    Route::post('/domains/{domain_uuid}/gateways/{gateway_uuid}/restart', [GatewayController::class, 'restart'])
        ->middleware('user.authorize:gateway_edit');


    /*
    |--------------------------------------------------------------------------
    | Access Controls (global to the instance: v_access_controls has no domain)
    |--------------------------------------------------------------------------
    |
    | /access-controls/reload is a literal segment declared BEFORE
    | /access-controls/{access_control_uuid} so it can never be read as a UUID.
    |
    */
    Route::get('/access-controls', [AccessControlController::class, 'index'])
        ->middleware('user.authorize:access_control_view');

    Route::post('/access-controls/reload', [AccessControlController::class, 'reload'])
        ->middleware('user.authorize:access_control_view');

    Route::get('/access-controls/{access_control_uuid}', [AccessControlController::class, 'show'])
        ->middleware('user.authorize:access_control_view');

    Route::patch('/access-controls/{access_control_uuid}', [AccessControlController::class, 'update'])
        ->middleware('user.authorize:access_control_edit');

    /*
    |--------------------------------------------------------------------------
    | Dialplans (domain-scoped)
    |--------------------------------------------------------------------------
    |
    | /dialplans/reload is a literal segment declared BEFORE
    | /dialplans/{dialplan_uuid} so it can never be read as a UUID.
    |
    */
    Route::get('/domains/{domain_uuid}/dialplans', [DialplanController::class, 'index'])
        ->middleware('user.authorize:dialplan_view');

    Route::post('/domains/{domain_uuid}/dialplans', [DialplanController::class, 'store'])
        ->middleware('user.authorize:dialplan_add');

    Route::post('/domains/{domain_uuid}/dialplans/reload', [DialplanController::class, 'reload'])
        ->middleware('user.authorize:dialplan_view');

    Route::get('/domains/{domain_uuid}/dialplans/{dialplan_uuid}', [DialplanController::class, 'show'])
        ->middleware('user.authorize:dialplan_view');

    Route::patch('/domains/{domain_uuid}/dialplans/{dialplan_uuid}', [DialplanController::class, 'update'])
        ->middleware('user.authorize:dialplan_edit');

    Route::delete('/domains/{domain_uuid}/dialplans/{dialplan_uuid}', [DialplanController::class, 'destroy'])
        ->middleware('user.authorize:dialplan_delete');

    // --- fin CallPulse additions ---
});
