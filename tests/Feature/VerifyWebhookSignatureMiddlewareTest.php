<?php

use Illuminate\Support\Facades\Route;

beforeEach(function () {
    Route::post('/test-webhook/{provider}', fn () => response('ok'))
        ->middleware('webhook.signature:mailgun');
});

it('passes the request through when the signature is valid', function () {
    $key = 'middleware-mailgun-key';
    config()->set('webhook-signatures.providers.mailgun.secret', $key);

    $timestamp = (string) time();
    $token = 'token';
    $signature = hash_hmac('sha256', $timestamp.$token, $key);

    $this->post('/test-webhook/mailgun', [
        'timestamp' => $timestamp,
        'token' => $token,
        'signature' => $signature,
    ])->assertOk();
});

it('aborts with 403 when the signature is invalid', function () {
    config()->set('webhook-signatures.providers.mailgun.secret', 'middleware-mailgun-key');

    $this->post('/test-webhook/mailgun', [
        'timestamp' => (string) time(),
        'token' => 'token',
        'signature' => 'invalid',
    ])->assertForbidden();
});

it('aborts with 403 when no secret is configured', function () {
    config()->set('webhook-signatures.providers.mailgun.secret', null);

    $this->post('/test-webhook/mailgun', [
        'timestamp' => (string) time(),
        'token' => 'token',
        'signature' => 'whatever',
    ])->assertForbidden();
});
