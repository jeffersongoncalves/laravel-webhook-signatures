<?php

use Illuminate\Http\Request;
use JeffersonGoncalves\WebhookSignatures\Verifiers\SendGridSignatureVerifier;

function sendgridKeyPair(): array
{
    $pkey = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_EC,
        'curve_name' => 'prime256v1',
    ]);

    $details = openssl_pkey_get_details($pkey);

    return [$pkey, $details['key']];
}

function sendgridRequest(string $timestamp, string $signature, string $payload): Request
{
    return Request::create('/webhook', 'POST', [], [], [], [
        'HTTP_X_TWILIO_EMAIL_EVENT_WEBHOOK_SIGNATURE' => $signature,
        'HTTP_X_TWILIO_EMAIL_EVENT_WEBHOOK_TIMESTAMP' => $timestamp,
        'CONTENT_TYPE' => 'application/json',
    ], $payload);
}

beforeEach(function () {
    [$this->privateKey, $this->publicKey] = sendgridKeyPair();
    $this->payload = '[{"event":"delivered"}]';
});

it('accepts a valid SendGrid ECDSA signature', function () {
    $timestamp = (string) time();
    openssl_sign($timestamp.$this->payload, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);

    $verifier = new SendGridSignatureVerifier;

    expect($verifier->verify(sendgridRequest($timestamp, base64_encode($signature), $this->payload), $this->publicKey))->toBeTrue();
});

it('rejects a SendGrid signature over a tampered payload', function () {
    $timestamp = (string) time();
    openssl_sign($timestamp.$this->payload, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);

    $verifier = new SendGridSignatureVerifier;

    expect($verifier->verify(sendgridRequest($timestamp, base64_encode($signature), '[{"event":"tampered"}]'), $this->publicKey))->toBeFalse();
});

it('rejects a SendGrid request with missing headers', function () {
    $request = Request::create('/webhook', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], $this->payload);

    $verifier = new SendGridSignatureVerifier;

    expect($verifier->verify($request, $this->publicKey))->toBeFalse();
});

it('rejects SendGrid verification when the verification key is absent', function () {
    $timestamp = (string) time();
    openssl_sign($timestamp.$this->payload, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);

    $verifier = new SendGridSignatureVerifier;

    expect($verifier->verify(sendgridRequest($timestamp, base64_encode($signature), $this->payload), ''))->toBeFalse();
});
