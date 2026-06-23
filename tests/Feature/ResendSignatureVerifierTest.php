<?php

use Illuminate\Http\Request;
use JeffersonGoncalves\WebhookSignatures\Verifiers\ResendSignatureVerifier;

function resendRequest(string $id, string $timestamp, string $signature, string $payload): Request
{
    return Request::create('/webhook', 'POST', [], [], [], [
        'HTTP_SVIX_ID' => $id,
        'HTTP_SVIX_TIMESTAMP' => $timestamp,
        'HTTP_SVIX_SIGNATURE' => $signature,
        'CONTENT_TYPE' => 'application/json',
    ], $payload);
}

function resendSign(string $id, string $timestamp, string $payload, string $secret): string
{
    $key = str_starts_with($secret, 'whsec_') ? substr($secret, 6) : $secret;
    $bytes = base64_decode($key, true);

    return 'v1,'.base64_encode(hash_hmac('sha256', "{$id}.{$timestamp}.{$payload}", $bytes, true));
}

beforeEach(function () {
    $this->secret = 'whsec_'.base64_encode(random_bytes(24));
    $this->payload = '{"type":"email.delivered"}';
});

it('accepts a valid Resend (Svix) signature', function () {
    $id = 'msg_123';
    $timestamp = (string) time();
    $signature = resendSign($id, $timestamp, $this->payload, $this->secret);

    $verifier = new ResendSignatureVerifier;

    expect($verifier->verify(resendRequest($id, $timestamp, $signature, $this->payload), $this->secret))->toBeTrue();
});

it('rejects an invalid Resend signature', function () {
    $id = 'msg_123';
    $timestamp = (string) time();

    $verifier = new ResendSignatureVerifier;

    expect($verifier->verify(resendRequest($id, $timestamp, 'v1,'.base64_encode('nope'), $this->payload), $this->secret))->toBeFalse();
});

it('rejects a Resend request with missing Svix headers', function () {
    $request = Request::create('/webhook', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], $this->payload);

    $verifier = new ResendSignatureVerifier;

    expect($verifier->verify($request, $this->secret))->toBeFalse();
});

it('rejects a Resend request with a stale timestamp', function () {
    $id = 'msg_123';
    $timestamp = (string) (time() - 1000);
    $signature = resendSign($id, $timestamp, $this->payload, $this->secret);

    $verifier = new ResendSignatureVerifier;

    expect($verifier->verify(resendRequest($id, $timestamp, $signature, $this->payload), $this->secret))->toBeFalse();
});

it('rejects Resend verification when the secret is absent', function () {
    $id = 'msg_123';
    $timestamp = (string) time();
    $signature = resendSign($id, $timestamp, $this->payload, $this->secret);

    $verifier = new ResendSignatureVerifier;

    expect($verifier->verify(resendRequest($id, $timestamp, $signature, $this->payload), ''))->toBeFalse();
});
