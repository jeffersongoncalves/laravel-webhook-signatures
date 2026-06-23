<?php

use Illuminate\Http\Request;
use JeffersonGoncalves\WebhookSignatures\Verifiers\MailgunSignatureVerifier;

function mailgunRequest(string $timestamp, string $token, string $signature): Request
{
    return Request::create('/webhook', 'POST', [
        'timestamp' => $timestamp,
        'token' => $token,
        'signature' => $signature,
    ]);
}

function mailgunSign(string $timestamp, string $token, string $key): string
{
    return hash_hmac('sha256', $timestamp.$token, $key);
}

it('accepts a valid Mailgun signature', function () {
    $key = 'mailgun-signing-key';
    $timestamp = (string) time();
    $token = 'a-random-token';
    $signature = mailgunSign($timestamp, $token, $key);

    $verifier = new MailgunSignatureVerifier;

    expect($verifier->verify(mailgunRequest($timestamp, $token, $signature), $key))->toBeTrue();
});

it('rejects an invalid Mailgun signature', function () {
    $key = 'mailgun-signing-key';
    $timestamp = (string) time();

    $verifier = new MailgunSignatureVerifier;

    expect($verifier->verify(mailgunRequest($timestamp, 'token', 'deadbeef'), $key))->toBeFalse();
});

it('rejects a Mailgun request with missing fields', function () {
    $key = 'mailgun-signing-key';
    $request = Request::create('/webhook', 'POST', []);

    $verifier = new MailgunSignatureVerifier;

    expect($verifier->verify($request, $key))->toBeFalse();
});

it('rejects a Mailgun request with a stale timestamp', function () {
    $key = 'mailgun-signing-key';
    $timestamp = (string) (time() - 1000);
    $token = 'a-random-token';
    $signature = mailgunSign($timestamp, $token, $key);

    $verifier = new MailgunSignatureVerifier;

    expect($verifier->verify(mailgunRequest($timestamp, $token, $signature), $key))->toBeFalse();
});

it('rejects Mailgun verification when the secret is absent', function () {
    $timestamp = (string) time();
    $token = 'token';
    $signature = mailgunSign($timestamp, $token, '');

    $verifier = new MailgunSignatureVerifier;

    expect($verifier->verify(mailgunRequest($timestamp, $token, $signature), ''))->toBeFalse();
});
