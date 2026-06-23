<?php

use Illuminate\Http\Request;
use JeffersonGoncalves\WebhookSignatures\Verifiers\GithubSignatureVerifier;

function githubRequest(string $payload, array $headers = []): Request
{
    $request = Request::create('/webhook', 'POST', [], [], [], [], $payload);

    foreach ($headers as $name => $value) {
        $request->headers->set($name, $value);
    }

    return $request;
}

function githubSign(string $payload, string $secret): string
{
    return 'sha256='.hash_hmac('sha256', $payload, $secret);
}

it('accepts a valid GitHub signature', function () {
    $secret = 'github-webhook-secret';
    $payload = '{"action":"opened"}';

    $request = githubRequest($payload, [
        'X-Hub-Signature-256' => githubSign($payload, $secret),
    ]);

    $verifier = new GithubSignatureVerifier;

    expect($verifier->verify($request, $secret))->toBeTrue();
});

it('rejects an invalid GitHub signature', function () {
    $secret = 'github-webhook-secret';
    $payload = '{"action":"opened"}';

    $request = githubRequest($payload, [
        'X-Hub-Signature-256' => 'sha256=deadbeef',
    ]);

    $verifier = new GithubSignatureVerifier;

    expect($verifier->verify($request, $secret))->toBeFalse();
});

it('rejects a GitHub signature computed over a different payload', function () {
    $secret = 'github-webhook-secret';

    $request = githubRequest('{"action":"closed"}', [
        'X-Hub-Signature-256' => githubSign('{"action":"opened"}', $secret),
    ]);

    $verifier = new GithubSignatureVerifier;

    expect($verifier->verify($request, $secret))->toBeFalse();
});

it('rejects a GitHub request with no signature header', function () {
    $secret = 'github-webhook-secret';

    $request = githubRequest('{"action":"opened"}');

    $verifier = new GithubSignatureVerifier;

    expect($verifier->verify($request, $secret))->toBeFalse();
});

it('rejects a GitHub signature without the sha256 prefix', function () {
    $secret = 'github-webhook-secret';
    $payload = '{"action":"opened"}';

    $request = githubRequest($payload, [
        'X-Hub-Signature-256' => hash_hmac('sha256', $payload, $secret),
    ]);

    $verifier = new GithubSignatureVerifier;

    expect($verifier->verify($request, $secret))->toBeFalse();
});

it('accepts a valid legacy GitHub sha1 signature', function () {
    $secret = 'github-webhook-secret';
    $payload = '{"action":"opened"}';

    $request = githubRequest($payload, [
        'X-Hub-Signature' => 'sha1='.hash_hmac('sha1', $payload, $secret),
    ]);

    $verifier = new GithubSignatureVerifier;

    expect($verifier->verify($request, $secret))->toBeTrue();
});

it('rejects GitHub verification when the secret is absent', function () {
    $payload = '{"action":"opened"}';

    $request = githubRequest($payload, [
        'X-Hub-Signature-256' => githubSign($payload, ''),
    ]);

    $verifier = new GithubSignatureVerifier;

    expect($verifier->verify($request, ''))->toBeFalse();
});
