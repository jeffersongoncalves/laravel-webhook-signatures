<?php

use Illuminate\Http\Request;
use JeffersonGoncalves\WebhookSignatures\Contracts\SignatureVerifier;
use JeffersonGoncalves\WebhookSignatures\Verifiers\MailgunSignatureVerifier;
use JeffersonGoncalves\WebhookSignatures\WebhookSignatureManager;

it('resolves verifiers for every supported provider', function () {
    $manager = new WebhookSignatureManager;

    foreach (['mailgun', 'sendgrid', 'postmark', 'resend', 'sns'] as $provider) {
        expect($manager->verifier($provider))->toBeInstanceOf(SignatureVerifier::class);
    }
});

it('throws for an unsupported provider', function () {
    $manager = new WebhookSignatureManager;

    $manager->verifier('unknown');
})->throws(InvalidArgumentException::class);

it('fails closed when no secret is configured', function () {
    config()->set('webhook-signatures.providers.mailgun.secret', null);

    $manager = new WebhookSignatureManager;
    $request = Request::create('/webhook', 'POST', [
        'timestamp' => (string) time(),
        'token' => 'token',
        'signature' => 'whatever',
    ]);

    expect($manager->verify('mailgun', $request))->toBeFalse();
});

it('verifies using the secret configured for the provider', function () {
    $key = 'configured-mailgun-key';
    config()->set('webhook-signatures.providers.mailgun.secret', $key);

    $timestamp = (string) time();
    $token = 'token';
    $signature = hash_hmac('sha256', $timestamp.$token, $key);

    $manager = new WebhookSignatureManager;
    $request = Request::create('/webhook', 'POST', [
        'timestamp' => $timestamp,
        'token' => $token,
        'signature' => $signature,
    ]);

    expect($manager->verify('mailgun', $request))->toBeTrue();
});

it('allows registering a custom verifier', function () {
    $manager = new WebhookSignatureManager;
    $manager->extend('custom', MailgunSignatureVerifier::class);

    expect($manager->verifier('custom'))->toBeInstanceOf(MailgunSignatureVerifier::class);
});
