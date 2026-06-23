<?php

use Illuminate\Http\Request;
use JeffersonGoncalves\WebhookSignatures\Verifiers\PostmarkSignatureVerifier;

function postmarkRequest(?string $user, ?string $pass): Request
{
    $server = [];

    if ($user !== null) {
        $server['PHP_AUTH_USER'] = $user;
    }

    if ($pass !== null) {
        $server['PHP_AUTH_PW'] = $pass;
    }

    return Request::create('/webhook', 'POST', [], [], [], $server);
}

it('accepts valid Postmark basic-auth credentials', function () {
    $verifier = new PostmarkSignatureVerifier;

    expect($verifier->verify(postmarkRequest('hook', 's3cret'), 'hook:s3cret'))->toBeTrue();
});

it('rejects invalid Postmark credentials', function () {
    $verifier = new PostmarkSignatureVerifier;

    expect($verifier->verify(postmarkRequest('hook', 'wrong'), 'hook:s3cret'))->toBeFalse();
});

it('rejects a Postmark request with no credentials', function () {
    $verifier = new PostmarkSignatureVerifier;

    expect($verifier->verify(postmarkRequest(null, null), 'hook:s3cret'))->toBeFalse();
});

it('rejects Postmark verification when the secret is absent', function () {
    $verifier = new PostmarkSignatureVerifier;

    expect($verifier->verify(postmarkRequest('hook', 's3cret'), ''))->toBeFalse();
});

it('rejects a malformed Postmark secret without a colon', function () {
    $verifier = new PostmarkSignatureVerifier;

    expect($verifier->verify(postmarkRequest('hook', 's3cret'), 'hooks3cret'))->toBeFalse();
});
