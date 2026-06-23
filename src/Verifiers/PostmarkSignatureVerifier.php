<?php

namespace JeffersonGoncalves\WebhookSignatures\Verifiers;

use Illuminate\Http\Request;
use JeffersonGoncalves\WebhookSignatures\Contracts\SignatureVerifier;

class PostmarkSignatureVerifier implements SignatureVerifier
{
    public function __construct(protected int $tolerance = 300) {}

    /**
     * Postmark does not cryptographically sign inbound webhook payloads.
     * Authentication is performed via HTTP Basic Auth credentials embedded in
     * the configured webhook URL.
     *
     * The secret is the expected credential pair in `username:password` form.
     * Both halves are compared in constant time.
     */
    public function verify(Request $request, string $secret): bool
    {
        if ($secret === '' || ! str_contains($secret, ':')) {
            return false;
        }

        [$expectedUser, $expectedPass] = explode(':', $secret, 2);

        if ($expectedUser === '' || $expectedPass === '') {
            return false;
        }

        $user = $request->getUser();
        $pass = $request->getPassword();

        if (! is_string($user) || ! is_string($pass) || $user === '' || $pass === '') {
            return false;
        }

        $userOk = hash_equals($expectedUser, $user);
        $passOk = hash_equals($expectedPass, $pass);

        return $userOk && $passOk;
    }
}
