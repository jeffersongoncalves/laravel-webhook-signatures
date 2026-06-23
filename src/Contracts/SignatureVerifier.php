<?php

namespace JeffersonGoncalves\WebhookSignatures\Contracts;

use Illuminate\Http\Request;

interface SignatureVerifier
{
    /**
     * Verify the authenticity of an incoming webhook request.
     *
     * Implementations MUST fail closed: any missing secret, missing header,
     * malformed payload or invalid signature returns false. Comparisons of
     * secret material MUST be constant-time (hash_equals / openssl_verify).
     */
    public function verify(Request $request, string $secret): bool;
}
