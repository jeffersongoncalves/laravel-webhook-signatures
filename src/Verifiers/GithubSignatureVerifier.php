<?php

namespace JeffersonGoncalves\WebhookSignatures\Verifiers;

use Illuminate\Http\Request;
use JeffersonGoncalves\WebhookSignatures\Contracts\SignatureVerifier;

class GithubSignatureVerifier implements SignatureVerifier
{
    public function __construct(protected int $tolerance = 300) {}

    /**
     * GitHub signs the raw request body with the webhook secret using
     * HMAC-SHA256 and exposes it in the `X-Hub-Signature-256` header as
     * `sha256=<hex>`. The legacy `X-Hub-Signature` header (`sha1=<hex>`) is
     * accepted as a fallback, but SHA-256 is always preferred.
     *
     * The secret is the webhook secret configured in the GitHub repository,
     * organization or app settings.
     */
    public function verify(Request $request, string $secret): bool
    {
        if ($secret === '') {
            return false;
        }

        $signature = $request->header('X-Hub-Signature-256');

        if (is_string($signature) && $signature !== '') {
            return $this->matches('sha256', $signature, $request->getContent(), $secret);
        }

        $legacy = $request->header('X-Hub-Signature');

        if (is_string($legacy) && $legacy !== '') {
            return $this->matches('sha1', $legacy, $request->getContent(), $secret);
        }

        // No usable signature header: reject (fail closed).
        return false;
    }

    /**
     * Compare a `algo=<hex>` header against the HMAC of the raw body.
     */
    protected function matches(string $algo, string $signature, string $payload, string $secret): bool
    {
        $prefix = $algo.'=';

        if (! str_starts_with($signature, $prefix)) {
            return false;
        }

        $expected = $prefix.hash_hmac($algo, $payload, $secret);

        return hash_equals($expected, $signature);
    }
}
