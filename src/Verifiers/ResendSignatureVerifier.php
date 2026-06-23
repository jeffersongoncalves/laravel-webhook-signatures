<?php

namespace JeffersonGoncalves\WebhookSignatures\Verifiers;

use Illuminate\Http\Request;
use JeffersonGoncalves\WebhookSignatures\Contracts\SignatureVerifier;

class ResendSignatureVerifier implements SignatureVerifier
{
    public function __construct(protected int $tolerance = 300) {}

    /**
     * Resend uses the Svix signing scheme. The signed content is
     * `{svix-id}.{svix-timestamp}.{payload}` hashed with HMAC-SHA256 and
     * base64-encoded. The `svix-signature` header may carry multiple
     * space-separated `version,signature` pairs.
     *
     * The secret is the Resend/Svix signing secret (with or without the
     * `whsec_` prefix); the base64 portion is decoded to raw key bytes.
     */
    public function verify(Request $request, string $secret): bool
    {
        if ($secret === '') {
            return false;
        }

        $svixId = $request->header('svix-id');
        $svixTimestamp = $request->header('svix-timestamp');
        $svixSignature = $request->header('svix-signature');

        if (! $svixId || ! $svixTimestamp || ! $svixSignature) {
            return false;
        }

        // Reject replays: the signed timestamp must be recent.
        if (abs(time() - (int) $svixTimestamp) > $this->tolerance) {
            return false;
        }

        $payload = $request->getContent();
        $signedContent = "{$svixId}.{$svixTimestamp}.{$payload}";

        $key = str_starts_with($secret, 'whsec_') ? substr($secret, 6) : $secret;
        $secretBytes = base64_decode($key, true);

        if ($secretBytes === false || $secretBytes === '') {
            return false;
        }

        $expected = base64_encode(hash_hmac('sha256', $signedContent, $secretBytes, true));

        foreach (explode(' ', $svixSignature) as $entry) {
            $parts = explode(',', $entry, 2);
            $value = $parts[1] ?? $parts[0];

            if (hash_equals($expected, $value)) {
                return true;
            }
        }

        return false;
    }
}
