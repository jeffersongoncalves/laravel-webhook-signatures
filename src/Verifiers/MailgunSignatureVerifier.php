<?php

namespace JeffersonGoncalves\WebhookSignatures\Verifiers;

use Illuminate\Http\Request;
use JeffersonGoncalves\WebhookSignatures\Contracts\SignatureVerifier;

class MailgunSignatureVerifier implements SignatureVerifier
{
    public function __construct(protected int $tolerance = 300) {}

    /**
     * Mailgun signs the concatenation of `timestamp` and `token` with the
     * webhook signing key using HMAC-SHA256 (hex digest).
     *
     * The secret is the Mailgun webhook signing key. The signature fields can
     * arrive either at the top level (legacy inbound routes) or nested inside a
     * `signature` object (event webhooks); both shapes are supported.
     */
    public function verify(Request $request, string $secret): bool
    {
        if ($secret === '') {
            return false;
        }

        $signature = $request->input('signature');

        if (is_array($signature)) {
            $timestamp = $signature['timestamp'] ?? null;
            $token = $signature['token'] ?? null;
            $provided = $signature['signature'] ?? null;
        } else {
            $timestamp = $request->input('timestamp');
            $token = $request->input('token');
            $provided = is_string($signature) ? $signature : null;
        }

        if (! is_scalar($timestamp) || ! is_scalar($token) || ! is_string($provided) || $provided === '') {
            return false;
        }

        // Reject replays: the signed timestamp must be recent.
        if (abs(time() - (int) $timestamp) > $this->tolerance) {
            return false;
        }

        $expected = hash_hmac('sha256', (string) $timestamp.(string) $token, $secret);

        return hash_equals($expected, $provided);
    }
}
