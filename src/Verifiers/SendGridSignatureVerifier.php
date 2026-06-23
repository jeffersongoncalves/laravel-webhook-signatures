<?php

namespace JeffersonGoncalves\WebhookSignatures\Verifiers;

use Illuminate\Http\Request;
use JeffersonGoncalves\WebhookSignatures\Contracts\SignatureVerifier;

class SendGridSignatureVerifier implements SignatureVerifier
{
    public function __construct(protected int $tolerance = 300) {}

    /**
     * SendGrid (Twilio) Event Webhook signs the concatenation of the timestamp
     * header and the raw request body using ECDSA (P-256) over SHA-256.
     *
     * The secret is the ECDSA "verification key" exposed in the SendGrid Event
     * Webhook settings. It may be a bare base64 DER key or a full PEM block.
     */
    public function verify(Request $request, string $secret): bool
    {
        if ($secret === '') {
            return false;
        }

        $signature = $request->header('X-Twilio-Email-Event-Webhook-Signature');
        $timestamp = $request->header('X-Twilio-Email-Event-Webhook-Timestamp');

        // Any missing field means we cannot verify: reject (fail closed).
        if (! $signature || ! $timestamp) {
            return false;
        }

        $signedPayload = $timestamp.$request->getContent();

        $publicKey = openssl_pkey_get_public($this->normalizePublicKey($secret));

        if ($publicKey === false) {
            return false;
        }

        $decodedSignature = base64_decode($signature, true);

        if ($decodedSignature === false || $decodedSignature === '') {
            return false;
        }

        return openssl_verify($signedPayload, $decodedSignature, $publicKey, OPENSSL_ALGO_SHA256) === 1;
    }

    /**
     * Normalize the verification key into PEM. SendGrid exposes it as a bare
     * base64-encoded DER public key, but a full PEM block is also accepted.
     */
    protected function normalizePublicKey(string $key): string
    {
        $key = trim($key);

        if (str_contains($key, '-----BEGIN')) {
            return $key;
        }

        return "-----BEGIN PUBLIC KEY-----\n".chunk_split($key, 64, "\n").'-----END PUBLIC KEY-----'."\n";
    }
}
