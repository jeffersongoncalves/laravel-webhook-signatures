<?php

namespace JeffersonGoncalves\WebhookSignatures\Verifiers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use JeffersonGoncalves\WebhookSignatures\Contracts\SignatureVerifier;

class SnsSignatureVerifier implements SignatureVerifier
{
    public function __construct(protected int $tolerance = 3600) {}

    /**
     * AWS SNS (used by SES event notifications) signs a canonical string built
     * from the message fields, using the private key behind the X.509
     * certificate referenced by `SigningCertURL`. Verification downloads that
     * certificate and checks the signature with openssl_verify.
     *
     * The secret is the expected `TopicArn`: the message is pinned to a single
     * topic, so notifications from any other topic are rejected.
     *
     * @param  string  $secret  the expected SNS TopicArn
     */
    public function verify(Request $request, string $secret): bool
    {
        if ($secret === '') {
            return false;
        }

        $payload = $this->payload($request);

        if ($payload === null) {
            return false;
        }

        // All fields required to reconstruct and verify the signature must be
        // present non-empty strings; a forged POST omitting any of them fails.
        foreach (['Type', 'Signature', 'SignatureVersion', 'SigningCertURL', 'MessageId', 'TopicArn', 'Timestamp'] as $field) {
            if (! isset($payload[$field]) || ! is_string($payload[$field]) || $payload[$field] === '') {
                return false;
            }
        }

        // Pin the message to the configured topic.
        if (! hash_equals($secret, $payload['TopicArn'])) {
            return false;
        }

        // Reject stale messages (AWS recommends rejecting messages older than 1h).
        $timestamp = strtotime($payload['Timestamp']);

        if ($timestamp === false || abs(time() - $timestamp) > $this->tolerance) {
            return false;
        }

        if (! $this->isValidCertUrl($payload['SigningCertURL'])) {
            return false;
        }

        $canonical = $this->canonicalMessage($payload);

        if ($canonical === null) {
            return false;
        }

        $signature = base64_decode($payload['Signature'], true);

        if ($signature === false || $signature === '') {
            return false;
        }

        // SignatureVersion 1 uses SHA1, version 2 uses SHA256.
        $algorithm = $payload['SignatureVersion'] === '2' ? OPENSSL_ALGO_SHA256 : OPENSSL_ALGO_SHA1;

        $certificate = rescue(fn () => (string) Http::get($payload['SigningCertURL'])->body(), '', false);

        if ($certificate === '') {
            return false;
        }

        $publicKey = openssl_pkey_get_public($certificate);

        if ($publicKey === false) {
            return false;
        }

        return openssl_verify($canonical, $signature, $publicKey, $algorithm) === 1;
    }

    /**
     * Decode the SNS message body (SNS posts JSON, often with a text/plain
     * content type, so parse the raw content first).
     *
     * @return array<string, mixed>|null
     */
    protected function payload(Request $request): ?array
    {
        $content = $request->getContent();

        if ($content !== '') {
            $decoded = json_decode($content, true);

            if (is_array($decoded)) {
                /** @var array<string, mixed> $decoded */
                return $decoded;
            }
        }

        $all = $request->all();

        return $all === [] ? null : $all;
    }

    /**
     * Ensure the SigningCertURL points to a legitimate AWS SNS endpoint over
     * HTTPS before we ever download it.
     */
    protected function isValidCertUrl(string $url): bool
    {
        $parsed = parse_url($url);

        if (! is_array($parsed) || ! isset($parsed['scheme'], $parsed['host'])) {
            return false;
        }

        if (strtolower($parsed['scheme']) !== 'https') {
            return false;
        }

        $host = strtolower($parsed['host']);

        // Host must be sns.<region>.amazonaws.com (or the China partition).
        return (bool) preg_match('/^sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$/', $host);
    }

    /**
     * Build the canonical string SNS signs, field by field in the documented order.
     *
     * @param  array<string, mixed>  $payload
     */
    protected function canonicalMessage(array $payload): ?string
    {
        $type = $payload['Type'];

        $fields = match ($type) {
            'Notification' => isset($payload['Subject'])
                ? ['Message', 'MessageId', 'Subject', 'Timestamp', 'TopicArn', 'Type']
                : ['Message', 'MessageId', 'Timestamp', 'TopicArn', 'Type'],
            'SubscriptionConfirmation', 'UnsubscribeConfirmation' => ['Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type'],
            default => null,
        };

        if ($fields === null) {
            return null;
        }

        $canonical = '';

        foreach ($fields as $field) {
            if (! isset($payload[$field]) || ! is_string($payload[$field])) {
                return null;
            }

            $canonical .= $field."\n".$payload[$field]."\n";
        }

        return $canonical;
    }
}
