<?php

namespace JeffersonGoncalves\WebhookSignatures;

use Illuminate\Http\Request;
use InvalidArgumentException;
use JeffersonGoncalves\WebhookSignatures\Contracts\SignatureVerifier;
use JeffersonGoncalves\WebhookSignatures\Verifiers\MailgunSignatureVerifier;
use JeffersonGoncalves\WebhookSignatures\Verifiers\PostmarkSignatureVerifier;
use JeffersonGoncalves\WebhookSignatures\Verifiers\ResendSignatureVerifier;
use JeffersonGoncalves\WebhookSignatures\Verifiers\SendGridSignatureVerifier;
use JeffersonGoncalves\WebhookSignatures\Verifiers\SnsSignatureVerifier;

class WebhookSignatureManager
{
    /**
     * @var array<string, class-string<SignatureVerifier>>
     */
    protected array $verifiers = [
        'mailgun' => MailgunSignatureVerifier::class,
        'sendgrid' => SendGridSignatureVerifier::class,
        'postmark' => PostmarkSignatureVerifier::class,
        'resend' => ResendSignatureVerifier::class,
        'sns' => SnsSignatureVerifier::class,
    ];

    /**
     * Verify a webhook request for the given provider.
     *
     * Fails closed: a missing secret (explicit or from config) returns false
     * without invoking the verifier.
     */
    public function verify(string $provider, Request $request, ?string $secret = null): bool
    {
        $secret ??= $this->secretFor($provider);

        if ($secret === null || $secret === '') {
            return false;
        }

        return $this->verifier($provider)->verify($request, $secret);
    }

    /**
     * Resolve the verifier instance for a provider.
     */
    public function verifier(string $provider): SignatureVerifier
    {
        $provider = strtolower($provider);

        if (! isset($this->verifiers[$provider])) {
            throw new InvalidArgumentException("Unsupported webhook signature provider [{$provider}].");
        }

        $class = $this->verifiers[$provider];

        return new $class($this->toleranceFor($provider));
    }

    /**
     * Register or override a verifier for a provider.
     *
     * @param  class-string<SignatureVerifier>  $verifier
     */
    public function extend(string $provider, string $verifier): void
    {
        $this->verifiers[strtolower($provider)] = $verifier;
    }

    /**
     * @return list<string>
     */
    public function providers(): array
    {
        return array_keys($this->verifiers);
    }

    protected function secretFor(string $provider): ?string
    {
        $secret = config('webhook-signatures.providers.'.strtolower($provider).'.secret');

        return is_string($secret) && $secret !== '' ? $secret : null;
    }

    protected function toleranceFor(string $provider): int
    {
        $provider = strtolower($provider);

        $tolerance = config(
            "webhook-signatures.tolerance.{$provider}",
            config('webhook-signatures.tolerance.default', 300)
        );

        return is_numeric($tolerance) ? (int) $tolerance : 300;
    }
}
