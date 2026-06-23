<?php

namespace JeffersonGoncalves\WebhookSignatures\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use JeffersonGoncalves\WebhookSignatures\WebhookSignatureManager;
use Symfony\Component\HttpFoundation\Response;

class VerifyWebhookSignature
{
    public function __construct(protected WebhookSignatureManager $manager) {}

    /**
     * Thin middleware that aborts with 403 when the webhook signature for the
     * given provider cannot be verified.
     *
     * Usage: ->middleware('webhook.signature:mailgun')
     */
    public function handle(Request $request, Closure $next, string $provider): Response
    {
        if (! $this->manager->verify($provider, $request)) {
            abort(403, 'Invalid webhook signature.');
        }

        return $next($request);
    }
}
