<?php

namespace JeffersonGoncalves\WebhookSignatures\Facades;

use Illuminate\Support\Facades\Facade;
use JeffersonGoncalves\WebhookSignatures\WebhookSignatureManager;

/**
 * @method static bool verify(string $provider, \Illuminate\Http\Request $request, ?string $secret = null)
 * @method static \JeffersonGoncalves\WebhookSignatures\Contracts\SignatureVerifier verifier(string $provider)
 * @method static void extend(string $provider, string $verifier)
 * @method static list<string> providers()
 *
 * @see WebhookSignatureManager
 */
class WebhookSignatures extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return WebhookSignatureManager::class;
    }
}
