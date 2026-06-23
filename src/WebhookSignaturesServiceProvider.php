<?php

namespace JeffersonGoncalves\WebhookSignatures;

use JeffersonGoncalves\WebhookSignatures\Http\Middleware\VerifyWebhookSignature;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class WebhookSignaturesServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package->name('laravel-webhook-signatures')
            ->hasConfigFile();
    }

    public function packageRegistered(): void
    {
        $this->app->singleton(WebhookSignatureManager::class, fn () => new WebhookSignatureManager);

        $this->app->alias(WebhookSignatureManager::class, 'webhook-signatures');
    }

    public function packageBooted(): void
    {
        $this->app['router']->aliasMiddleware('webhook.signature', VerifyWebhookSignature::class);
    }
}
