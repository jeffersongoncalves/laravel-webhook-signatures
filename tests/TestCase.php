<?php

namespace JeffersonGoncalves\WebhookSignatures\Tests;

use JeffersonGoncalves\WebhookSignatures\WebhookSignaturesServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    protected function getPackageProviders($app)
    {
        return [
            WebhookSignaturesServiceProvider::class,
        ];
    }
}
