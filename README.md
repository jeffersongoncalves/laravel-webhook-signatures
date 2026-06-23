<div class="filament-hidden">

![Laravel Webhook Signatures](https://raw.githubusercontent.com/jeffersongoncalves/laravel-webhook-signatures/main/art/jeffersongoncalves-laravel-webhook-signatures.png)

</div>

# Laravel Webhook Signatures

[![Latest Version on Packagist](https://img.shields.io/packagist/v/jeffersongoncalves/laravel-webhook-signatures.svg?style=flat-square)](https://packagist.org/packages/jeffersongoncalves/laravel-webhook-signatures)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/jeffersongoncalves/laravel-webhook-signatures/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/jeffersongoncalves/laravel-webhook-signatures/actions?query=workflow%3Arun-tests+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/jeffersongoncalves/laravel-webhook-signatures.svg?style=flat-square)](https://packagist.org/packages/jeffersongoncalves/laravel-webhook-signatures)

Centralized, **fail-closed** webhook signature verification for the major email and service providers (Mailgun, SendGrid, Postmark, Resend/Svix, AWS SNS/SES and GitHub) in Laravel applications.

This package was born out of the need to eliminate the **duplicated and buggy** signature-verification logic scattered across several packages (`laravel-help-desk`, `laravel-service-desk`, `laravel-mail`, `laravel-satis`). Instead of every package re-implementing — and getting wrong — the same verification, they all depend on a single, audited and tested source of truth.

## Security principles

Every verifier follows the **fail-closed** principle:

- Missing or empty secret → verification **fails** (returns `false`). There is never a fail-open path.
- Secret material is always compared with `hash_equals` (HMAC/basic-auth) or `openssl_verify` (ECDSA/RSA) — constant time, no timing leaks.
- Timestamp validation (replay protection) wherever the provider exposes a signed timestamp.
- Any missing or malformed header, field or certificate results in rejection.

## Compatibility

| Item                 | Supported versions |
|----------------------|--------------------|
| PHP                  | 8.2, 8.3, 8.4      |
| Laravel              | 11.x, 12.x, 13.x   |
| Orchestra Testbench  | 9.x, 10.x, 11.x    |
| Required extension   | `ext-openssl`      |

## Installation

```bash
composer require jeffersongoncalves/laravel-webhook-signatures
```

Publish the configuration file (optional):

```bash
php artisan vendor:publish --tag="webhook-signatures-config"
```

## Configuration

The meaning of the "secret" varies per provider. Define the values via `.env`:

```dotenv
WEBHOOK_MAILGUN_SIGNING_KEY=...           # Mailgun signing key
WEBHOOK_SENDGRID_VERIFICATION_KEY=...     # SendGrid ECDSA verification key
WEBHOOK_POSTMARK_BASIC_AUTH=user:password # Postmark Basic Auth credentials
WEBHOOK_RESEND_SECRET=whsec_...           # Resend Svix secret
WEBHOOK_SNS_TOPIC_ARN=arn:aws:sns:...     # expected TopicArn (SES via SNS)
GITHUB_WEBHOOK_SECRET=...                  # GitHub webhook secret (HMAC-SHA256)
```

| Provider   | Scheme                                                                | Secret meaning                                  |
|------------|----------------------------------------------------------------------|-------------------------------------------------|
| `mailgun`  | HMAC-SHA256 over `timestamp + token`                                  | webhook signing key                             |
| `sendgrid` | ECDSA (P-256/SHA-256) over `timestamp + body`, Twilio headers         | ECDSA verification key (PEM or base64 DER)      |
| `postmark` | Basic Auth (`hash_equals`)                                            | credentials in `user:password` format           |
| `resend`   | HMAC-SHA256 base64 over `id.timestamp.payload`, `svix-*` headers      | Svix secret (with or without `whsec_` prefix)   |
| `sns`      | X.509 certificate + `openssl_verify` over canonical string           | expected TopicArn (message pinned to the topic) |
| `github`   | HMAC-SHA256 over raw body, `X-Hub-Signature-256` header (`sha256=<hex>`); legacy `X-Hub-Signature` (sha1) fallback | GitHub webhook secret |

The timestamp tolerance (in seconds) is configurable:

```php
// config/webhook-signatures.php
'tolerance' => [
    'default' => 300,   // Mailgun, Resend, SendGrid
    'sns'     => 3600,  // SNS may redeliver messages later
],
```

## Usage

### 1. Middleware (recommended)

The package registers the `webhook.signature` middleware alias, parameterized by provider. It aborts with `403` when the signature cannot be verified:

```php
use Illuminate\Support\Facades\Route;

Route::post('/webhooks/mailgun', InboundController::class)
    ->middleware('webhook.signature:mailgun');

Route::post('/webhooks/resend', ResendController::class)
    ->middleware('webhook.signature:resend');
```

The secret is read automatically from `config('webhook-signatures.providers.{provider}.secret')`.

### 2. Direct usage via Facade

```php
use JeffersonGoncalves\WebhookSignatures\Facades\WebhookSignatures;

public function handle(Request $request)
{
    if (! WebhookSignatures::verify('sendgrid', $request)) {
        abort(403);
    }

    // ... process the event
}
```

You can also pass the secret explicitly (bypassing the config):

```php
WebhookSignatures::verify('mailgun', $request, $myKey);
```

### 3. Using a standalone verifier

Each verifier implements the `SignatureVerifier` interface:

```php
use JeffersonGoncalves\WebhookSignatures\Verifiers\ResendSignatureVerifier;

$verifier = new ResendSignatureVerifier(tolerance: 300);

$valid = $verifier->verify($request, $secret); // bool
```

### 4. Registering a custom verifier

```php
use JeffersonGoncalves\WebhookSignatures\Facades\WebhookSignatures;

WebhookSignatures::extend('my-provider', MyVerifier::class);
```

`MyVerifier` must implement `JeffersonGoncalves\WebhookSignatures\Contracts\SignatureVerifier` and accept `int $tolerance` in the constructor.

## What each verifier does

- **Mailgun** — computes `hash_hmac('sha256', timestamp.token, $key)` and compares it with the received signature via `hash_equals`. Accepts the fields at the top level (inbound routes) or nested under `signature` (event webhooks). Rejects timestamps outside the tolerance window.
- **SendGrid** — verifies the ECDSA signature (P-256/SHA-256) over `timestamp + raw body`, reading the `X-Twilio-Email-Event-Webhook-Signature` and `-Timestamp` headers. Normalizes the verification key (PEM or base64 DER) and uses `openssl_verify`.
- **Postmark** — Postmark does not sign the payload; authentication is via Basic Auth. Compares user and password in constant time (`hash_equals`).
- **Resend (Svix)** — reconstructs `id.timestamp.payload`, computes HMAC-SHA256 with the decoded key (`whsec_` prefix stripped), base64-encodes it and compares against each `version,signature` pair from the `svix-signature` header. Rejects timestamps outside the tolerance.
- **GitHub** — computes `hash_hmac('sha256', raw body, $secret)` and compares it, via `hash_equals`, against the `X-Hub-Signature-256` header (`sha256=<hex>` format). As a fallback it accepts the legacy `X-Hub-Signature` header (`sha1=<hex>`), but always prioritizes SHA-256. A missing or malformed header results in rejection.
- **AWS SNS/SES** — pins the message to the expected `TopicArn`, validates that the `SigningCertURL` points to a legitimate AWS host (`sns.<region>.amazonaws.com`), reconstructs the canonical string documented by SNS, downloads the X.509 certificate and verifies the signature with `openssl_verify` (SHA1 for `SignatureVersion 1`, SHA256 for `2`). Rejects messages that are too old.

## Testing

```bash
composer test       # Pest
composer analyse    # PHPStan (level 5, Larastan)
composer format     # Laravel Pint
```

Each verifier has tests covering: valid signature accepted, invalid signature rejected, request without credentials rejected and (where applicable) old timestamp rejected. All cryptographic keys and fixtures are generated inside the tests.

## Migration (consumer packages)

This package consolidates signature verification that used to be duplicated (and divergent) across:

- `laravel-help-desk` → `src/Http/Middleware/Verify{Mailgun,SendGrid,Postmark,Resend}Signature.php`
- `laravel-service-desk` → `src/Http/Middleware/Verify{Mailgun,SendGrid,Postmark,Resend}Signature.php`
- `laravel-mail` → `src/Webhooks/{SendGrid,Ses,...}WebhookHandler::validate()`
- `laravel-satis` → its own GitHub webhook verification

Real problems found in the duplication:

- **Fail-open**: `help-desk` returned `$next($request)` when the key was not configured — i.e. it accepted any request. Here the behavior is always fail-closed.
- **Non-constant comparison**: `service-desk` (SendGrid/Postmark) used `!==` instead of `hash_equals`, exposing it to timing attacks.
- **No replay protection**: some Mailgun implementations did not validate timestamp recency.

Suggested migration steps (to apply per package):

1. Add `jeffersongoncalves/laravel-webhook-signatures` to the package `composer.json`.
2. Replace the package's own middlewares with the `webhook.signature:{provider}` alias, **or** call `WebhookSignatures::verify(...)` inside the existing handler.
3. Map the current secrets (e.g. `help-desk.email.inbound.mailgun.signing_key`) to `config('webhook-signatures.providers.mailgun.secret')` — or pass the secret explicitly as the third argument of `verify()`, preserving the package config.
4. Remove the duplicated `Verify*Signature.php` files and their redundant tests.
5. Run the consumer package test suite.

## License

MIT. See [LICENSE.md](LICENSE.md).
