# Laravel Webhook Signatures

Verificação centralizada e *fail-closed* de assinaturas de webhooks dos principais provedores de e-mail e serviços (Mailgun, SendGrid, Postmark, Resend/Svix e AWS SNS/SES) para aplicações Laravel.

Este pacote nasceu da necessidade de eliminar a lógica de verificação de assinatura **duplicada e com bugs** espalhada por vários pacotes (`laravel-help-desk`, `laravel-service-desk`, `laravel-mail`, `laravel-satis`). Em vez de cada pacote reimplementar — e errar — a mesma verificação, todos passam a depender de uma única fonte de verdade, auditada e testada.

## Princípios de segurança

Todos os verificadores seguem o princípio **fail-closed**:

- Segredo ausente ou vazio → a verificação **falha** (retorna `false`). Nunca há *fail-open*.
- Comparações de material secreto usam sempre `hash_equals` (HMAC/basic-auth) ou `openssl_verify` (ECDSA/RSA) — tempo constante, sem vazamento por *timing*.
- Validação de timestamp (proteção contra *replay*) onde o provedor expõe um timestamp assinado.
- Qualquer cabeçalho, campo ou certificado ausente/malformado resulta em rejeição.

## Compatibilidade

| Item                | Versões suportadas        |
|---------------------|---------------------------|
| PHP                 | 8.2, 8.3, 8.4             |
| Laravel             | 11.x, 12.x, 13.x          |
| Orchestra Testbench | 9.x, 10.x, 11.x           |
| Extensão obrigatória | `ext-openssl`            |

## Instalação

```bash
composer require jeffersongoncalves/laravel-webhook-signatures
```

Publique o arquivo de configuração (opcional):

```bash
php artisan vendor:publish --tag="webhook-signatures-config"
```

## Configuração

O significado do "segredo" varia por provedor. Defina os valores via `.env`:

```dotenv
WEBHOOK_MAILGUN_SIGNING_KEY=...          # chave de assinatura do Mailgun
WEBHOOK_SENDGRID_VERIFICATION_KEY=...    # chave de verificação ECDSA do SendGrid
WEBHOOK_POSTMARK_BASIC_AUTH=usuario:senha # credenciais Basic Auth do Postmark
WEBHOOK_RESEND_SECRET=whsec_...          # segredo Svix do Resend
WEBHOOK_SNS_TOPIC_ARN=arn:aws:sns:...    # TopicArn esperado (SES via SNS)
```

| Provedor   | Esquema                                                | Significado do segredo                          |
|------------|--------------------------------------------------------|-------------------------------------------------|
| `mailgun`  | HMAC-SHA256 sobre `timestamp + token`                  | chave de assinatura do webhook                  |
| `sendgrid` | ECDSA (P-256/SHA-256) sobre `timestamp + corpo`, headers Twilio | chave de verificação ECDSA (PEM ou base64 DER) |
| `postmark` | Basic Auth (`hash_equals`)                             | credenciais no formato `usuario:senha`          |
| `resend`   | HMAC-SHA256 base64 sobre `id.timestamp.payload`, headers `svix-*` | segredo Svix (com ou sem prefixo `whsec_`) |
| `sns`      | Certificado X.509 + `openssl_verify` sobre string canônica | TopicArn esperado (mensagem fixada ao tópico) |

A tolerância de timestamp (em segundos) é configurável:

```php
// config/webhook-signatures.php
'tolerance' => [
    'default' => 300,   // Mailgun, Resend, SendGrid
    'sns'     => 3600,  // SNS pode reentregar mensagens mais tarde
],
```

## Uso

### 1. Middleware (forma recomendada)

O pacote registra o alias de middleware `webhook.signature`, parametrizado pelo provedor. Ele aborta com `403` quando a assinatura não pode ser verificada:

```php
use Illuminate\Support\Facades\Route;

Route::post('/webhooks/mailgun', InboundController::class)
    ->middleware('webhook.signature:mailgun');

Route::post('/webhooks/resend', ResendController::class)
    ->middleware('webhook.signature:resend');
```

O segredo é lido automaticamente de `config('webhook-signatures.providers.{provedor}.secret')`.

### 2. Uso direto via Facade

```php
use JeffersonGoncalves\WebhookSignatures\Facades\WebhookSignatures;

public function handle(Request $request)
{
    if (! WebhookSignatures::verify('sendgrid', $request)) {
        abort(403);
    }

    // ... processa o evento
}
```

Você também pode passar o segredo explicitamente (ignorando a config):

```php
WebhookSignatures::verify('mailgun', $request, $minhaChave);
```

### 3. Uso de um verificador isolado

Cada verificador implementa a interface `SignatureVerifier`:

```php
use JeffersonGoncalves\WebhookSignatures\Verifiers\ResendSignatureVerifier;

$verifier = new ResendSignatureVerifier(tolerance: 300);

$valido = $verifier->verify($request, $segredo); // bool
```

### 4. Registrando um verificador customizado

```php
use JeffersonGoncalves\WebhookSignatures\Facades\WebhookSignatures;

WebhookSignatures::extend('meu-provedor', MeuVerifier::class);
```

`MeuVerifier` deve implementar `JeffersonGoncalves\WebhookSignatures\Contracts\SignatureVerifier` e aceitar `int $tolerance` no construtor.

## O que cada verificador faz

- **Mailgun** — calcula `hash_hmac('sha256', timestamp.token, $chave)` e compara com a assinatura recebida via `hash_equals`. Aceita os campos no nível superior (rotas inbound) ou aninhados em `signature` (event webhooks). Rejeita timestamps fora da janela de tolerância.
- **SendGrid** — verifica a assinatura ECDSA (P-256/SHA-256) sobre `timestamp + corpo bruto`, lendo os cabeçalhos `X-Twilio-Email-Event-Webhook-Signature` e `-Timestamp`. Normaliza a chave de verificação (PEM ou base64 DER) e usa `openssl_verify`.
- **Postmark** — o Postmark não assina o payload; a autenticação é por Basic Auth. Compara usuário e senha em tempo constante (`hash_equals`).
- **Resend (Svix)** — reconstrói `id.timestamp.payload`, calcula HMAC-SHA256 com a chave decodificada (prefixo `whsec_` removido), faz base64 e compara contra cada par `versão,assinatura` do cabeçalho `svix-signature`. Rejeita timestamps fora da tolerância.
- **AWS SNS/SES** — fixa a mensagem ao `TopicArn` esperado, valida que o `SigningCertURL` aponta para um host legítimo da AWS (`sns.<região>.amazonaws.com`), reconstrói a string canônica documentada pela SNS, baixa o certificado X.509 e verifica a assinatura com `openssl_verify` (SHA1 para `SignatureVersion 1`, SHA256 para `2`). Rejeita mensagens muito antigas.

## Testes

```bash
composer test       # Pest
composer analyse    # PHPStan (level 5, Larastan)
composer format     # Laravel Pint
```

Cada verificador tem testes cobrindo: assinatura válida aceita, assinatura inválida rejeitada, requisição sem credenciais rejeitada e (onde aplicável) timestamp antigo rejeitado. Todas as chaves e *fixtures* criptográficas são geradas dentro dos testes.

## Migração (pacotes consumidores)

> Esta seção é **apenas documental**. Os pacotes consumidores não são alterados por este pacote — eles só poderão depender dele após a publicação no Packagist.

Hoje a verificação está duplicada (e divergente) em:

- `laravel-help-desk` → `src/Http/Middleware/Verify{Mailgun,SendGrid,Postmark,Resend}Signature.php`
- `laravel-service-desk` → `src/Http/Middleware/Verify{Mailgun,SendGrid,Postmark,Resend}Signature.php`
- `laravel-mail` → `src/Webhooks/{Mailgun,SendGrid,Ses,...}WebhookHandler::validate()`
- `laravel-satis` → verificação de webhook própria

Problemas reais encontrados na duplicação:

- **Fail-open**: o `help-desk` retornava `$next($request)` quando a chave não estava configurada — ou seja, aceitava qualquer requisição. Aqui o comportamento é sempre *fail-closed*.
- **Comparação não constante**: o `service-desk` (SendGrid/Postmark) usava `!==` em vez de `hash_equals`, expondo a *timing attacks*.
- **Sem proteção contra replay**: parte das implementações de Mailgun não validava a recência do timestamp.

Plano de migração sugerido (a executar em cada pacote, separadamente):

1. Adicionar `jeffersongoncalves/laravel-webhook-signatures` ao `composer.json` do pacote.
2. Substituir os middlewares próprios pelo alias `webhook.signature:{provedor}`, **ou** chamar `WebhookSignatures::verify(...)` dentro do handler existente.
3. Mapear os segredos atuais (ex.: `help-desk.email.inbound.mailgun.signing_key`) para `config('webhook-signatures.providers.mailgun.secret')` — ou passar o segredo explicitamente como terceiro argumento de `verify()`, preservando a config do pacote.
4. Remover os arquivos `Verify*Signature.php` duplicados e seus testes redundantes.
5. Rodar a suíte de testes do pacote consumidor.

Nenhum desses passos é realizado automaticamente — eles ficam documentados aqui para serem aplicados quando o pacote estiver publicado.

## Licença

MIT. Veja [LICENSE.md](LICENSE.md).
