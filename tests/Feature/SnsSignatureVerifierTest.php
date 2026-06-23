<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use JeffersonGoncalves\WebhookSignatures\Verifiers\SnsSignatureVerifier;

const SNS_TOPIC = 'arn:aws:sns:us-east-1:123456789012:ses-events';
const SNS_CERT_URL = 'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-cert.pem';

function snsKeyAndCert(): array
{
    $pkey = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);

    $csr = openssl_csr_new(['commonName' => 'sns.amazonaws.com'], $pkey);
    $x509 = openssl_csr_sign($csr, null, $pkey, 1);
    openssl_x509_export($x509, $certPem);

    return [$pkey, $certPem];
}

function snsCanonical(array $payload): string
{
    $canonical = '';

    foreach (['Message', 'MessageId', 'Timestamp', 'TopicArn', 'Type'] as $field) {
        $canonical .= $field."\n".$payload[$field]."\n";
    }

    return $canonical;
}

function snsPayload($privateKey, string $timestamp, string $message = 'hello'): array
{
    $payload = [
        'Type' => 'Notification',
        'MessageId' => 'msg-id-1',
        'TopicArn' => SNS_TOPIC,
        'Message' => $message,
        'Timestamp' => $timestamp,
        'SignatureVersion' => '1',
        'SigningCertURL' => SNS_CERT_URL,
    ];

    openssl_sign(snsCanonical($payload), $signature, $privateKey, OPENSSL_ALGO_SHA1);
    $payload['Signature'] = base64_encode($signature);

    return $payload;
}

function snsRequest(array $payload): Request
{
    return Request::create('/webhook', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], json_encode($payload));
}

beforeEach(function () {
    [$this->privateKey, $this->cert] = snsKeyAndCert();

    Http::fake([
        'sns.us-east-1.amazonaws.com/*' => Http::response($this->cert, 200),
    ]);
});

it('accepts a valid SNS message signature', function () {
    $payload = snsPayload($this->privateKey, gmdate('Y-m-d\TH:i:s.000\Z'));

    $verifier = new SnsSignatureVerifier;

    expect($verifier->verify(snsRequest($payload), SNS_TOPIC))->toBeTrue();
});

it('rejects an SNS message with a tampered body', function () {
    $payload = snsPayload($this->privateKey, gmdate('Y-m-d\TH:i:s.000\Z'));
    $payload['Message'] = 'tampered';

    $verifier = new SnsSignatureVerifier;

    expect($verifier->verify(snsRequest($payload), SNS_TOPIC))->toBeFalse();
});

it('rejects an SNS message with missing fields', function () {
    $payload = snsPayload($this->privateKey, gmdate('Y-m-d\TH:i:s.000\Z'));
    unset($payload['Signature']);

    $verifier = new SnsSignatureVerifier;

    expect($verifier->verify(snsRequest($payload), SNS_TOPIC))->toBeFalse();
});

it('rejects an SNS message from a different topic', function () {
    $payload = snsPayload($this->privateKey, gmdate('Y-m-d\TH:i:s.000\Z'));

    $verifier = new SnsSignatureVerifier;

    expect($verifier->verify(snsRequest($payload), 'arn:aws:sns:us-east-1:123456789012:other'))->toBeFalse();
});

it('rejects an SNS message with a stale timestamp', function () {
    $payload = snsPayload($this->privateKey, gmdate('Y-m-d\TH:i:s.000\Z', time() - 7200));

    $verifier = new SnsSignatureVerifier;

    expect($verifier->verify(snsRequest($payload), SNS_TOPIC))->toBeFalse();
});

it('rejects an SNS message with a non-AWS cert URL', function () {
    $payload = snsPayload($this->privateKey, gmdate('Y-m-d\TH:i:s.000\Z'));
    $payload['SigningCertURL'] = 'https://evil.example.com/cert.pem';

    $verifier = new SnsSignatureVerifier;

    expect($verifier->verify(snsRequest($payload), SNS_TOPIC))->toBeFalse();
});

it('rejects SNS verification when the secret is absent', function () {
    $payload = snsPayload($this->privateKey, gmdate('Y-m-d\TH:i:s.000\Z'));

    $verifier = new SnsSignatureVerifier;

    expect($verifier->verify(snsRequest($payload), ''))->toBeFalse();
});
