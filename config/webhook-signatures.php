<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Tolerância de Timestamp (segundos)
    |--------------------------------------------------------------------------
    |
    | Janela máxima, em segundos, entre o timestamp assinado pelo provedor e o
    | horário atual do servidor. Requisições fora desta janela são rejeitadas
    | (proteção contra replay). Use `default` para a maioria e sobrescreva por
    | provedor quando necessário (a SNS, por exemplo, pode reentregar mais tarde).
    |
    */

    'tolerance' => [
        'default' => 300,
        'sns' => 3600,
    ],

    /*
    |--------------------------------------------------------------------------
    | Segredos por Provedor
    |--------------------------------------------------------------------------
    |
    | O significado do "secret" varia por provedor:
    |
    |  - mailgun:  chave de assinatura do webhook (HMAC-SHA256).
    |  - sendgrid: chave de verificação ECDSA (Event Webhook).
    |  - postmark: credenciais Basic Auth no formato "usuario:senha".
    |  - resend:   segredo de assinatura Svix (com ou sem o prefixo "whsec_").
    |  - sns:      TopicArn esperado (a mensagem é fixada a este tópico).
    |  - github:   segredo do webhook (HMAC-SHA256 sobre o corpo bruto).
    |
    | Um segredo vazio faz a verificação FALHAR (fail-closed): a requisição é
    | sempre rejeitada quando não há segredo configurado.
    |
    */

    'providers' => [

        'mailgun' => [
            'secret' => env('WEBHOOK_MAILGUN_SIGNING_KEY'),
        ],

        'sendgrid' => [
            'secret' => env('WEBHOOK_SENDGRID_VERIFICATION_KEY'),
        ],

        'postmark' => [
            'secret' => env('WEBHOOK_POSTMARK_BASIC_AUTH'),
        ],

        'resend' => [
            'secret' => env('WEBHOOK_RESEND_SECRET'),
        ],

        'sns' => [
            'secret' => env('WEBHOOK_SNS_TOPIC_ARN'),
        ],

        'github' => [
            'secret' => env('GITHUB_WEBHOOK_SECRET'),
        ],

    ],

];
