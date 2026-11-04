# Partner Backend Authentication Guide

This guide explains how an external backend authenticates with the FlowSense TALQ Gateway pilot.

## Important status

The gateway implements Telegram-verified automatic API-key issuance, key expiration, and revocation. It remains a pilot scaffold: device and data-package lists are placeholders until a real FlowSense data source is connected. Do not treat empty successful responses as live FlowSense data or claim TALQ certification.

## 1. Request access and verify Telegram

Submit `POST /access-requests` with JSON:

```json
{
  "contact_name": "Partner contact name",
  "email": "partner technical contact email",
  "organization": "Partner organization",
  "telegram_username": "@partner_username",
  "purpose": "Backend-to-backend integration with FlowSense",
  "client_address": "00000000-0000-4000-8000-000000000001"
}
```

The response contains a `request_id`, a private `request_token`, and a `telegram_url`. Open the link and press Start using the Telegram account whose username was submitted. The backend verifies the actual Telegram sender through a secret-protected webhook. The link expires after 30 minutes by default.

Check the status with `GET /access-requests/{request_id}/status` and the `X-Request-Token` header. Do not log or persist the request token.

## 2. Issue the API key

After the status reports `telegram_verified: true`, call:

```http
POST /access-requests/{request_id}/issue-key
Content-Type: application/json

{"request_token": "<request-token>"}
```

The gateway returns the API key once, along with its ID, client address, creation time, expiry, and lifetime. Save the raw key in a secret manager immediately; the gateway stores only the hash. Keys expire after 90 days by default.

## 3. Call the gateway

```http
GET /devices?clientAddress=00000000-0000-4000-8000-000000000001
X-API-Key: <issued-client-api-key>
talq-api-version: 2.7.1
Accept: application/json
```

Use the actual stable CMS UUID associated with the key. Never place an API key in a URL, browser code, or public repository.

## 4. Verify or revoke

Call `GET /auth/verify` with `X-API-Key` to check authentication. A key can revoke keys belonging to the same access request using `POST /auth/api-keys/{key_id}/revoke`. An administrator can list key metadata and revoke any key using `X-Admin-Key`; keep that credential server-side only.

## Production checklist

- Set `TELEGRAM_BOT_TOKEN`, `TELEGRAM_BOT_USERNAME`, and `TELEGRAM_WEBHOOK_SECRET` as private backend environment variables.
- Configure Telegram's webhook to `https://flowsense-talq-gateway.onrender.com/telegram/webhook` using the matching secret token.
- Set `FRONTEND_ORIGINS` to the exact browser frontend origin; do not use CORS as authentication.
- Back up PostgreSQL, apply migration `001_email_verification_and_key_expiration.postgresql.sql`, then apply `002_telegram_verification.postgresql.sql` before deploying this branch.
- Keep `DEMO_MODE=true` until real FlowSense telemetry is integrated.
- Validate all implemented routes and payloads against the official TALQ 2.7.1 contract and the intended CMS.

The gateway is not a complete or TALQ-certified implementation.
