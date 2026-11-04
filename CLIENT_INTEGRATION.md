# Client Backend Integration Guide

Base URL:
- Production: `https://flowsense-talq-gateway.onrender.com`
- Local development: `http://127.0.0.1:8000`

The browser console calls the gateway only for access-request creation, Telegram verification status, one-time key issuance, and owner-scoped revocation. Never expose `ADMIN_API_KEY` in browser code. For normal application traffic, keep `X-API-Key` on your own backend and call the gateway server-to-server.

## 1. Request access

`POST /access-requests` JSON:

```json
{
  "contact_name": "Integration Contact",
  "email": "integration@example.com",
  "organization": "Partner Organization",
  "telegram_username": "@example_user",
  "purpose": "Backend integration with FlowSense gateway",
  "client_address": "00000000-0000-4000-8000-000000000001"
}
```

The response contains `request_id`, `request_token`, and `telegram_url`. Open the Telegram link and press Start from the Telegram account whose username was supplied. The request token is a temporary browser secret; keep it in memory and never log it.

## 2. Verify Telegram

The bot receives `/start <one-time-token>` through the configured Telegram webhook. The gateway validates the webhook secret, one-time token, expiration, and Telegram sender username. The user must return to the browser and check the status.

```http
GET /access-requests/{request_id}/status
X-Request-Token: <request_token>
```

The response reports `telegram_verified: true` only after successful verification. A typed username by itself does not verify identity.

## 3. Issue the API key once

After status is verified, exchange the request token:

```http
POST /access-requests/{request_id}/issue-key
Content-Type: application/json

{"request_token": "<request_token>"}
```

The response contains `api_key`, `api_key_id`, `client_address`, `created_at`, `expires_at`, and `lifetime_days`. The raw key is returned once only. Store it in a secret manager; the gateway persists only its hash.

## 4. Verify and use the key

```http
GET /auth/verify
X-API-Key: <issued-client-api-key>
```

Protected gateway routes also require `talq-api-version: 2.7.1` and the exact approved `clientAddress` query parameter.

## 5. Revoke access

An authenticated key can revoke a key belonging to the same access request:

```http
POST /auth/api-keys/{key_id}/revoke
X-API-Key: <active-key-from-the-same-request>
```

Administrators can separately list key metadata and revoke keys using `X-Admin-Key`. Never place the admin secret in frontend code. Keys expire after 90 days by default.

## Telegram and deployment requirements

Configure `TELEGRAM_BOT_TOKEN`, `TELEGRAM_BOT_USERNAME`, and `TELEGRAM_WEBHOOK_SECRET` as backend secrets. The Telegram webhook URL must be publicly reachable over HTTPS. Configure `FRONTEND_ORIGINS` with the exact origin serving the browser UI; CORS is not authentication.

The current gateway is a pilot scaffold. Device and data-package lists are placeholders until real FlowSense data is mapped, and the project is not TALQ-certified.


## OAuth 2.0 username/password and refresh-token flow

An administrator provisions a username/password account linked to an already-approved, active client API key using `POST /admin/oauth-users` and the `X-Admin-Key` header. Passwords must contain at least 12 characters. The gateway stores only a salted PBKDF2-HMAC-SHA256 password hash. Never send the admin key or user password from browser code.

### 1. Login

`POST /oauth/token` using `application/x-www-form-urlencoded`:

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=partner_user&password=<password>&scope=data%3Aread%20gateway%3Aread
```

The response includes `access_token`, `token_type`, `expires_in` (default 900 seconds / 15 minutes), `refresh_token`, `refresh_expires_in` (default 604800 seconds / 7 days), and `scope`. Only token hashes are persisted. Access-token lifetime is configurable with `OAUTH_ACCESS_TOKEN_SECONDS` (60-3600 seconds); refresh lifetime with `OAUTH_REFRESH_TOKEN_DAYS` (1-90 days).

### 2. Call protected APIs

Send `Authorization: Bearer <access_token>`. TALQ routes still require `talq-api-version: 2.7.1` and the approved `clientAddress` query parameter. Data routes require `data:read`; other protected gateway read routes require `gateway:read`.

### 3. Refresh before expiry

Exchange the current refresh token at the same token endpoint:

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<refresh_token>
```

The response contains a new access token and a new refresh token. Refresh tokens are single-use and rotated; discard the old refresh token immediately. Reuse of an old refresh token is rejected.

### 4. Revoke a session

`POST /oauth/revoke` JSON:

```json
{"refresh_token": "<current_refresh_token>"}
```

This revokes the refresh token and active access tokens for that user. Revoking the underlying approved API key also blocks the user's OAuth access.

### Existing client-credentials flow

The verified dashboard owner can still create a confidential OAuth client from the **OAuth 2.0 Applications** panel. The client secret is returned once; only its SHA-256 hash is persisted. Exchange it from a trusted backend using HTTP Basic authentication:

```http
POST /oauth/token
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=data%3Aread%20gateway%3Aread
```

The response contains an opaque bearer access token valid for 3600 seconds. Only the token hash is stored. Use `Authorization: Bearer <access_token>` for protected read APIs. Data endpoints require `data:read`; other protected gateway read routes require `gateway:read`. The token is bound to the client UUID and must be accompanied by the required `clientAddress` query parameter and `talq-api-version: 2.7.1` header where the TALQ route requires them. Revoking an OAuth client also revokes its active access tokens. Existing `X-API-Key` clients remain supported.

Do not store an OAuth client secret in browser JavaScript or a public client. The dashboard is only the credential-management console; token exchange should happen server-to-server.
