# Partner Backend Authentication Guide

This guide explains how an external backend authenticates with the FlowSense TALQ Gateway pilot.

## Important status

The gateway implements email-verified automatic API-key issuance, expiration, and revocation. It is still a pilot scaffold: device and data-package lists are empty placeholders until a real FlowSense data source is connected. Do not treat an empty successful response as live FlowSense data or claim TALQ certification.

## 1. Submit an access request

Send `POST /access-requests` to the gateway base URL with JSON:

```json
{
  "contact_name": "Partner contact name",
  "email": "partner technical contact email",
  "organization": "Partner organization",
  "purpose": "Backend-to-backend integration with FlowSense",
  "client_address": "Partner's agreed TALQ clientAddress"
}
```

The response includes a `request_id` and `status: pending_verification`. The gateway sends a one-time token to the submitted email. This does not issue a key yet.

Use the stable UUID configured for the partner CMS as `client_address`; do not use an organization slug, hostname, or IP address. The same UUID must be sent on protected gateway requests.

## 2. Verify email and receive the key automatically

The gateway emails a one-time verification token. Exchange it with:

```http
POST /verify-email
Content-Type: application/json

{"token": "<token-from-email>"}
```

After successful verification, the gateway automatically returns the API key once, plus `created_at`, `expires_at`, `client_address`, and `lifetime_days`. No manual administrator approval is required. Verification tokens expire after 30 minutes by default and cannot be reused. Store the API key in a secret manager immediately; the gateway stores only its hash.

## 3. Partner calls the gateway

Example request:

```http
GET /devices?clientAddress=PARTNER_CLIENT_ADDRESS
Host: flowsense-talq-gateway.onrender.com
X-API-Key: fs_talq_REPLACE_WITH_ISSUED_KEY
talq-api-version: 2.7.1
Accept: application/json
```

Replace the example key and address with the values issued/agreed for the partner. Never place an API key in a URL, browser code, or public repository.

For a simple connectivity/authentication check, call `GET /integration-status` with `X-API-Key`. TALQ-style routes such as `/devices` also require `talq-api-version: 2.7.1` and the approved `clientAddress` query parameter.

## 4. Revoke access

An administrator can list issued key metadata with `GET /admin/api-keys` and revoke a key using `POST /admin/api-keys/{key_id}/revoke`. Revocation invalidates that key. Keys expire after 90 days by default; check the `expires_at` value returned at issuance. An expired key receives HTTP 401 and must be replaced by repeating email verification.

## CORS and network security

CORS is normally unnecessary for backend-to-backend HTTP calls. Use HTTPS and send the API key in the `X-API-Key` header. If the partner's browser-based frontend calls this API directly, discuss a strict CORS allowlist separately; never use CORS as authentication.

## Production checklist

- Set a strong, private `ADMIN_API_KEY` in Render.
- Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL`, and `SMTP_USE_STARTTLS` as secret/environment settings; never commit SMTP credentials.
- Set `PUBLIC_BASE_URL` to the deployed HTTPS gateway URL, `API_KEY_LIFETIME_DAYS=90`, and `EMAIL_VERIFICATION_MINUTES=30`.
- Configure `DATABASE_URL` to a persistent PostgreSQL database before issuing production keys.
- Use the deployed gateway's HTTPS base URL.
- Keep each partner on a unique key; never share the admin secret.
- Confirm the intended TALQ version and required endpoint schemas with the partner.
- Connect and validate actual FlowSense data before promising device/measurement access.
- Run an interoperability test with the partner's backend. API-key authentication alone does not establish TALQ conformance or certification.


## TALQ clientAddress requirement

For TALQ 2.7.1 Gateway operations, the `clientAddress` query parameter is the **CMS address** and must be a UUID. Ask the partner to provide the stable UUID configured for its CMS; do not use a company slug, hostname, or IP address. The gateway binds that UUID to the approved API key. Example only: `00000000-0000-4000-8000-000000000001` (replace with the partner's real CMS UUID).
