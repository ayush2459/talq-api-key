# Partner Backend Authentication Guide

This guide explains how an external backend authenticates with the FlowSense TALQ Gateway pilot.

## Important status

The gateway currently implements API-key authentication and a request/approve/revoke lifecycle. It is still a pilot scaffold: device and data-package lists are empty placeholders until a real FlowSense data source is connected. Do not treat an empty successful response as live FlowSense data or claim TALQ certification.

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

The response includes a `request_id` and `status: pending`. This does not issue a key.

Agree the exact `client_address` value with the partner before submitting. The same value must be sent on protected gateway requests.

## 2. Administrator approves and issues a key

An authorized administrator calls:

- `GET /admin/access-requests?status=pending`
- `POST /admin/access-requests/{request_id}/approve`

Include the admin secret in the `X-Admin-Key` header. Keep this secret private; it is not the partner's API key.

The approval response returns a new `fs_talq_...` client API key once. Copy it into the partner's secret manager or another secure secret store. It cannot be retrieved from the gateway later; only a hash is stored.

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

An administrator can list issued key metadata with `GET /admin/api-keys` and revoke a key using `POST /admin/api-keys/{key_id}/revoke`. Revocation invalidates that key.

## CORS and network security

CORS is normally unnecessary for backend-to-backend HTTP calls. Use HTTPS and send the API key in the `X-API-Key` header. If the partner's browser-based frontend calls this API directly, discuss a strict CORS allowlist separately; never use CORS as authentication.

## Production checklist

- Set a strong, private `ADMIN_API_KEY` in Render.
- Configure `DATABASE_URL` to a persistent PostgreSQL database before issuing production keys.
- Use the deployed gateway's HTTPS base URL.
- Keep each partner on a unique key; never share the admin secret.
- Confirm the intended TALQ version and required endpoint schemas with the partner.
- Connect and validate actual FlowSense data before promising device/measurement access.
- Run an interoperability test with the partner's backend. API-key authentication alone does not establish TALQ conformance or certification.
