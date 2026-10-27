# OAuth 2.0 client credentials for the FlowSense TALQ Gateway

This branch adds an OAuth 2.0 **Client Credentials** grant for machine-to-machine access, following RFC 6749 and Bearer-token use from RFC 6750. It is an addition to the existing Telegram approval and API-key flow, not a replacement for FlowSense or Neon.

## Current behavior

- Existing `X-API-Key` authentication remains supported.
- OAuth credentials are issued only by the admin-protected endpoint and are linked to an existing active API client.
- OAuth access tokens expire after 3600 seconds (one hour); only token hashes are stored.
- OAuth requests use the `data:read` scope.
- The existing TALQ `talq-api-version: 2.7.1` and `clientAddress` checks still apply.
- Neon credentials remain server-side in `FLOW_SENSE_DATABASE_URL`; never give them to an API consumer.

## 1. Register an OAuth client

First, the partner must already have completed the current access approval/Telegram process and have an active API client. Use the exact approved TALQ clientAddress UUID.

Send this request to the gateway. Keep the admin key private.

```bash
curl -X POST "https://flowsense-talq-gateway.onrender.com/oauth/clients" \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: YOUR_ADMIN_API_KEY" \
  -d '{"client_address":"APPROVED-CLIENT-UUID","label":"Partner integration"}'
```

The response contains `client_id` and `client_secret`. The secret is shown only once; transfer it through a secure secret-sharing channel and store it in the partner's backend secret manager. Do not put it in browser JavaScript, a frontend, source control, or logs.

## 2. Request an access token

Use HTTP Basic authentication with the issued client ID and secret. The request body is URL-encoded.

```bash
curl -X POST "https://flowsense-talq-gateway.onrender.com/oauth/token" \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "grant_type=client_credentials&scope=data%3Aread"
```

The response contains an opaque `access_token`, `token_type: Bearer`, `expires_in: 3600`, and the granted scope. The token response uses `Cache-Control: no-store` and `Pragma: no-cache`.

## 3. Call a data endpoint

Send the token in the standard Bearer header. Continue to provide the required TALQ version and the same approved `clientAddress`.

```bash
curl "https://flowsense-talq-gateway.onrender.com/data/facilities?limit=10&clientAddress=APPROVED-CLIENT-UUID" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "talq-api-version: 2.7.1"
```

Do not send the original API key in this OAuth request. The gateway validates the token and then applies the existing clientAddress and TALQ-version checks.

## 4. Revoke an OAuth client

```bash
curl -X POST "https://flowsense-talq-gateway.onrender.com/oauth/clients/YOUR_CLIENT_ID/revoke" \
  -H "X-Admin-Key: YOUR_ADMIN_API_KEY"
```

This revokes the client and its existing access tokens. A new OAuth client must be registered to resume OAuth access.

## Important operational notes

- Set a strong `ADMIN_API_KEY` in the gateway backend environment.
- Keep `DATABASE_URL` (gateway management database) and `FLOW_SENSE_DATABASE_URL` (FlowSense data source) separate.
- Use HTTPS and keep client secrets and access tokens out of logs.
- Existing API-key authentication remains enabled on this branch for backward compatibility. If OAuth-only access is required later, disable legacy key access only after partner testing and an explicit migration decision.
- This is a first implementation of the client-credentials flow. It does not implement browser login, user consent, Authorization Code + PKCE, OpenID Connect, or per-facility scopes. Confirm the partner's exact conformance requirements before describing it as a complete authorization-server product.
