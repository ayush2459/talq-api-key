# FlowSense TALQ Gateway

**A FastAPI-based pilot gateway with Telegram-verified client API key issuance.**

FlowSense TALQ Gateway provides a pilot access workflow for connecting client systems to a future FlowSense/TALQ integration. A client submits an access request, opens a one-time Telegram deep link, and verifies that the Telegram sender matches the submitted username. Only then can the client exchange its request token for a unique API key bound to its CMS UUID. Keys expire after 90 days by default and can be revoked.

> **Status:** Live read-only FlowSense data routes are implemented behind API-key and TALQ client-address checks. The legacy `/devices` and `/data-packages` pilot routes remain placeholders; the live data endpoints are under `/data/*`. This is not a complete or TALQ-certified implementation.

## Access lifecycle

1. **Request access:** The browser submits contact name, email, organization, Telegram username, purpose, and CMS UUID to `POST /access-requests`.
2. **Verify Telegram:** The gateway returns a one-time `https://t.me/<bot>?start=<token>` deep link. The user opens the configured bot and presses Start. The webhook validates the Telegram secret header, link expiry, and sender username.
3. **Check status:** The browser polls `GET /access-requests/{request_id}/status` using its private `X-Request-Token`.
4. **Issue a key:** After verification, `POST /access-requests/{request_id}/issue-key` returns a high-entropy key once. Only a SHA-256 hash is stored.
5. **Use and revoke:** Client requests use `X-API-Key`. The owner can revoke a key belonging to the same access request; administrators retain a separate admin-only revocation route. Keys expire after 90 days by default.

The raw client API key and request token must never be logged or stored in browser storage. The dashboard stores only display metadata locally. A separate high-entropy key-management token is returned once when a key is issued; only its SHA-256 hash is stored on the server. The dashboard stores this management token in browser local storage to reload metadata and support revocation after refresh. Treat it like a password: do not share it, commit it, or use it on an untrusted device. You can connect another device by entering the management token. It is scoped to the verified email and Telegram username used for issuance, so it can manage keys created by that same verified identity across requests. It cannot access admin endpoints. The admin credential is never sent to the browser.

## OAuth 2.0 integration

The dashboard includes an OAuth 2.0 Applications panel for the Telegram-verified owner. It creates confidential OAuth clients linked to the same verified integration and client UUID. The client secret is returned once and only its hash is stored. Server-side integrations exchange credentials at `POST /oauth/token` using the OAuth 2.0 `client_credentials` grant and receive a one-hour opaque Bearer access token.

Scopes are restricted to `data:read` and `gateway:read`. Use `Authorization: Bearer <access_token>` on supported read-only gateway routes; legacy `X-API-Key` access remains supported. Revoking an OAuth client revokes its outstanding access tokens. Do not place client secrets in frontend code. See [CLIENT_INTEGRATION.md](CLIENT_INTEGRATION.md) for token exchange examples.

### OAuth 2.0 Data Explorer dashboard tab

The console has an `OAuth Data Explorer` tab for manually testing a registered OAuth client. Enter the Client ID and Client Secret, choose the `data:read` scope, and connect. The token response returns the approved client's address and organization metadata so the browser can query `/data/facilities`, `/data/energy`, and `/data/water` with the required `clientAddress` and TALQ version header. The page supports all facilities or a selected facility, a 24-hour to 365-day time range, manual refresh, and optional 30-second, 60-second, or 5-minute refresh. It shows reading timestamps and warns when the latest returned reading is older than 30 minutes. Refresh queries the database; it does not generate sensor readings.

**Security limitation:** This explorer is intended as a controlled diagnostic tool. The OAuth Client Credentials grant is designed for confidential clients. A secret entered into a browser is visible to that browser session even if it is not persisted in browser storage. For production user-facing access, exchange the credentials in a trusted backend-for-frontend or use Authorization Code with PKCE. The explorer does not save the client secret or Bearer token in local or session storage.

## API endpoints

### Public
- `GET /health` — health probe.
- `POST /access-requests` — submit an access request; this does not issue a key.

### Admin-only (requires `X-Admin-Key`)
- `GET /admin/access-requests?status=pending_verification` — inspect unverified requests. Supported statuses: `pending_verification`, `verified`, `issuing`, `key_issued`, `all`.
- `GET /admin/api-keys` — list key metadata, never raw keys.
- `POST /admin/api-keys/{key_id}/revoke` — revoke an issued key.

### Client authentication and issuance
- `POST /access-requests` — create a request and return a Telegram verification link plus a private request token.
- `POST /telegram/webhook` — Telegram webhook endpoint (configured with Telegram's `secret_token` header).
- `GET /access-requests/{request_id}/status` — check verification status using `X-Request-Token`.
- `POST /access-requests/{request_id}/issue-key` — issue the key after verification; raw key is returned once.
- `GET /auth/verify` — verify an issued client API key and return safe organization/client metadata.
- `POST /auth/api-keys/{key_id}/revoke` — revoke a key within the authenticated request's own key scope, when the API key is available.
- `GET /auth/managed-api-keys` — list safe key metadata using `X-Key-Management-Token`; returns only keys for the associated access request.
- `POST /auth/managed-api-keys/{key_id}/revoke` — revoke a key in that same request scope using `X-Key-Management-Token`.

### Protected gateway pilot routes (requires `X-API-Key`)
- `GET /integration-status`
- `GET /devices`
- `GET /devices/count`
- `GET /devices/{deviceAddress}`
- `GET /services`
- `GET /services/{serviceName}`
- `GET /data-packages`

Gateway routes also require the `talq-api-version: 2.7.1` header and `clientAddress` query parameter. The requested client address must match the one associated with the issued key. These are pilot routes and response payloads, not proof of complete TALQ 2.7.1 conformance.

### Live FlowSense data routes (requires `X-API-Key` + TALQ headers)
- `GET /data/facilities?limit=100` — facilities metadata.
- `GET /data/devices?facility_code=FS-FAC-001&limit=100` — IoT devices with facility metadata.
- `GET /data/energy?facility_code=FS-FAC-001&hours=24&limit=500` — main energy meter readings.
- `GET /data/water?facility_code=FS-FAC-001&hours=24&limit=500` — main water meter readings and water-related sensor readings.
- `GET /data/alerts?facility_code=FS-FAC-001&status=active&limit=100` — alerts with related anomaly metadata.

All routes are read-only. `facility_code` is optional because the selected policy allows every approved API key to read all facilities; clients can still filter their results. Results are bounded by default and maximum limits to avoid unbounded scans. `FLOW_SENSE_DATABASE_URL` must point to the FlowSense PostgreSQL database using a dedicated read-only database role. It is separate from `DATABASE_URL`, which stores gateway access requests and API-key hashes.

## Local setup (Windows PowerShell)

Prerequisites: Python 3.11 and Git.

```powershell
git clone https://github.com/ayush2459/talq-api-key.git
cd talq-api-key
py -3.11 -m venv .venv
.\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Generate a strong admin secret:

```powershell
py -c "import secrets; print(secrets.token_urlsafe(48))"
```

Put the generated value into `ADMIN_API_KEY` in `.env`. Do not use a client API key as the admin key, and never commit `.env`.

The local example uses SQLite. Configure the Telegram bot settings for verification; tests mock Telegram message delivery:

```dotenv
ADMIN_API_KEY=replace-with-your-generated-admin-secret
DATABASE_URL=sqlite:///./flowsense_talq.db
TALQ_CLIENT_ADDRESS=
DEMO_MODE=true
API_KEY_LIFETIME_DAYS=90
TELEGRAM_VERIFICATION_MINUTES=30
PUBLIC_BASE_URL=http://127.0.0.1:8000
TELEGRAM_BOT_TOKEN=
TELEGRAM_BOT_USERNAME=
TELEGRAM_WEBHOOK_SECRET=
FRONTEND_ORIGINS=http://127.0.0.1:5500,http://localhost:5500
```

Start the service:

```powershell
.\\RUN_WINDOWS.ps1
```

Open [Swagger UI](http://127.0.0.1:8000/docs) or the [health endpoint](http://127.0.0.1:8000/health).

### Run tests

```powershell
.\\.venv\\Scripts\\python.exe -m pip install pytest httpx
.\\.venv\\Scripts\\python.exe -m pytest -q
```

## Deploying on Render

The repository includes a Dockerfile and Render Blueprint. For approval and API-key records to survive restarts and deployments, configure a **persistent PostgreSQL database**:

1. Create a PostgreSQL database in Render (or use an existing managed PostgreSQL database).
2. Back up any existing database before applying schema changes.
3. Apply `migrations/001_email_verification_and_key_expiration.postgresql.sql`, then `migrations/002_telegram_verification.postgresql.sql`, to the existing database before deploying code that expects those columns.
4. Copy the private/internal connection URL into the web service's `DATABASE_URL` environment variable when the database and web service are in the same Render region.
5. Configure `TELEGRAM_BOT_TOKEN`, `TELEGRAM_BOT_USERNAME`, `TELEGRAM_WEBHOOK_SECRET`, and the exact `FRONTEND_ORIGINS` value in Render's environment settings. Keep secrets private.
6. Confirm `ADMIN_API_KEY` is strong and keep `DEMO_MODE=true` until real FlowSense integration is complete.
7. Only after CI passes and a manual Telegram end-to-end test succeeds should the branch be considered deployable.

Do not rely on the default SQLite file for a cloud deployment: local files on ephemeral hosting may be lost during redeploys or restarts. Never commit database credentials or admin secrets to GitHub.

## Telegram bot setup

1. Create a bot with Telegram's official BotFather and keep the bot token private.
2. Set `TELEGRAM_BOT_TOKEN`, `TELEGRAM_BOT_USERNAME` (without the leading `@`), and `TELEGRAM_WEBHOOK_SECRET` as backend environment variables.
3. After deploying the backend to HTTPS, configure the webhook from a trusted PowerShell session. Set the token in your shell without committing it:
   ```powershell
   $env:TELEGRAM_BOT_TOKEN = "paste-token-from-BotFather"
   $env:TELEGRAM_WEBHOOK_SECRET = "use-a-long-random-secret"
   $body = @{
     url = "https://flowsense-talq-gateway.onrender.com/telegram/webhook"
     secret_token = $env:TELEGRAM_WEBHOOK_SECRET
     allowed_updates = @("message")
   } | ConvertTo-Json
   Invoke-RestMethod -Method Post -Uri "https://api.telegram.org/bot$env:TELEGRAM_BOT_TOKEN/setWebhook" -ContentType "application/json" -Body $body
   Remove-Item Env:TELEGRAM_BOT_TOKEN
   ```
4. Confirm Telegram reports `ok: true`, then test a new access request end to end. Never publish bot tokens or webhook secrets in issues, screenshots, source control, or browser code.

The webhook must be configured only after the service is publicly reachable over HTTPS. Local UI testing can validate request creation and API connectivity, but Telegram cannot call a local-only webhook.

## Example access workflow

Use the browser console or submit a request directly:

```powershell
$body = @{
  contact_name = "Example Contact"
  email = "integration@example.com"
  organization = "Example Organization"
  telegram_username = "@example_user"
  purpose = "Integrate our CMS with FlowSense gateway data for a pilot."
  client_address = "00000000-0000-4000-8000-000000000001"
} | ConvertTo-Json
$request = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/access-requests" -ContentType "application/json" -Body $body
$request
```

Open the returned `telegram_url`, press Start with the matching Telegram account, and then check the request status using `X-Request-Token`. After `telegram_verified` is true, submit `POST /access-requests/{request_id}/issue-key` with JSON body `{"request_token":"<request_token>"}`. The raw API key is returned once. Use the real stable CMS UUID for `client_address`.

## Security notes and production work

- Keep `ADMIN_API_KEY` restricted to trusted administrators.
- The raw client API key and verification token are each shown only in their one-time flows; only hashes are persisted.
- Configure SMTP environment variables before enabling access requests; email delivery fails closed if SMTP is missing or fails.
- `API_KEY_LIFETIME_DAYS` defaults to 90 (allowed: 1–3650); `TELEGRAM_VERIFICATION_MINUTES` defaults to 30 (allowed: 5–1440).
- Apply `migrations/001_email_verification_and_key_expiration.postgresql.sql` to an existing PostgreSQL database before deploying. Back up first. Existing keys receive a 90-day lifetime from their original creation time.
- Revoke a key if it is exposed or no longer needed.
- The public request endpoint should be protected with rate limiting and abuse monitoring before broad public release.
- Use HTTPS, rotate credentials, review logs, and implement suitable client authentication and access controls.
- Validate all relevant request/response schemas and security requirements against the official TALQ specification and the intended CMS.
- The current admin key is a shared administrative secret, not a full user-management or identity-provider system.

## Current limitations

- No live MQTT, sensor, meter, or production database integration with FlowSense business data.
- Device and data-package lists are empty placeholders.
- Only a limited set of gateway-style routes is present.
- No complete TALQ schema validation or external CMS interoperability test has been demonstrated.
- The service is not TALQ-certified.

## Roadmap

- [x] Basic FastAPI gateway scaffold and protected routes.
- [x] Email-verification-based automatic API key issuance, 90-day default expiration, and revocation workflow.
- [x] Store issued API keys as hashes.
- [ ] Add rate limiting, Telegram webhook monitoring, rate limiting, audit events, and richer admin identity management.
- [x] Add read-only FlowSense PostgreSQL endpoints for facilities, devices, energy, water, and alerts.
- [ ] Map live database records into complete official TALQ models.
- [ ] Validate the required operations and payloads against the official specification.
- [ ] Run integration tests with the target CMS and review production security.

## References

- Repository: https://github.com/ayush2459/talq-api-key
- TALQ Consortium specification: https://github.com/TALQ-consortium/TALQ_specification
- FastAPI: https://fastapi.tiangolo.com/
- Render: https://render.com/docs
