# FlowSense TALQ Gateway

**A FastAPI-based pilot gateway with Telegram-verified client API key issuance.**

FlowSense TALQ Gateway provides a pilot access workflow for connecting client systems to a future FlowSense/TALQ integration. A client submits an access request, opens a one-time Telegram deep link, and verifies that the Telegram sender matches the submitted username. Only then can the client exchange its request token for a unique API key bound to its CMS UUID. Keys expire after 90 days by default and can be revoked.

> **Status:** Pilot scaffold, not a complete or TALQ-certified implementation. Device and data-package collections are placeholders. Live FlowSense integration, complete TALQ schema validation, and production security controls remain future work.

## Access lifecycle

1. **Request access:** The browser submits contact name, email, organization, Telegram username, purpose, and CMS UUID to `POST /access-requests`.
2. **Verify Telegram:** The gateway returns a one-time `https://t.me/<bot>?start=<token>` deep link. The user opens the configured bot and presses Start. The webhook validates the Telegram secret header, link expiry, and sender username.
3. **Check status:** The browser polls `GET /access-requests/{request_id}/status` using its private `X-Request-Token`.
4. **Issue a key:** After verification, `POST /access-requests/{request_id}/issue-key` returns a high-entropy key once. Only a SHA-256 hash is stored.
5. **Use and revoke:** Client requests use `X-API-Key`. The owner can revoke a key belonging to the same access request; administrators retain a separate admin-only revocation route. Keys expire after 90 days by default.

The raw API key and request token must not be logged or stored in browser local storage. The dashboard keeps key material in memory for the current page session; refresh loses access to that one-time display. The admin credential is never sent to the browser.

## API endpoints

### Public
- `GET /health` — health probe.
- `POST /access-requests` — submit an access request; this does not issue a key.

### Admin-only (requires `X-Admin-Key`)
- `GET /admin/access-requests?status=pending_verification` — inspect unverified requests. Supported statuses: `pending_verification`, `verified`, `all`.
- `GET /admin/api-keys` — list key metadata, never raw keys.
- `POST /admin/api-keys/{key_id}/revoke` — revoke an issued key.

### Client authentication and issuance
- `POST /access-requests` — create a request and return a Telegram verification link plus a private request token.
- `POST /telegram/webhook` — Telegram webhook endpoint (configured with Telegram's `secret_token` header).
- `GET /access-requests/{request_id}/status` — check verification status using `X-Request-Token`.
- `POST /access-requests/{request_id}/issue-key` — issue the key after verification; raw key is returned once.
- `GET /auth/verify` — verify an issued client API key and return safe organization/client metadata.
- `POST /auth/api-keys/{key_id}/revoke` — revoke a key within the authenticated request's own key scope.
- `POST /admin/api-keys/{key_id}/revoke` — admin-only revocation using `X-Admin-Key`.

### Protected gateway pilot routes (requires `X-API-Key`)
- `GET /integration-status`
- `GET /devices`
- `GET /devices/count`
- `GET /devices/{deviceAddress}`
- `GET /services`
- `GET /services/{serviceName}`
- `GET /data-packages`

Gateway routes also require the `talq-api-version: 2.7.1` header and `clientAddress` query parameter. The requested client address must match the one associated with the issued key. These are pilot routes and response payloads, not proof of complete TALQ 2.7.1 conformance.

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

The local example uses SQLite. Configure SMTP for real verification-email delivery; tests mock the email sender:

```dotenv
ADMIN_API_KEY=replace-with-your-generated-admin-secret
DATABASE_URL=sqlite:///./flowsense_talq.db
TALQ_CLIENT_ADDRESS=
DEMO_MODE=true
API_KEY_LIFETIME_DAYS=90
EMAIL_VERIFICATION_MINUTES=30
PUBLIC_BASE_URL=http://127.0.0.1:8000
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=replace-with-smtp-username
SMTP_PASSWORD=replace-with-smtp-password
SMTP_FROM_EMAIL=api@example.com
SMTP_USE_STARTTLS=true
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
2. Copy its private/internal connection URL into the web service's `DATABASE_URL` environment variable when the database and web service are in the same Render region.
3. Deploy the Blueprint and confirm `ADMIN_API_KEY` has a strong generated value. Keep it private.
4. Keep `DEMO_MODE=true` until real FlowSense integration is complete.
5. Test the health endpoint and submit a sample access request.

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

Submit a request in Swagger UI using `POST /access-requests`:

```json
{
  "contact_name": "Example Contact",
  "email": "integration@example.com",
  "organization": "Example Organization",
  "purpose": "Integrate our CMS with FlowSense gateway data for a pilot.",
  "client_address": "00000000-0000-4000-8000-000000000001"
}
```

The gateway emails a one-time verification token. Submit it to `POST /verify-email` as JSON containing the token. The response contains the new key once and its `expires_at` timestamp. Use it in `X-API-Key` and include the exact approved CMS UUID as `clientAddress`.

## Security notes and production work

- Keep `ADMIN_API_KEY` restricted to trusted administrators.
- The raw client API key and verification token are each shown only in their one-time flows; only hashes are persisted.
- Configure SMTP environment variables before enabling access requests; email delivery fails closed if SMTP is missing or fails.
- `API_KEY_LIFETIME_DAYS` defaults to 90 (allowed: 1–3650); `EMAIL_VERIFICATION_MINUTES` defaults to 30 (allowed: 5–1440).
- Apply `migrations/001_email_verification_and_key_expiration.postgresql.sql` to an existing PostgreSQL database before deploying. Back up first. Existing keys receive a 90-day lifetime from their original creation time.
- Revoke a key if it is exposed or no longer needed.
- The public request endpoint should be protected with rate limiting, abuse monitoring, and optionally CAPTCHA/email verification before broad public release.
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
- [ ] Map real FlowSense meter and sensor data into applicable TALQ models.
- [ ] Validate the required operations and payloads against the official specification.
- [ ] Run integration tests with the target CMS and review production security.

## References

- Repository: https://github.com/ayush2459/talq-api-key
- TALQ Consortium specification: https://github.com/TALQ-consortium/TALQ_specification
- FastAPI: https://fastapi.tiangolo.com/
- Render: https://render.com/docs
