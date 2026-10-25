# FlowSense TALQ Gateway

**A FastAPI-based pilot gateway with approval-based client API key issuance.**

FlowSense TALQ Gateway explores a secure access workflow for connecting authorized client systems to a future FlowSense/TALQ integration. A client submits an access request; the gateway emails a one-time verification token; after email ownership is verified, the service automatically issues a unique API key bound to that CMS UUID. Keys expire after 90 days by default and can also be revoked.

> **Status:** Pilot scaffold, not a complete or TALQ-certified implementation. Device and data-package collections are placeholders. Live FlowSense integration, complete TALQ schema validation, and production security controls remain future work.

## Access lifecycle

1. **Request access:** Client submits contact name, email, organization, purpose, and CMS UUID to `POST /access-requests`.
2. **Verify email:** Gateway sends a one-time token to the submitted email address. It expires after 30 minutes by default.
3. **Automatic issuance:** Client submits the token to `POST /verify-email`. The gateway issues a client API key automatically and shows it once; no manual admin approval is required.
4. **Use API:** Client sends the key using `X-API-Key`, plus `talq-api-version: 2.7.1` and its approved `clientAddress`.
5. **Expiration/revocation:** Keys expire after 90 days by default. An administrator can also revoke a key using `POST /admin/api-keys/{key_id}/revoke`.

Only a SHA-256 hash of each issued API key is stored in the database. The raw key is not retrievable later, so the client must save it securely when issued. The admin credential is separate from client API keys and must never be shared with clients.

## API endpoints

### Public
- `GET /health` — health probe.
- `POST /access-requests` — submit an access request; this does not issue a key.

### Admin-only (requires `X-Admin-Key`)
- `GET /admin/access-requests?status=pending_verification` — inspect unverified requests. Supported statuses: `pending_verification`, `verified`, `all`.
- `GET /admin/api-keys` — list key metadata, never raw keys.
- `POST /admin/api-keys/{key_id}/revoke` — revoke an issued key.

### Client authentication and issuance
- `POST /verify-email` — exchange a one-time email verification token for a client API key. The raw key is returned once.
- `GET /auth/verify` — verify an issued client API key and return safe organization/client metadata. Requires `X-API-Key`.

See [CLIENT_INTEGRATION.md](CLIENT_INTEGRATION.md) for the partner-backend request examples and Python client sample.

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
- [ ] Add rate limiting, email verification, audit events, and richer admin identity management.
- [ ] Map real FlowSense meter and sensor data into applicable TALQ models.
- [ ] Validate the required operations and payloads against the official specification.
- [ ] Run integration tests with the target CMS and review production security.

## References

- Repository: https://github.com/ayush2459/talq-api-key
- TALQ Consortium specification: https://github.com/TALQ-consortium/TALQ_specification
- FastAPI: https://fastapi.tiangolo.com/
- Render: https://render.com/docs
