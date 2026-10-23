# FlowSense TALQ Gateway

**A FastAPI-based pilot gateway with approval-based client API key issuance.**

FlowSense TALQ Gateway explores a secure access workflow for connecting authorized client systems to a future FlowSense/TALQ integration. A client submits an access request; an administrator reviews and approves it; the service then generates a unique API key bound to that client's approved address. Each issued key can be revoked independently.

> **Status:** Pilot scaffold, not a complete or TALQ-certified implementation. Device and data-package collections are placeholders. Live FlowSense integration, complete TALQ schema validation, and production security controls remain future work.

## Access lifecycle

1. **Request access:** Client submits contact name, work email, organization, intended use, and client address to `POST /access-requests`.
2. **Review request:** An administrator lists pending requests through `GET /admin/access-requests`.
3. **Approve:** An administrator calls `POST /admin/access-requests/{request_id}/approve` using the `X-Admin-Key` header. The service creates a unique client API key and returns the raw key **once**.
4. **Use API:** Client sends its issued key using `X-API-Key`, plus `talq-api-version: 2.7.1` and its approved `clientAddress` on gateway requests.
5. **Revoke:** An administrator can revoke a key using `POST /admin/api-keys/{key_id}/revoke`. Revoked keys are rejected immediately.

Only a SHA-256 hash of each issued API key is stored in the database. The raw key is not retrievable later, so the client must save it securely when issued. The admin credential is separate from client API keys and must never be shared with clients.

## API endpoints

### Public
- `GET /health` — health probe.
- `POST /access-requests` — submit an access request; this does not issue a key.

### Admin-only (requires `X-Admin-Key`)
- `GET /admin/access-requests?status=pending` — list requests. Supported statuses: `pending`, `approved`, `rejected`, `all`.
- `POST /admin/access-requests/{request_id}/approve` — approve and issue one client API key.
- `POST /admin/access-requests/{request_id}/reject` — reject a pending request.
- `GET /admin/api-keys` — list key metadata, never raw keys.
- `POST /admin/api-keys/{key_id}/revoke` — revoke an issued key.

### Client authentication
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

The local example uses SQLite:

```dotenv
ADMIN_API_KEY=replace-with-your-generated-admin-secret
DATABASE_URL=sqlite:///./flowsense_talq.db
TALQ_CLIENT_ADDRESS=
DEMO_MODE=true
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
  "client_address": "cms-example-01"
}
```

An administrator then lists pending requests and approves the returned request ID. The approval response contains the new key once. Use that key in the `X-API-Key` header for protected endpoints and include `clientAddress=cms-example-01`.

## Security notes and production work

- Keep `ADMIN_API_KEY` restricted to trusted administrators.
- The raw client API key is returned once; only its hash is persisted.
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
- [x] Access request, administrator approval, per-client key issuance, and revocation workflow.
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
