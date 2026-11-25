# FlowSense TALQ Gateway

Backend-only, LAN-deployable integration gateway for approved FlowSense partners.
This is a development pilot, not a claim of full TALQ 2.7.1 conformance or certification.

## Security boundary

The application is exposed as two separate Uvicorn listeners:

- **Internal control plane:** `app.admin_app:admin_app`, protected by a loopback-client guard and bound to `127.0.0.1:8001`. It contains administrator routes and Swagger UI. Never expose this listener to partner machines.
- **Partner API:** `app.partner_app:partner_app`, bound to the gateway's private LAN IP on port 8000. It has no Swagger, ReDoc or OpenAPI and applies an explicit HTTP-method/path allowlist before forwarding requests.

Partner machines can access only onboarding, OAuth, partner-owned key management and authorized data routes. Admin routes, legacy onboarding, docs, database and AWS credentials are not exposed through the partner listener.

## Windows LAN setup

Prerequisites: Python 3.11, private gateway LAN IP, and a protected gateway database.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Set a unique `ADMIN_API_KEY` and a persistent `DATABASE_URL` in the server-only `.env`. Configure `FLOW_SENSE_DATABASE_URL`, `AWS_REGION`, and the server's AWS IAM identity only on the FlowSense host. Never provide these values to partners.

Start the internal control plane in an administrator-only PowerShell window:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

Start the partner listener in another window (replace the example IP):

```powershell
$env:FLOWSENSE_LAN_HOST = "192.168.1.10"
.\.venv\Scripts\python.exe -m uvicorn app.partner_app:partner_app --host $env:FLOWSENSE_LAN_HOST --port 8000
```

Admin Swagger is available only on the gateway host at `http://127.0.0.1:8001/docs`. Partner base URL is the LAN listener, ideally behind a private-CA TLS reverse proxy. Restrict inbound TCP 8000 to approved partner IPs; do not permit partner access to port 8001, database ports or RDS. Binding to a private IP is not a substitute for firewall rules.

## Partner API onboarding

The partner runs `scripts/partner_onboarding_client.py` from its own backend environment. It generates an RSA key pair locally and submits only the public key. The private key remains on the partner machine.

Partner API:
- `POST /v1/onboarding/requests`
- `GET /v1/onboarding/requests/{request_id}`
- `POST /v1/onboarding/requests/{request_id}/claim`
- `POST /oauth/token`
- `GET /integrations/me`
- `POST /integrations/me/api-keys`
- `GET /integrations/me/api-keys`
- `POST /integrations/me/api-keys/{key_id}/rotate`
- `POST /integrations/me/api-keys/{key_id}/retire`
- `GET /auth/verify`
- `GET /devices`, `/measurements`, `/alerts`, `/events`, `/data-packages`

All other paths return 404 on the partner listener, including `/admin/*`, `/access-requests`, `/docs`, `/redoc`, and `/openapi.json`.

### Partner-side environment

```powershell
$env:FLOWSENSE_BASE_URL = "https://192.168.1.10:8000"
$env:PARTNER_CONTACT_NAME = "Partner Contact"
$env:PARTNER_EMAIL = "partner@example.com"
$env:PARTNER_ORGANIZATION = "Example Partner"
$env:PARTNER_PURPOSE = "Read approved FlowSense device and energy data."
$env:PARTNER_CLIENT_ADDRESS = "example-partner-01"
py scripts/partner_onboarding_client.py
```

The partner receives a request ID and a random onboarding status token. It stores the token locally and polls for approval. FlowSense admins review requests through the loopback-only control plane, approve them, provision OAuth scopes and assign facility grants. Provisioning encrypts the client credentials for the partner's submitted RSA public key; the admin response does not reveal the client secret. The partner claims the encrypted package once:

```powershell
py scripts/partner_onboarding_client.py --claim
```

The credential envelope uses RSA-OAEP-SHA256 to wrap an AES-256-GCM key. Claims expire 30 minutes after provisioning, and onboarding status tokens expire after 72 hours. The reference client protects the RSA private key with a local passphrase and stores claimed OAuth credentials in an encrypted local vault. Keep the private key, onboarding token, vault passphrase and encrypted vault private. The internal control plane records metadata-only audit events at `GET /admin/onboarding/{request_id}/audit`. Use `scripts/configure_partner_firewall.ps1 -PartnerIPv4 <approved-partner-ip>` from an elevated PowerShell session and review any pre-existing broad firewall allow rules.

## Data authorization

OAuth client credentials issue short-lived bearer tokens. Partners create and manage their own TALQ API keys. API keys are scoped to approved data categories and exact TALQ `clientAddress`. RDS retrieval is filtered by active facility grants and uses the server-side read-only IAM-authenticated database connection.

Available data routes:
- `GET /devices`, `/devices/count`, `/devices/{deviceAddress}`
- `GET /measurements` (energy/water scopes, bounded date windows and pagination)
- `GET /alerts` and `/events`
- `GET /data-packages`

The gateway does not expose database credentials or RDS connectivity to partners. `/events` currently represents alert lifecycle records; it does not imply a separate events table. Verify all returned records against live RDS data before production use.

## Tests and limitations

```powershell
.\.venv\Scripts\python.exe -m pip install pytest httpx
.\.venv\Scripts\python.exe -m compileall -q app tests scripts
.\.venv\Scripts\python.exe -m pytest -q
```

CI verifies unit tests and code compilation only. It cannot reach a private LAN or the live FlowSense RDS instance. Complete live tests for firewall isolation, TLS, facility grants, two-partner data isolation, credential claim, rotation and revocation before production. The gateway is not TALQ-certified; validate required models and operations against the target CMS and specification.

Never commit `.env`, partner private keys, onboarding tokens, OAuth credentials, bearer tokens or raw API keys.


## Cross-platform partner testing

For Windows, macOS and Linux partner machines, use
[`scripts/partner_test_client.py`](scripts/partner_test_client.py) to verify
the encrypted local API-key vault, retrieve only the isolated synthetic
`/v1/test-data` fixtures, or deliberately rotate and retire a partner API key.
See [`PARTNER_TEST_CLIENT.md`](PARTNER_TEST_CLIENT.md) for prerequisites and
commands. The client requires a trusted FlowSense certificate for HTTPS and
does not store credentials in the repository.
