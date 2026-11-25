# FlowSense Partner API — backend-only LAN onboarding

Partners use only the Partner API listener. They do not receive the admin URL,
Swagger/OpenAPI, admin credentials, database credentials, or AWS access.

## Network listeners

Run two separate Uvicorn processes on the FlowSense gateway host:

**Internal control plane (administrator only):**
```powershell
.\.venv\Scripts\python.exe -m uvicorn app.admin_app:admin_app --host 127.0.0.1 --port 8001
```

**Partner API (restricted private LAN):**
```powershell
$env:FLOWSENSE_LAN_HOST = "192.168.1.10"
.\.venv\Scripts\python.exe -m uvicorn app.partner_app:partner_app --host $env:FLOWSENSE_LAN_HOST --port 8000
```

The partner app has no docs or OpenAPI and enforces a method/path allowlist
before forwarding to the internal application. The internal app (including
all /admin routes and Swagger) must remain bound to loopback. Do not bind it
to 0.0.0.0 or the LAN interface.

Use a firewall rule that allows TCP 8000 only from approved partner IPs.
Do not allow partner machines to reach TCP 8001, the RDS endpoint, or database
ports. Use TLS on the LAN (for example, a private-CA certificate at a TLS
reverse proxy) before production use. The example listener uses HTTPS as the
partner client's default; configure the actual TLS termination accordingly.

## Partner onboarding API

The reference client in `scripts/partner_onboarding_client.py` generates a
3072-bit RSA key pair locally. It sends only the public key to FlowSense.
The private key never leaves the partner machine.

Set these environment variables on the partner machine:
```powershell
$env:FLOWSENSE_BASE_URL = "https://192.168.1.10:8000"
$env:PARTNER_CONTACT_NAME = "Partner Contact"
$env:PARTNER_EMAIL = "partner@example.com"
$env:PARTNER_ORGANIZATION = "Example Partner"
$env:PARTNER_PURPOSE = "Read approved FlowSense energy and device data."
$env:PARTNER_CLIENT_ADDRESS = "example-partner-01"
```

Install dependencies and submit:
```powershell
py -m pip install -r requirements.txt
py scripts/partner_onboarding_client.py
```

The partner receives a request ID and a random status token. The status token
is stored locally and is required to poll and claim. FlowSense admin reviews
the request at the internal control plane and provisions it using the existing
admin approval/provisioning endpoints. For a new API-based enrollment, the
provision operation stores an encrypted credential envelope and does not
return the client secret to the admin response. The partner claims the
envelope once:
```powershell
py scripts/partner_onboarding_client.py --claim
```

The server encrypts a random AES-256-GCM key with the submitted RSA public
key using RSA-OAEP-SHA256. The package is decryptable only by the matching
partner private key. Claim is one-time and expires 30 minutes after provisioning.
The onboarding status token expires after 72 hours. The reference client protects the RSA private key with a local passphrase and stores decrypted OAuth credentials in an AES-GCM/Scrypt encrypted local vault. Keep the private key, status token, vault passphrase and encrypted vault private; never commit them. The vault can be loaded using the `load_credentials(passphrase)` helper and should be transferred into the partner's secret manager for production.

FlowSense records metadata-only onboarding audit events. An administrator can inspect them using `GET /admin/onboarding/{request_id}/audit` on the loopback-only control plane. No secrets or tokens are written to audit details.

On Windows, an administrator can run `scripts/configure_partner_firewall.ps1 -PartnerIPv4 <approved-partner-ip>` from an elevated PowerShell session. Review existing broad firewall allow rules as well; allow rules are additive.

## Partner routes

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

Everything else returns 404 on the partner listener, including admin routes,
legacy onboarding routes, Swagger, ReDoc and OpenAPI.

## Important deployment note

The current development branch uses one shared SQLAlchemy metadata/database
for both processes. Both processes must use the same protected gateway
DATABASE_URL. The partner process needs access to that database internally,
but partner clients never receive its address or credentials. FlowSense RDS
credentials and AWS IAM permissions remain server-only and read-only.
