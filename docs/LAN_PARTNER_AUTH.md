# LAN-only third-party integration (development branch)

This branch adds a backend-to-backend OAuth 2.0 Client Credentials flow and a
partner-owned TALQ API-key lifecycle. No partner website or dashboard is
required. The partner runs a program on its own server and calls FlowSense
over the private LAN.

## Flow

1. A partner submits an access request through `POST /access-requests`.
2. A FlowSense administrator reviews it and approves it using the existing
   `POST /admin/access-requests/{request_id}/approve` endpoint.
3. The administrator provisions OAuth credentials using
   `POST /admin/integrations/{request_id}/provision`. The client secret is
   returned once.
4. The partner exchanges its Client ID and Client Secret for a short-lived
   OAuth token at `POST /oauth/token`.
5. The partner creates its own gateway key at
   `POST /integrations/me/api-keys`.
6. The partner calls protected gateway endpoints with `X-API-Key`.
7. Before expiry, the partner rotates its key, tests the replacement, and
   retires the previous key.

## New endpoints

| Method | Endpoint | Authentication |
|---|---|---|
| POST | `/admin/integrations/{request_id}/provision` | FlowSense admin key |\n| POST | `/admin/integrations/{integration_id}/suspend` | FlowSense admin key |
| POST | `/oauth/token` | HTTP Basic client credentials |
| GET | `/integrations/me` | OAuth Bearer token |
| POST | `/integrations/me/api-keys` | Bearer token with `keys:manage` |
| GET | `/integrations/me/api-keys` | Bearer token with `keys:manage` |
| POST | `/integrations/me/api-keys/{key_id}/rotate` | Bearer token with `keys:manage` |
| POST | `/integrations/me/api-keys/{key_id}/retire` | Bearer token with `keys:manage` |
| POST | `/integrations/me/api-keys/{key_id}/revoke` | Bearer token with `keys:manage` |

## LAN setup (Windows PowerShell)

Run this on the FlowSense LAN server. Bind to the LAN interface only when
private-network access is intended:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Set a strong, private `ADMIN_API_KEY` in `.env`. Keep `.env` out of Git.
For a LAN server with a private PostgreSQL connection, set `DATABASE_URL`
to that server-side connection string. Do not expose database credentials
to partner machines.

Start the app on the LAN interface:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Use the server's private LAN address from partner machines, for example
`http://192.168.1.10:8000`. The IP and port are examples; use the actual
LAN configuration. Restrict inbound access with the host firewall. For
sensitive or production use, terminate TLS on the private network as well.

## Provision a partner

First create a request through `POST /access-requests`, then approve it with
the existing admin endpoint. Provision the OAuth client after approval:

```http
POST /admin/integrations/1/provision
X-Admin-Key: <ADMIN_API_KEY>
Content-Type: application/json

{
  "scopes": ["devices:read", "energy:read"]
}
```

Save the returned `client_id` and `client_secret` securely. The secret is
not stored in plaintext and cannot be retrieved later. The admin chooses the
partner data scopes during provisioning; if omitted, only `devices:read` is
approved by default. `keys:manage` is added for the partner key lifecycle.

## Run the independent partner test client

On a separate machine/process on the same LAN, configure these environment
variables. Use the exact approved client address from the access request:

```powershell
$env:FLOWSENSE_BASE_URL = "http://192.168.1.10:8000"
$env:FLOWSENSE_CLIENT_ID = "<client_id>"
$env:FLOWSENSE_CLIENT_SECRET = "<client_secret>"
$env:FLOWSENSE_CLIENT_ADDRESS = "<approved-client-address>"
```

Run:

```powershell
py scripts/lan_partner_smoke_test.py
```

The script obtains an OAuth token, creates or rotates a gateway key, verifies
the new key against `/auth/verify` and `/devices`, saves the test key to the
local ignored file `.partner-key.json`, and retires the previous key only
after the replacement passes verification.

## Security behavior

- OAuth access tokens expire after 1 hour.
- Partner API keys expire after 30 days by default.
- API keys and OAuth tokens are stored as SHA-256 hashes; plaintext is returned
  only at creation/rotation.
- A rotated key remains active until the partner verifies the replacement
  and explicitly retires the previous key.
- API keys are tied to the approved partner client address and carry data scopes.
- Each partner can list, rotate, retire, or revoke only its own keys.
- Admins can suspend an integration; outstanding OAuth tokens and partner API keys are revoked.\n- The existing admin key is never given to a partner.
- Do not commit `.env`, `.partner-key.json`, or any real credentials.

## Important current limitations

- This is a development implementation and must be tested on a clean local
  database before use with the existing RDS database.
- The new tables are created by SQLAlchemy `create_all`; no existing tables
  are altered. Back up the database before deployment.
- The current TALQ device/data routes still return pilot placeholder data.
  Successful authentication does not mean live meter/sensor data has been
  mapped yet.
- The gateway scaffold is not a claim of full TALQ 2.7.1 conformance or
  certification. Validate required models and operations against the actual
  TALQ specification and target CMS.
- This branch does not configure a recurring scheduler. The partner-side
  script demonstrates rotation; production partner software should schedule
  it before the 30-day expiry and persist secrets in a secrets manager.
