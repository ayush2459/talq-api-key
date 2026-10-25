# Client Backend Integration Guide

Base URL:
- Production: `https://flowsense-talq-gateway.onrender.com`
- Local development: `http://127.0.0.1:8000`

This is server-to-server HTTPS authentication. CORS is not required for calls made directly from one backend to another. Do not expose the API key in browser code, frontend JavaScript, URLs, or logs.

## 1. Request access

Send `POST /access-requests` with JSON:

```json
{
  "contact_name": "Integration Contact",
  "email": "integration@example.com",
  "organization": "Partner Organization",
  "purpose": "Backend integration with FlowSense gateway",
  "client_address": "00000000-0000-4000-8000-000000000001"
}
```

Use the real, stable UUID configured for the partner CMS as `client_address`. Do not use a company slug, hostname, or IP address. The endpoint sends a one-time verification token to the supplied email. The token expires after 30 minutes by default. A request does not issue a key until the email is verified.

## 2. Verify email and receive a key automatically

The email contains a token. Exchange it by calling:

```http
POST /verify-email
Content-Type: application/json

{"token": "<token-from-verification-email>"}
```

A successful response contains `api_key`, `api_key_id`, `client_address`, `created_at`, `expires_at`, and `lifetime_days`. **Copy the API key immediately**; it is returned once only. The gateway stores only the key hash. There is no manual administrator approval step.

The verification token is single-use. An invalid, expired, or previously used token is rejected.

## 3. Verify the key

```http
GET /auth/verify
X-API-Key: <issued-client-api-key>
```

A successful response confirms authentication and returns safe metadata for the organization and registered client address. A missing, invalid, or revoked key returns HTTP 401.

## 4. Call a gateway route

```http
GET /devices?clientAddress=00000000-0000-4000-8000-000000000001
X-API-Key: <issued-client-api-key>
talq-api-version: 2.7.1
```

Use the exact CMS UUID registered with that API key. Gateway routes that require TALQ-style headers reject a mismatched address.

## 5. Python example

```python
import os
import urllib.error
import urllib.request

BASE_URL = os.environ["FLOWSENSE_GATEWAY_URL"].rstrip("/")
API_KEY = os.environ["FLOWSENSE_API_KEY"]
CLIENT_ADDRESS = os.environ["FLOWSENSE_CLIENT_ADDRESS"]

def get_json(path: str):
    request = urllib.request.Request(
        f"{BASE_URL}{path}",
        headers={
            "X-API-Key": API_KEY,
            "talq-api-version": "2.7.1",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.read().decode("utf-8")

# Verify authentication first. This route does not require TALQ headers.
verify_request = urllib.request.Request(
    f"{BASE_URL}/auth/verify",
    headers={"X-API-Key": API_KEY, "Accept": "application/json"},
)
with urllib.request.urlopen(verify_request, timeout=15) as response:
    print(response.read().decode("utf-8"))

# Then call a gateway route using the approved clientAddress.
print(get_json(f"/devices?clientAddress={CLIENT_ADDRESS}"))
```

Configure `FLOWSENSE_GATEWAY_URL`, `FLOWSENSE_API_KEY`, and `FLOWSENSE_CLIENT_ADDRESS` as environment variables on the partner backend. Do not hard-code credentials. Keys expire after 90 days by default; the `expires_at` value in the issuance response is authoritative. Obtain a new key by repeating email verification before expiry and update the secret in your backend.

## Important scope limitation

The gateway currently authenticates callers, but `/devices` and `/data-packages` return empty placeholder collections until real FlowSense device/meter data is connected and mapped. Successful authentication therefore does not yet mean live FlowSense data is available. The current scaffold is not a complete or TALQ-certified implementation; confirm the required TALQ operations and payload schemas with the target CMS before production use.


## TALQ clientAddress requirement

For TALQ 2.7.1 Gateway operations, the `clientAddress` query parameter is the **CMS address** and must be a UUID. Ask the partner to provide the stable UUID configured for its CMS; do not use a company slug, hostname, or IP address. The gateway binds that UUID to the approved API key. Example only: `00000000-0000-4000-8000-000000000001` (replace with the partner's real CMS UUID).


## API-key lifetime and errors

- Default API-key lifetime: 90 days (`API_KEY_LIFETIME_DAYS`).
- Email verification token lifetime: 30 minutes (`EMAIL_VERIFICATION_MINUTES`).
- Expired or revoked API keys return HTTP 401. The client should stop retrying with the same key and obtain a fresh key through the email-verification flow.
- The gateway's administrator can inspect key metadata and expiration with `GET /admin/api-keys`, and revoke a key with `POST /admin/api-keys/{key_id}/revoke`. The administrator key is never sent to the partner.
- The gateway owner must configure SMTP variables (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL`, and `SMTP_USE_STARTTLS`) in the deployment secret settings. Do not put SMTP credentials in source control.
- Before deploying over an existing PostgreSQL database, back it up and apply `migrations/001_email_verification_and_key_expiration.postgresql.sql`. Existing keys are assigned an expiration 90 days after their original creation time.
