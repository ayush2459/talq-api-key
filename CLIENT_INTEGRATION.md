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
  "client_address": "partner-system-01"
}
```

The response contains a request ID. A request does not grant access until the gateway administrator approves it.

## 2. Administrator approves the request

Use Swagger UI or an HTTP client to call:

`POST /admin/access-requests/{request_id}/approve`

Include the secret admin header `X-Admin-Key`. The response contains the client API key once. The administrator must securely send that key to the partner through an approved secret-sharing channel. Never send the admin key to the partner.

## 3. Verify the key

```http
GET /auth/verify
X-API-Key: <issued-client-api-key>
```

A successful response confirms authentication and returns safe metadata for the organization and registered client address. A missing, invalid, or revoked key returns HTTP 401.

## 4. Call a gateway route

```http
GET /devices?clientAddress=partner-system-01
X-API-Key: <issued-client-api-key>
talq-api-version: 2.7.1
```

Use the exact `clientAddress` approved for that API key. Gateway routes that require TALQ-style headers reject a mismatched address.

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

Configure `FLOWSENSE_GATEWAY_URL`, `FLOWSENSE_API_KEY`, and `FLOWSENSE_CLIENT_ADDRESS` as environment variables on the partner backend. Do not hard-code credentials.

## Important scope limitation

The gateway currently authenticates callers, but `/devices` and `/data-packages` return empty placeholder collections until real FlowSense device/meter data is connected and mapped. Successful authentication therefore does not yet mean live FlowSense data is available. The current scaffold is not a complete or TALQ-certified implementation; confirm the required TALQ operations and payload schemas with the target CMS before production use.


## TALQ clientAddress requirement

For TALQ 2.7.1 Gateway operations, the `clientAddress` query parameter is the **CMS address** and must be a UUID. Ask the partner to provide the stable UUID configured for its CMS; do not use a company slug, hostname, or IP address. The gateway binds that UUID to the approved API key. Example only: `00000000-0000-4000-8000-000000000001` (replace with the partner's real CMS UUID).
