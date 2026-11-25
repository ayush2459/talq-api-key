# FlowSense Partner Backend Integration

Partners use only the restricted Partner API listener. They do not receive
Swagger, admin endpoints, admin credentials, database credentials, AWS access,
or access to the internal control-plane listener.

## 1. Submit onboarding request

Generate an RSA key pair locally (3072 bits recommended). Submit only the
public key to `POST /v1/onboarding/requests`:

```json
{
  "contact_name": "Partner Contact",
  "email": "partner@example.com",
  "organization": "Example Partner",
  "purpose": "Backend integration for approved FlowSense IoT data.",
  "client_address": "example-partner-01",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----"
}
```

The response contains `request_id` and a random `status_token`. Save the
status token securely. It is required in the `X-Onboarding-Token` header for
status checks and the one-time claim. The token expires after 72 hours.

## 2. Poll for approval

```http
GET /v1/onboarding/requests/{request_id}
X-Onboarding-Token: <private-status-token>
```

Possible statuses include `pending`, `approved`, `credentials_ready`,
`credentials_claimed`, and `rejected`.

## 3. Claim encrypted credentials

After FlowSense approves and provisions the integration, call:

```http
POST /v1/onboarding/requests/{request_id}/claim
X-Onboarding-Token: <private-status-token>
```

The response contains an encrypted credential envelope. It is encrypted with
a random AES-256-GCM key; that key is wrapped using the submitted RSA public
key with RSA-OAEP-SHA256. Decrypt it locally using the matching private key.
The private key is never sent to FlowSense. The claim can be used once and
expires 30 minutes after provisioning.

## 4. Authenticate and create a TALQ API key

Exchange the claimed Client ID and Client Secret at `POST /oauth/token`
using HTTP Basic authentication and `grant_type=client_credentials`. Request
only the scopes approved by FlowSense. Use the resulting Bearer token to call
`GET /integrations/me` and `POST /integrations/me/api-keys`.

Use the returned API key in `X-API-Key` for data calls, with
`talq-api-version: 2.7.1` and the exact approved `clientAddress` query
parameter. API keys expire after 30 days by default; rotate before expiry,
verify the replacement, then retire the old key.

## Security requirements

- Never request or use `X-Admin-Key`.
- Never call `/admin/*`, `/docs`, `/redoc`, `/openapi.json`, or legacy
  `/access-requests`; the partner listener returns 404 for these paths.
- Do not send the RSA private key to FlowSense.
- Keep status token, private key, Client Secret, OAuth tokens and API key in
  the partner's secret manager or protected local store. The reference client protects its private key with a passphrase and stores credentials in an encrypted local vault; do not commit the vault or its passphrase.
- Use HTTPS with certificate validation. CORS is not relevant to backend-to-
  backend calls.
- A successful authentication response does not guarantee live data mapping
  or TALQ certification. Validate data and interoperability with FlowSense.
