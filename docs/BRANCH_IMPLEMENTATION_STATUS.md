# Branch implementation status

Updated: 2026-11-25

This document separates code implemented and CI-verified from deployment and
live FlowSense RDS checks that still require the private LAN environment.

## Implemented in this branch

### Partner/admin boundary
- Separate `app.admin_app:admin_app` loopback-only control-plane ASGI entry point.
- Separate `app.partner_app:partner_app` partner-facing ASGI entry point.
- Partner listener has no Swagger, ReDoc or OpenAPI and applies a strict
  HTTP-method/path allowlist.
- Partner listener returns 404 for admin routes, legacy onboarding routes,
  internal health diagnostics, docs and OpenAPI.
- Internal application docs are disabled; admin docs are served only through
  the loopback-guarded admin entry point.
- Windows startup launches admin on `127.0.0.1:8001` and partner API on the
  configured private LAN address at port 8000.
- Docker default serves only the allowlisted partner application.
- Windows Firewall helper creates a TCP 8000 allow rule for an approved
  partner IPv4; existing broad allow rules must still be reviewed.

### Partner onboarding and credentials
- Partner request endpoint accepts organization/contact details, TALQ
  clientAddress and partner-generated RSA public key.
- Partner receives a random status token; only its hash is stored.
- Partner can poll request status and claim credentials once.
- FlowSense admin approval and OAuth provisioning remain on the internal
  control plane.
- API-originated partner credentials are sealed with RSA-OAEP-SHA256 and
  AES-256-GCM; the admin provisioning response never returns the client
  secret in plaintext.
- Credential claims expire after 30 minutes; onboarding status tokens expire
  after 72 hours.
- OAuth client-secret rotation uses the same encrypted one-time claim flow for
  API-originated enrollments and revokes outstanding bearer tokens.
- Reference partner client protects its RSA private key and encrypted local
  credential vault with a passphrase.

### Authorization and operations
- OAuth 2.0 client credentials and short-lived bearer tokens.
- Partner-owned API key creation, listing, rotation, retirement and revocation.
- Scope enforcement for devices, energy/water measurements, alerts/events and
  data packages.
- Facility-level grants and server-side RDS filtering.
- Metadata-only onboarding audit trail for request, approval, rejection,
  provisioning, claim and secret rotation. No raw credentials are written to
  audit details.
- Admin-only audit endpoint:
  `GET /admin/onboarding/{request_id}/audit`.

### Data endpoints
- Facility-filtered device listing, count and individual device retrieval.
- Facility-filtered meter and numeric sensor readings.
- Facility-filtered FlowSense alerts.
- Alert lifecycle records exposed as events.
- Data packages assembled from partner-authorized scopes.
- Measurement/alert queries use bounded date ranges, server-side pagination
  and a maximum page size of 500.
- RDS uses the server-side IAM-authenticated read-only connection.

## CI verification

Latest GitHub Actions run for this branch:
- Run: https://github.com/ayush2459/talq-api-key/actions/runs/45570897066
- Result: **success**
- Tests: **20 passed, 1 warning**
- Python compile check: passed
- Dependency consistency check: passed

CI does not access the private LAN, AWS account or live FlowSense RDS.

## Required live acceptance before production

- Configure a private-CA TLS reverse proxy for the partner listener.
- Bind admin service only to loopback and partner service only to the private
  LAN interface.
- Restrict TCP 8000 to approved partner source IPs and review existing
  broad Windows Firewall allow rules.
- Verify a partner machine cannot access admin routes, docs, OpenAPI,
  database ports or the RDS endpoint.
- Submit an onboarding request from the partner machine, approve it from the
  internal control plane, provision scopes and assign facility grants.
- Claim and decrypt credentials on the partner machine; verify repeated claim
  is rejected.
- Verify OAuth token issuance, partner key lifecycle and secret rotation.
- Validate devices, measurements, alerts, events and data packages against
  direct read-only queries for the granted FlowSense facility.
- Provision two partners with different facility grants and prove neither can
  read the other's facility.
- Verify suspension and facility-grant revocation remove access immediately.
- Validate response models against the target CMS and TALQ 2.7.1 specification.
  This implementation is not TALQ-certified.

## Operational constraints

- Keep `.env`, database URLs, AWS credentials, onboarding tokens, private
  keys, OAuth secrets, bearer tokens and raw API keys out of Git.
- Partners receive only the Partner API; never provide admin or RDS access.
- Never expose the admin port 8001 to the LAN or public networks.
- Do not use plain HTTP for real credential exchange; TLS is required.
- Back up the gateway database before deployment or schema changes.
