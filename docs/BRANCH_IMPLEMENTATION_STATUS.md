# Branch implementation status

Updated: 2026-11-24

This document records what is present in this Git branch. It deliberately
separates checked-in implementation from functionality demonstrated only in
a developer's local working copy.

## Verified in this branch

- FastAPI gateway scaffold and access-request approval workflow.
- OAuth 2.0 client-credentials endpoint.
- Partner integration provisioning and client-secret rotation.
- Partner-owned API-key creation, listing, rotation, retirement and revocation.
- Integration suspension, including revocation of outstanding OAuth tokens
  and partner-managed API keys.
- Token/API-key expiry and scope checks.
- Unit tests for the authentication and key lifecycle workflows.
- A LAN partner smoke-test script and setup documentation.

## Not yet verified in this branch

- Live AWS RDS device retrieval and facility-level device filtering.
- Facility authorization applied to measurement, alert, event and data-package
  endpoints.
- Live energy and water measurement queries.
- Live alert/anomaly and event queries.
- Production TALQ schema conformance or certification.
- End-to-end testing from a separate partner machine across the intended
  private LAN/VPN path.

The live device implementation demonstrated during local development must
be committed and tested on this branch before GitHub can be treated as the
source of truth for that working behavior. Do not replace it with placeholder
responses or mark live RDS integration complete based only on local results.

## Next implementation sequence

1. Synchronize the verified live-RDS device implementation from the developer
   working copy into this branch, including its required imports and
   configuration loading. Add isolated tests for the facility filter.
2. Add facility-scoped energy and water measurement retrieval with bounded
   time windows, pagination, and server-side SQL filtering.
3. Add facility-scoped alerts and events.
4. Replace any remaining demo data-package responses with real, authorized
   datasets.
5. Test token expiry/revocation, key rotation/retirement, integration
   suspension, facility-grant revocation and cross-partner isolation.
6. Run private-network interoperability and TALQ schema validation.

## Security and operating constraints

- Keep .env, database URLs, AWS credentials, OAuth client secrets, bearer
  tokens and raw API keys out of Git.
- The gateway must be reachable only through the intended private network;
  LAN binding alone is not a substitute for firewall/VPN controls.
- Partners receive gateway credentials only; they must not receive database
  credentials or direct Neon/AWS access.
- Use bounded queries and least-privilege read-only database access for
  operational data.
