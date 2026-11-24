# Branch implementation status

Updated: 2026-11-24

This document distinguishes checked-in implementation from behavior that still
requires verification against the live FlowSense RDS instance and a separate
partner machine.

## Implemented in this branch

- FastAPI gateway scaffold and approval-based access request workflow.
- OAuth 2.0 client-credentials endpoint and partner provisioning.
- Client-secret rotation, OAuth token expiry/revocation, and integration suspension.
- Partner-owned API-key creation, listing, rotation, retirement, and revocation.
- Scope enforcement for device, measurement, alert/event, and data-package routes.
- Facility grants with active/revoked state and partner-specific facility lookup.
- RDS IAM-authenticated, read-only connection module.
- Facility-filtered device listing, count, and individual device retrieval.
- Facility-filtered meter and numeric sensor readings through `GET /measurements`.
- Facility-filtered FlowSense alerts through `GET /alerts`.
- Alert lifecycle records exposed as events through `GET /events`.
- Data packages assembled from the authenticated partner's authorized scopes.
- Measurement/alert queries use server-side facility filters, bounded date ranges,
  pagination, and a maximum page size of 500.
- Unit tests cover OAuth/key lifecycle and facility/scope/time-window boundaries.
- LAN partner smoke-test script and setup documentation.

## Still requires live/environment verification

- Connect from the configured gateway host to the actual AWS RDS instance using
  the intended IAM role/profile and verify the connection is read-only.
- Confirm the live database's resource_type and sensor measurement values map
  to the energy/water classifications used by the measurement query.
- Exercise device, measurement, alert, event, and data-package endpoints against
  representative real facilities and compare returned rows with direct read-only
  database queries.
- Verify facility-grant revocation immediately removes access to every RDS route.
- Verify two partner integrations cannot read one another's facility data.
- Run the independent partner smoke test from a separate machine over the
  intended private LAN/VPN path.
- Validate request/response models against the target CMS and the official TALQ
  2.7.1 specification. This branch is not TALQ-certified.

## Data source and query behavior

- Meter readings use `meter_readings` joined to `meters` and `facilities`.
- Numeric sensor readings use `sensor_readings` joined to `iot_sensors`,
  `iot_devices`, and `facilities`, with optional source-meter classification.
- Alerts use `alerts` joined to `facilities`; the known alert lifecycle fields
  are returned without assuming additional anomaly columns.
- `/events` currently presents alert lifecycle records as events. No separate
  events table has been assumed.
- Measurement and alert windows default to seven days and are capped at 90 days.
- Pagination is server-side; page size is limited to 500.
- Legacy keys without an OAuth-managed integration and active facility grants
  receive no FlowSense RDS data.

## Next implementation sequence

1. Deploy with the correct server-side `FLOW_SENSE_DATABASE_URL`, AWS region,
   and IAM identity; verify read-only RDS connectivity.
2. Validate energy/water classification against live meter and sensor metadata.
3. Run the partner smoke test and cross-partner isolation tests against live RDS.
4. Complete target-CMS/TALQ schema mapping and interoperability validation.
5. Review firewall/VPN restrictions, TLS termination, operational logging,
   backups, credential rotation, and deployment monitoring before production.

## Security and operating constraints

- Keep `.env`, database URLs, AWS credentials, OAuth client secrets, bearer
  tokens, and raw API keys out of Git.
- Partners receive gateway credentials only; never give partners RDS credentials.
- RDS queries use read-only transactions and facility filters on the server.
- The gateway must be reachable only through the intended private network;
  LAN binding alone is not a substitute for firewall/VPN controls.
- Keep query windows and result sizes bounded.
