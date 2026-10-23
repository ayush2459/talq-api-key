# FlowSense data-source contract for the TALQ adapter

This directory documents the inspected upstream contract and provides a read-only integration pattern. The gateway repository stays independent; it does not import the FlowSense application's Python modules or make changes to FlowSense's frontend, backend, MQTT pipeline, or schema.

Source repository: https://github.com/ayush2459/flowsense

## Verified PostgreSQL tables

The FlowSense schema at `db/schema.sql` and ORM in `backend/models.py` define the following objects:

| Source | Useful fields | Adapter use |
|---|---|---|
| `facilities` | `facility_id` UUID, `facility_code`, `facility_name`, `city`, `status` | Namespace and facility metadata |
| `meters` | `meter_id` UUID, `facility_id`, `meter_code`, `resource_type` (`energy` / `water`), `unit`, `status` | Main energy/water meters |
| `iot_devices` | `iot_device_id` UUID, `facility_id`, `device_code`, `device_model`, `firmware_version`, `status`, `last_seen_at` | TALQ device identity/status mapping |
| `iot_sensors` | `sensor_id` UUID, `iot_device_id`, `sensor_code`, `sensor_type`, `measurement`, `unit`, `data_type`, `source_meter_id`, `status` | Sensor-function/attribute mapping |
| `meter_readings` | `meter_id`, `reading_time`, `reading_value`, `quality_status`, `source` | Meter observations |
| `sensor_readings` | `sensor_id`, `reading_time`, `numeric_value`, `boolean_value`, `quality_status` | Sensor observations and timestamps |
| `resource_reconciliation` | `facility_id`, `resource_type`, `reconciliation_time`, meter/observed/expected/unaccounted values, loss and status | Facility analytics, not automatically a raw sensor observation |
| `anomalies` | UUID, facility/device/sensor/meter refs, type, resource, severity, timestamp, actual/expected value, estimated loss, status | Event/alert candidate mapping |
| `alerts` | UUID, anomaly/facility refs, title/message, severity, time, status | Alert/event candidate mapping |

The schema seeds measurements with units including kWh, kW, V, A, ratio, L/min, kL, bar, °C, humidity percent, and vibration mm/s. Confirm actual hardware semantics and whether values are instantaneous, cumulative, or interval totals before exposing them as TALQ attributes.

## Existing read-only API paths

The backend's `backend/main.py` registers routes including:

- `GET /api/facilities`
- `GET /api/facilities/{facility_code}/summary`
- `GET /api/facilities/{facility_code}/anomalies`
- `GET /api/anomalies/recent`
- `GET /api/facilities/{facility_code}/reconciliation`
- `GET /api/facilities/{facility_code}/yearly-summary`
- `GET /api/facilities/{facility_code}/energy`
- `GET /api/facilities/{facility_code}/water`
- `GET /api/devices`
- `GET /api/devices/{device_code}/health`

These are FlowSense REST APIs, not TALQ operations. Route availability in source does not prove a production URL is reachable or authenticated.

## Proposed safe integration approach

1. Use a separate, read-only database credential for the gateway, restricted to specific tables/views needed by the adapter. Never reuse a superuser or paste secrets into code.
2. Prefer parameterized queries against stable source tables, or add a narrowly scoped read-only FlowSense API if direct DB access is unsuitable.
3. Use UUIDs for persistent identity. TALQ `clientAddress` is the CMS UUID; it is not the organization slug, device address, hostname, or IP.
4. Define and version a mapping registry from FlowSense facilities/devices/sensors to TALQ resource addresses and model functions/attributes.
5. Preserve timestamps, units, quality status and numeric/boolean distinctions. Never convert resource reconciliation values into sensor readings without clearly labelling their semantics.
6. Don't register every environmental sensor under a lighting profile automatically. Select and implement the TALQ profile(s) supported by the actual deployment; the profile determines mandatory operations.
7. Keep partner API-key authorization separate from TALQ payload/schema validation.

## Important limitations

This repository does not expose FlowSense production database credentials or deploy configuration. This document derives from source schema and route inspection only. The adapter has not been run against a live FlowSense database, and it is not TALQ-certified.
