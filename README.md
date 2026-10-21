# FlowSense TALQ Gateway

**An IoT interoperability gateway for integrating FlowSense water and energy monitoring systems with TALQ-compatible smart-city management platforms.**

FlowSense TALQ Gateway is a FastAPI-based pilot project designed to explore how FlowSense device and meter data can be exposed through a standardized gateway interface for integration with external Central Management Software (CMS).

The project establishes an initial API foundation for device discovery, service discovery, data-package access, and secure API access. Its long-term objective is to bridge FlowSense's IoT monitoring infrastructure with interoperable smart-city platforms using the [TALQ Consortium's specifications](https://github.com/TALQ-consortium/TALQ_specification).

> **Project status:** Prototype / pilot scaffold. This repository is not a complete, validated, or TALQ-certified implementation. Device data and data packages are currently placeholders. Full schema validation, real FlowSense integration, and security hardening are required before production use.

---

## Table of Contents

- [Overview](#overview)
- [Objectives](#objectives)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [API Endpoints](#api-endpoints)
- [Authentication and Security](#authentication-and-security)
- [Getting Started](#getting-started)
- [Running Tests](#running-tests)
- [Deployment on Render](#deployment-on-render)
- [Current Limitations](#current-limitations)
- [Development Roadmap](#development-roadmap)
- [References](#references)

## Overview

FlowSense is an IoT-based monitoring concept for tracking energy and water consumption, identifying anomalies, and generating actionable operational insights.

The TALQ Gateway pilot explores an interoperability layer between FlowSense and external management platforms. Rather than requiring every client to integrate directly with FlowSense's internal data services, a gateway can provide a defined interface through which authorized clients discover devices, inspect available services, and retrieve relevant data.

### Key capabilities

- **Device discovery:** Initial endpoints for listing devices, counting devices, and retrieving a device by address.
- **Service discovery:** Exposes a list of available gateway services.
- **Data-package access:** Provides an initial endpoint for exposing data packages.
- **API access control:** Protects gateway endpoints using an API key.
- **Protocol version identification:** Checks the requested TALQ API version for protected gateway requests.
- **Client identification:** Requires a `clientAddress` query parameter and supports an optional configured client-address restriction.
- **Health monitoring:** Provides a public health endpoint for deployment monitoring.
- **Cloud deployment foundation:** Includes Docker and Render configuration.

## Objectives

1. Establish an API foundation for FlowSense-to-CMS interoperability.
2. Explore the relevant TALQ Gateway API patterns and request conventions.
3. Create a modular service that can later connect to actual FlowSense meter and sensor data.
4. Introduce basic authentication and configuration management.
5. Enable repeatable local development, automated testing, and cloud deployment.
6. Build toward schema-validated integration with a compatible Central Management Software platform.

## Architecture

The intended integration architecture is:

```text
FlowSense IoT Devices and Meters
              |
              v
   FlowSense Data Services
   (Sensors, Meter Readings,
    Database and Processing)
              |
              v
     FlowSense TALQ Gateway
        (FastAPI Service)
              |
       API Authentication
       and Request Validation
              |
              v
   TALQ-Compatible CMS Client
```

**Current implementation:** The FastAPI application exposes a limited set of gateway-style routes. The device and data-package collections are empty placeholders, and the application does not yet connect to real FlowSense sensors, MQTT, or a production database.

**Target implementation:** Integrate live FlowSense data, map it to the applicable TALQ data model, validate requests and responses against the official specification, and test interoperability with the intended CMS.

## Technology Stack

| Component | Technology |
|---|---|
| Backend framework | FastAPI |
| Programming language | Python 3.11 |
| API server | Uvicorn |
| API documentation | OpenAPI / Swagger UI |
| API access control | Shared API key |
| Containerization | Docker |
| Deployment configuration | Render Blueprint |
| Automated testing | pytest and FastAPI TestClient |
| Interoperability reference | TALQ Consortium specifications |

## API Endpoints

The current pilot exposes the following routes.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/integration-status` | View pilot integration status |
| `GET` | `/devices` | List configured devices |
| `GET` | `/devices/count` | Count configured devices |
| `GET` | `/devices/{deviceAddress}` | Retrieve a device by address |
| `GET` | `/services` | List available services |
| `GET` | `/services/{serviceName}` | Retrieve a service entry |
| `GET` | `/data-packages` | List configured data packages |

Protected routes require the `X-API-Key` header, the `talq-api-version: 2.7.1` header, and the `clientAddress` query parameter.

These are currently pilot endpoint implementations. Their presence and request conventions do **not** establish full conformance with TALQ 2.7.1. Request and response schemas, mandatory operations, error behavior, and security requirements must be validated against the official specification.

### Example health-check request

```http
GET /health
```

Example response:

```json
{
  "status": "ok",
  "service": "FlowSense TALQ Gateway",
  "environment": "production"
}
```

### Example protected request

```http
GET /devices?clientAddress=test-client
X-API-Key: YOUR_API_KEY
talq-api-version: 2.7.1
```

The current device collection is empty until actual or explicitly configured device records are added.

## Authentication and Security

The pilot uses an API key to restrict access to protected routes.

### Current safeguards

- API key supplied through an environment variable.
- Authentication for protected endpoints.
- Constant-time API-key comparison.
- Optional restriction to a configured client address.
- Environment-based configuration.
- `.env` exclusion through `.gitignore`.
- Docker-based deployment configuration.

### Production security requirements

Before connecting an external CMS or real IoT infrastructure, the service should be enhanced with:

- HTTPS/TLS and appropriate certificate management.
- Authentication and client identity mechanisms compatible with the target TALQ implementation.
- Least-privilege access controls and secret rotation.
- Request validation, rate limiting, and abuse protection.
- Structured audit logs and monitoring.
- Secure error handling and dependency updates.
- Appropriate network restrictions and production environment configuration.

The current shared API-key mechanism is a pilot safeguard; it should not be assumed to satisfy every TALQ security requirement.

## Getting Started

### Prerequisites

- Python 3.11
- Git
- Windows PowerShell or another supported terminal
- Internet access for installing dependencies

### 1. Clone the repository

```powershell
git clone https://github.com/ayush2459/talq-api-key.git
cd talq-api-key
```

### 2. Create a virtual environment

```powershell
py -3.11 -m venv .venv
```

### 3. Install dependencies

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 4. Configure environment variables

Create a local environment file:

```powershell
Copy-Item .env.example .env
```

Generate a strong API key:

```powershell
py -c "import secrets; print(secrets.token_urlsafe(48))"
```

Open `.env` and configure it:

```dotenv
FLOWSENSE_API_KEY=replace-with-your-generated-secret
TALQ_CLIENT_ADDRESS=
DEMO_MODE=true
```

Replace the example API key with the generated secret. Keep `.env` private and never commit it to GitHub.

### 5. Start the application

```powershell
.\RUN_WINDOWS.ps1
```

### 6. Open the API documentation

Once the server starts, visit:

- **Swagger UI:** http://127.0.0.1:8000/docs
- **Health check:** http://127.0.0.1:8000/health

Swagger UI provides an interactive way to inspect endpoints and send test requests.

## Running Tests

Install the test dependencies into the project's virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pip install pytest httpx
```

Run the test suite:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The initial four-test suite covers basic health-check behavior, API-key enforcement, required TALQ-style request parameters, and service discovery.

A successful local run previously reported **4 passed**. This validates the tested pilot behaviors only; it is not a substitute for full protocol conformance or CMS integration testing.

## Deployment on Render

The repository includes a `Dockerfile` and `render.yaml` for a Render Blueprint deployment.

### Deployment procedure

1. Sign in to [Render](https://dashboard.render.com/).
2. Connect your GitHub account.
3. Create a new Blueprint and select `ayush2459/talq-api-key`.
4. Review the service configuration from `render.yaml`.
5. Configure `FLOWSENSE_API_KEY` as a strong secret in Render.
6. Keep `DEMO_MODE=true` until real data integration and validation are complete.
7. Deploy and inspect the build logs.
8. Open the deployed `/health` endpoint to verify service availability.

The deployment URL will be assigned by Render.

**Deployment note:** A successful deployment means the web service is running. It does not mean that the gateway is certified, interoperable with a particular CMS, or connected to real FlowSense data.

## Current Limitations

The current pilot is intentionally limited:

- Device and data-package collections contain no real records.
- No live MQTT ingestion or sensor integration is implemented.
- No production database integration is implemented.
- TALQ request and response schemas have not been fully validated.
- Only a subset of gateway-style routes is implemented.
- The API-key mechanism is not a complete TALQ security implementation.
- Interoperability with an external CMS has not been demonstrated.
- TALQ certification has not been obtained.

These limitations define the remaining engineering work rather than implying functionality that has not yet been built.

## Development Roadmap

### Phase 1 — Gateway foundation
- [x] FastAPI application scaffold
- [x] Initial gateway-style routes
- [x] API-key protection
- [x] Environment configuration
- [x] Basic automated tests
- [x] Docker and Render deployment files

### Phase 2 — FlowSense integration
- [ ] Connect the gateway to actual FlowSense services and database records.
- [ ] Map energy and water meter readings to the appropriate data model.
- [ ] Implement device identity, status, and data retrieval from real records.
- [ ] Add validation for missing, invalid, and stale readings.

### Phase 3 — TALQ interoperability
- [ ] Validate the required operations and payloads against the official TALQ specification.
- [ ] Implement applicable request and response schemas.
- [ ] Verify error responses, pagination, and protocol-specific behavior where required.
- [ ] Test against the intended CMS and its supported TALQ version.

### Phase 4 — Production readiness
- [ ] Harden authentication and transport security.
- [ ] Add observability, audit logging, and operational alerts.
- [ ] Add integration and regression tests.
- [ ] Document deployment, recovery, and secret-rotation procedures.
- [ ] Evaluate formal conformance and certification requirements.

## References

- **GitHub repository:** https://github.com/ayush2459/talq-api-key
- **TALQ Consortium specification repository:** https://github.com/TALQ-consortium/TALQ_specification
- **FastAPI documentation:** https://fastapi.tiangolo.com/
- **Render documentation:** https://render.com/docs

---

**Built as an interoperability foundation for FlowSense.** The next milestone is to connect real FlowSense meter and sensor data, validate the applicable TALQ schemas, and demonstrate interoperability with a compatible CMS.
