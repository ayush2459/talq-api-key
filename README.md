# FlowSense TALQ Gateway

Pilot scaffold for exploring a subset of TALQ Gateway API patterns with FastAPI.

> **Status:** prototype scaffold only. This repository is not a fully conformant or TALQ-certified implementation. It uses placeholder/demo data and requires protocol-schema validation, security review, and integration with real FlowSense device readings before production use.

## Local setup (Windows PowerShell)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and set a unique, long `FLOWSENSE_API_KEY`. Never commit `.env` or publish the key.

```powershell
.\RUN_WINDOWS.ps1
```

Visit `http://127.0.0.1:8000/docs` and `http://127.0.0.1:8000/health`.

To run tests, install test dependencies in your virtual environment with `.\.venv\Scripts\python.exe -m pip install pytest httpx`, then run `.\.venv\Scripts\python.exe -m pytest -q`.

## Render deployment

A `Dockerfile` and `render.yaml` Blueprint are provided. Import this GitHub repository into Render and create the web service from the Blueprint. Set `FLOWSENSE_API_KEY` to a new, strong secret in Render's Environment settings. Keep `TALQ_CLIENT_ADDRESS` empty unless you know the permitted CMS client address and want to restrict it. Do not put secrets in GitHub.

## Pilot endpoints

- `GET /health` — public health probe
- `GET /integration-status` — requires `X-API-Key`
- `GET /devices`
- `GET /devices/count`
- `GET /devices/{deviceAddress}`
- `GET /services`
- `GET /services/{serviceName}`
- `GET /data-packages`

Protected routes require `X-API-Key`, `talq-api-version: 2.7.1`, and the `clientAddress` query parameter. These are pilot routes and response payloads; verify every route and schema against the exact TALQ specification and target CMS before integration.

## Next engineering milestones

1. Map real FlowSense sensor and meter data into the official TALQ data model.
2. Validate schemas and mandatory operations against official TALQ 2.7.1 materials.
3. Review authentication, TLS, client identity, access control, rate limits, and logs.
4. Add integration tests against the intended CMS.
