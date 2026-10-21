# FlowSense TALQ Gateway

Pilot scaffold for exploring a subset of TALQ Gateway API patterns with FastAPI.

> **Status:** prototype scaffold only. This repository is not a fully conformant or TALQ-certified implementation. It uses placeholder/demo data and requires protocol-schema validation, security review, and integration with real FlowSense device readings before production use.

## Run locally (Windows PowerShell)

1. Create and activate a virtual environment:

   ```powershell
   py -3.11 -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   Copy-Item .env.example .env
   ```

2. Edit `.env` and set a unique `FLOWSENSE_API_KEY`. Do not commit `.env` or share the key.

3. Start the service:

   ```powershell
   .\RUN_WINDOWS.ps1
   ```

4. Browse to `http://127.0.0.1:8000/docs` and `http://127.0.0.1:8000/health`.

5. Run tests:

   ```powershell
   .\.venv\Scripts\python.exe -m pytest -q
   ```

## Deployment

The repository includes a Dockerfile and Render Blueprint (`render.yaml`). Import this repository into Render as a **Web Service** using the Docker runtime. Set `FLOWSENSE_API_KEY` to a strong random secret. Keep `TALQ_CLIENT_ADDRESS` blank unless the expected client address is known and you need to restrict requests. Do not put secrets in GitHub.

## Implemented pilot endpoints

The scaffold provides `/health`, `/integration-status`, and a limited set of gateway-style routes: `/devices`, `/devices/count`, `/devices/{deviceAddress}`, `/services`, `/services/{serviceName}`, and `/data-packages`. These routes are a starting point, not a guarantee of TALQ 2.7.1 conformance.

## Next steps before real CMS integration

- Map actual FlowSense readings and devices into the official TALQ model.
- Validate request/response schemas and required operations against the official TALQ specification.
- Review authentication, TLS, client identity, access control, and logging for deployment.
- Add integration tests with the intended Central Management Software (CMS).
