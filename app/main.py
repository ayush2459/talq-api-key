"""FlowSense TALQ Gateway pilot scaffold (not certified or fully conformant)."""

import os
import secrets
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import JSONResponse

APP_ENV = os.getenv("APP_ENV", "production")
EXPECTED_API_KEY = os.getenv("FLOWSENSE_API_KEY", "").strip()
EXPECTED_CLIENT_ADDRESS = os.getenv("TALQ_CLIENT_ADDRESS", "").strip()
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"

app = FastAPI(
    title="FlowSense TALQ Gateway (pilot scaffold)",
    version="0.1.0",
    description=(
        "Pilot scaffold exposing a small subset of TALQ-style gateway routes. "
        "Not a complete TALQ implementation or certification claim."
    ),
)

# Deliberately empty until real FlowSense device data is mapped and validated.
DEMO_DEVICES: list[dict[str, Any]] = []
DEMO_DATA_PACKAGES: list[dict[str, Any]] = []
SERVICES = ["device-management", "measurements", "events"]


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    if not EXPECTED_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server API key is not configured",
        )
    if not x_api_key or not secrets.compare_digest(x_api_key, EXPECTED_API_KEY):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key")


def require_talq_headers(
    talq_api_version: str | None = Header(default=None, alias="talq-api-version"),
    client_address: str = Query(..., alias="clientAddress"),
) -> str:
    if talq_api_version != "2.7.1":
        raise HTTPException(status_code=400, detail="talq-api-version must be 2.7.1")
    if EXPECTED_CLIENT_ADDRESS and client_address != EXPECTED_CLIENT_ADDRESS:
        raise HTTPException(status_code=403, detail="Unapproved clientAddress")
    return client_address


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok", "service": "FlowSense TALQ Gateway", "environment": APP_ENV}


@app.get("/integration-status", dependencies=[Depends(require_api_key)])
def integration_status() -> dict[str, Any]:
    return {
        "status": "pilot",
        "demo_mode": DEMO_MODE,
        "device_count": len(DEMO_DEVICES),
        "data_package_count": len(DEMO_DATA_PACKAGES),
        "notes": [
            "This is a limited pilot scaffold, not a complete TALQ implementation.",
            "Real FlowSense data mapping and official schema validation are still required.",
        ],
    }


@app.get("/devices", dependencies=[Depends(require_api_key)])
def list_devices(
    client_address: str = Depends(require_talq_headers),
) -> dict[str, Any]:
    return {"devices": DEMO_DEVICES, "clientAddress": client_address}


@app.get("/devices/count", dependencies=[Depends(require_api_key)])
def count_devices(client_address: str = Depends(require_talq_headers)) -> dict[str, Any]:
    return {"count": len(DEMO_DEVICES), "clientAddress": client_address}


@app.get("/devices/{deviceAddress}", dependencies=[Depends(require_api_key)])
def get_device(
    deviceAddress: str,
    client_address: str = Depends(require_talq_headers),
) -> JSONResponse:
    for device in DEMO_DEVICES:
        address = device.get("deviceAddress") or device.get("address")
        if address == deviceAddress:
            return JSONResponse({"device": device, "clientAddress": client_address})
    raise HTTPException(status_code=404, detail="Device not found in configured gateway data")


@app.get("/services", dependencies=[Depends(require_api_key)])
def list_services(client_address: str = Depends(require_talq_headers)) -> dict[str, Any]:
    return {"services": SERVICES, "clientAddress": client_address}


@app.get("/services/{serviceName}", dependencies=[Depends(require_api_key)])
def get_service(
    serviceName: str,
    client_address: str = Depends(require_talq_headers),
) -> dict[str, Any]:
    if serviceName not in SERVICES:
        raise HTTPException(status_code=404, detail="Service not found")
    return {"serviceName": serviceName, "available": True, "clientAddress": client_address}


@app.get("/data-packages", dependencies=[Depends(require_api_key)])
def list_data_packages(
    client_address: str = Depends(require_talq_headers),
) -> dict[str, Any]:
    return {"dataPackages": DEMO_DATA_PACKAGES, "clientAddress": client_address}
