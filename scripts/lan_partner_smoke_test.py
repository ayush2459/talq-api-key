"""LAN smoke-test client for the FlowSense partner OAuth/key lifecycle.

Configure FLOWSENSE_BASE_URL, FLOWSENSE_CLIENT_ID, FLOWSENSE_CLIENT_SECRET,
and FLOWSENSE_CLIENT_ADDRESS in the local shell. This script is for controlled
LAN testing; partner production systems should use a proper secret manager.
"""
import base64
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BASE_URL = os.environ["FLOWSENSE_BASE_URL"].rstrip("/")
CLIENT_ID = os.environ["FLOWSENSE_CLIENT_ID"]
CLIENT_SECRET = os.environ["FLOWSENSE_CLIENT_SECRET"]
CLIENT_ADDRESS = os.environ["FLOWSENSE_CLIENT_ADDRESS"]
SECRET_FILE = Path(os.getenv("FLOWSENSE_PARTNER_SECRET_FILE", ".partner-key.json"))
TEST_SCOPES = sorted(set(os.getenv("FLOWSENSE_TEST_SCOPES", "devices:read").split()))
TALQ_HEADERS = {"talq-api-version": "2.7.1"}


def call(method: str, path: str, *, headers=None, body=None):
    payload = None if body is None else (
        body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
    )
    request = Request(
        BASE_URL + path,
        data=payload,
        headers={"Accept": "application/json", **(headers or {})},
        method=method,
    )
    try:
        with urlopen(request, timeout=20) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {path} failed ({exc.code}): {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Cannot reach FlowSense at {BASE_URL}: {exc}") from exc


def get_access_token() -> str:
    basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    form = urlencode({
        "grant_type": "client_credentials",
        "scope": " ".join(sorted(set(TEST_SCOPES) | {"keys:manage"})),
    }).encode()
    result = call(
        "POST",
        "/oauth/token",
        headers={
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body=form,
    )
    print(f"[OK] OAuth token issued; expires in {result['expires_in']} seconds")
    return result["access_token"]


def verify_key(api_key: str) -> None:
    headers = {"X-API-Key": api_key, **TALQ_HEADERS}
    call("GET", "/auth/verify", headers={"X-API-Key": api_key})

    def verify_route(path: str, label: str, count_field: str) -> None:
        result = call(
            "GET",
            path + ("&" if "?" in path else "?") + urlencode({"clientAddress": CLIENT_ADDRESS}),
            headers=headers,
        )
        print(f"[OK] {label} route accepted the key ({result.get(count_field, 'response received')} records/items)")

    verify_route("/devices", "Devices", "count")
    if {"energy:read", "water:read"} & set(TEST_SCOPES):
        verify_route("/measurements?limit=5", "Measurements", "count")
    if "alerts:read" in TEST_SCOPES:
        verify_route("/alerts?limit=5", "Alerts", "count")
        verify_route("/events?limit=5", "Events", "count")
    if {"energy:read", "water:read", "alerts:read"} & set(TEST_SCOPES):
        verify_route("/data-packages?limit=5", "Data packages", "count")


def save_secret(payload: dict) -> None:
    SECRET_FILE.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        SECRET_FILE.chmod(0o600)
    except OSError:
        pass
    print(f"[OK] Test credential saved locally to {SECRET_FILE}")
    print("[IMPORTANT] Keep this file private and never commit it to Git.")


def main() -> None:
    token = get_access_token()
    bearer = {"Authorization": f"Bearer {token}"}
    saved = json.loads(SECRET_FILE.read_text(encoding="utf-8")) if SECRET_FILE.exists() else None

    if saved and saved.get("key_id"):
        result = call(
            "POST",
            f"/integrations/me/api-keys/{saved['key_id']}/rotate",
            headers=bearer,
        )
        print(f"[OK] Replacement API key created (key ID {result['key_id']})")
        verify_key(result["api_key"])
        save_secret({
            "key_id": result["key_id"],
            "api_key": result["api_key"],
            "expires_at": result["expires_at"],
        })
        call(
            "POST",
            f"/integrations/me/api-keys/{result['previous_key_id']}/retire",
            headers=bearer,
        )
        print("[OK] Previous API key retired after replacement verification")
    else:
        result = call("POST", "/integrations/me/api-keys", headers=bearer)
        print(f"[OK] Initial API key created (key ID {result['key_id']})")
        verify_key(result["api_key"])
        save_secret({
            "key_id": result["key_id"],
            "api_key": result["api_key"],
            "expires_at": result["expires_at"],
        })

    print("[DONE] Partner OAuth and API-key lifecycle smoke test passed.")
    print("Verified routes for approved scopes: " + ", ".join(TEST_SCOPES))
    print("A successful HTTP response confirms API behavior; compare returned records with authorized live RDS data during acceptance testing.")


if __name__ == "__main__":
    main()
