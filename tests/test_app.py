import importlib
from pathlib import Path

from fastapi.testclient import TestClient


def make_client(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    monkeypatch.setenv("TALQ_CLIENT_ADDRESS", "")
    import app.main as main
    importlib.reload(main)
    return TestClient(main.app), main


def submit_request(client):
    response = client.post(
        "/access-requests",
        json={
            "contact_name": "Test User",
            "email": "client@example.com",
            "organization": "Example Org",
            "purpose": "Integrate our management system with FlowSense device data.",
            "client_address": "cms-example-01",
        },
    )
    assert response.status_code == 201
    return response.json()["request_id"]


def test_health_is_public(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_protected_endpoint_requires_issued_key(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    response = client.get("/integration-status")
    assert response.status_code == 401


def test_access_request_requires_admin_approval_before_key_works(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    request_id = submit_request(client)
    # No key is issued by the public request endpoint.
    assert client.get("/integration-status").status_code == 401
    response = client.post(
        f"/admin/access-requests/{request_id}/approve",
        headers={"X-Admin-Key": "test-admin-secret"},
    )
    assert response.status_code == 200
    issued_key = response.json()["api_key"]
    assert issued_key.startswith("fs_talq_")
    assert client.get("/integration-status", headers={"X-API-Key": issued_key}).status_code == 200


def test_devices_requires_talq_version_and_client_address(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    request_id = submit_request(client)
    approval = client.post(
        f"/admin/access-requests/{request_id}/approve",
        headers={"X-Admin-Key": "test-admin-secret"},
    ).json()
    response = client.get(
        "/devices",
        headers={"X-API-Key": approval["api_key"], "talq-api-version": "2.7.1"},
    )
    assert response.status_code == 422


def test_approved_key_is_bound_to_client_address(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    request_id = submit_request(client)
    approval = client.post(
        f"/admin/access-requests/{request_id}/approve",
        headers={"X-Admin-Key": "test-admin-secret"},
    ).json()
    response = client.get(
        "/services?clientAddress=wrong-client",
        headers={"X-API-Key": approval["api_key"], "talq-api-version": "2.7.1"},
    )
    assert response.status_code == 403


def test_revoked_key_stops_working(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    request_id = submit_request(client)
    approval = client.post(
        f"/admin/access-requests/{request_id}/approve",
        headers={"X-Admin-Key": "test-admin-secret"},
    ).json()
    revoke = client.post(
        f"/admin/api-keys/{approval['api_key_id']}/revoke",
        headers={"X-Admin-Key": "test-admin-secret"},
    )
    assert revoke.status_code == 200
    assert client.get(
        "/integration-status", headers={"X-API-Key": approval["api_key"]}
    ).status_code == 401

def test_auth_verify_returns_authenticated_client_metadata(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    request_id = submit_request(client)
    approval = client.post(
        f"/admin/access-requests/{request_id}/approve",
        headers={"X-Admin-Key": "test-admin-secret"},
    ).json()

    response = client.get(
        "/auth/verify",
        headers={"X-API-Key": approval["api_key"]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is True
    assert body["organization"] == "Example Org"
    assert body["client_address"] == "cms-example-01"
