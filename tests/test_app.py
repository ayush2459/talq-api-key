import importlib

from fastapi.testclient import TestClient


def make_client(monkeypatch):
    monkeypatch.setenv("FLOWSENSE_API_KEY", "test-secret")
    monkeypatch.setenv("TALQ_CLIENT_ADDRESS", "")
    import app.main as main
    importlib.reload(main)
    return TestClient(main.app)


def test_health_is_public(monkeypatch):
    client = make_client(monkeypatch)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_protected_endpoint_requires_key(monkeypatch):
    client = make_client(monkeypatch)
    response = client.get("/integration-status")
    assert response.status_code == 401


def test_devices_requires_talq_version_and_client_address(monkeypatch):
    client = make_client(monkeypatch)
    response = client.get("/devices", headers={"X-API-Key": "test-secret", "talq-api-version": "2.7.1"})
    assert response.status_code == 422


def test_services_endpoint(monkeypatch):
    client = make_client(monkeypatch)
    response = client.get(
        "/services?clientAddress=test-client",
        headers={"X-API-Key": "test-secret", "talq-api-version": "2.7.1"},
    )
    assert response.status_code == 200
    assert "measurements" in response.json()["services"]
