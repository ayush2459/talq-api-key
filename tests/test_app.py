import importlib
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient


def make_client(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    monkeypatch.setenv("TALQ_CLIENT_ADDRESS", "")
    monkeypatch.setenv("API_KEY_LIFETIME_DAYS", "90")
    monkeypatch.setenv("EMAIL_VERIFICATION_MINUTES", "30")
    import app.main as main
    importlib.reload(main)
    sent_tokens = []
    monkeypatch.setattr(
        main, "send_verification_email",
        lambda recipient, organization, token: sent_tokens.append(token),
    )
    main._test_verification_tokens = sent_tokens
    return TestClient(main.app), main


def submit_request(client):
    response = client.post(
        "/access-requests",
        json={
            "contact_name": "Test User",
            "email": "client@example.com",
            "organization": "Example Org",
            "purpose": "Integrate our management system with FlowSense device data.",
            "client_address": "00000000-0000-4000-8000-000000000001",
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "pending_verification"
    return response.json()["request_id"]


def verify_request(client, main, token=None):
    token = token or main._test_verification_tokens[-1]
    response = client.post("/verify-email", json={"token": token})
    return response


def test_health_is_public(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_key_is_not_issued_until_email_verification(monkeypatch, tmp_path):
    client, main = make_client(monkeypatch, tmp_path)
    submit_request(client)
    assert len(main._test_verification_tokens) == 1
    assert client.get("/integration-status").status_code == 401
    issued = verify_request(client, main)
    assert issued.status_code == 200, issued.text
    body = issued.json()
    assert body["status"] == "verified"
    assert body["api_key"].startswith("fs_talq_")
    assert body["lifetime_days"] == 90
    assert body["expires_at"]
    assert client.get(
        "/integration-status", headers={"X-API-Key": body["api_key"]}
    ).status_code == 200


def test_verification_token_can_only_be_used_once(monkeypatch, tmp_path):
    client, main = make_client(monkeypatch, tmp_path)
    submit_request(client)
    token = main._test_verification_tokens[-1]
    first = verify_request(client, main, token)
    assert first.status_code == 200
    second = verify_request(client, main, token)
    assert second.status_code == 400


def test_invalid_verification_token_does_not_issue_key(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    submit_request(client)
    response = client.post("/verify-email", json={"token": "not-a-real-verification-token-123"})
    assert response.status_code == 400


def test_expired_verification_token_is_rejected(monkeypatch, tmp_path):
    client, main = make_client(monkeypatch, tmp_path)
    submit_request(client)
    from sqlalchemy import select
    with main.SessionLocal() as db:
        request = db.scalar(select(main.AccessRequest))
        request.verification_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    response = verify_request(client, main)
    assert response.status_code == 400


def test_expired_api_key_is_rejected(monkeypatch, tmp_path):
    client, main = make_client(monkeypatch, tmp_path)
    submit_request(client)
    issued = verify_request(client, main).json()
    from sqlalchemy import select
    with main.SessionLocal() as db:
        record = db.scalar(select(main.ClientAPIKey))
        record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    response = client.get("/integration-status", headers={"X-API-Key": issued["api_key"]})
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


def test_api_key_is_bound_to_client_address(monkeypatch, tmp_path):
    client, main = make_client(monkeypatch, tmp_path)
    submit_request(client)
    issued = verify_request(client, main).json()
    response = client.get(
        "/services?clientAddress=00000000-0000-4000-8000-000000000002",
        headers={"X-API-Key": issued["api_key"], "talq-api-version": "2.7.1"},
    )
    assert response.status_code == 403


def test_revoked_key_stops_working(monkeypatch, tmp_path):
    client, main = make_client(monkeypatch, tmp_path)
    submit_request(client)
    issued = verify_request(client, main).json()
    revoke = client.post(
        f"/admin/api-keys/{issued['api_key_id']}/revoke",
        headers={"X-Admin-Key": "test-admin-secret"},
    )
    assert revoke.status_code == 200
    assert client.get(
        "/integration-status", headers={"X-API-Key": issued["api_key"]}
    ).status_code == 401


def test_admin_key_listing_includes_expiration_metadata(monkeypatch, tmp_path):
    client, main = make_client(monkeypatch, tmp_path)
    submit_request(client)
    verify_request(client, main)
    response = client.get("/admin/api-keys", headers={"X-Admin-Key": "test-admin-secret"})
    assert response.status_code == 200
    assert response.json()[0]["expires_at"]
    assert response.json()[0]["expired"] is False


def test_legacy_manual_approval_endpoint_is_removed(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    assert client.post(
        "/admin/access-requests/1/approve",
        headers={"X-Admin-Key": "test-admin-secret"},
    ).status_code == 404
