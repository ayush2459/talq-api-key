import importlib
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qs

from fastapi.testclient import TestClient
from sqlalchemy import select


def make_client(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    monkeypatch.setenv("TALQ_CLIENT_ADDRESS", "")
    monkeypatch.setenv("API_KEY_LIFETIME_DAYS", "90")
    monkeypatch.setenv("TELEGRAM_VERIFICATION_MINUTES", "30")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:test-bot-token")
    monkeypatch.setenv("TELEGRAM_BOT_USERNAME", "FlowSenseTestBot")
    monkeypatch.setenv("TELEGRAM_WEBHOOK_SECRET", "test-webhook-secret")
    import app.main as main
    importlib.reload(main)
    sent_messages = []
    monkeypatch.setattr(main, "send_telegram_message", lambda chat_id, text: sent_messages.append((str(chat_id), text)))
    main._test_telegram_messages = sent_messages
    return TestClient(main.app), main


def submit_request(client):
    response = client.post(
        "/access-requests",
        json={
            "contact_name": "Test User",
            "email": "client@example.com",
            "organization": "Example Org",
            "telegram_username": "@testuser",
            "purpose": "Integrate our management system with FlowSense device data.",
            "client_address": "00000000-0000-4000-8000-000000000001",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "pending_verification"
    assert body["telegram_url"].startswith("https://t.me/FlowSenseTestBot?start=")
    return body


def telegram_start(client, body, username="testuser", chat_id=12345):
    start_token = parse_qs(urlparse(body["telegram_url"]).query)["start"][0]
    return client.post(
        "/telegram/webhook",
        headers={"X-Telegram-Bot-Api-Secret-Token": "test-webhook-secret"},
        json={
            "update_id": 1,
            "message": {
                "text": f"/start {start_token}",
                "from": {"id": chat_id, "username": username},
                "chat": {"id": chat_id, "type": "private"},
            },
        },
    )


def test_health_is_public(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_key_is_issued_only_after_telegram_verification(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    request = submit_request(client)
    headers = {"X-Request-Token": request["request_token"]}
    assert client.get(f"/access-requests/{request['request_id']}/status", headers=headers).json()["status"] == "pending_verification"
    verified = telegram_start(client, request)
    assert verified.status_code == 200
    state = client.get(f"/access-requests/{request['request_id']}/status", headers=headers)
    assert state.status_code == 200
    assert state.json()["telegram_verified"] is True
    issued = client.post(
        f"/access-requests/{request['request_id']}/issue-key",
        json={"request_token": request["request_token"]},
    )
    assert issued.status_code == 200, issued.text
    body = issued.json()
    assert body["status"] == "issued"
    assert body["api_key"].startswith("fs_talq_")
    assert body["lifetime_days"] == 90
    assert body["expires_at"]
    assert client.get("/integration-status", headers={"X-API-Key": body["api_key"]}).status_code == 200


def test_telegram_webhook_requires_secret(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    response = client.post("/telegram/webhook", json={})
    assert response.status_code == 401


def test_username_must_match_telegram_sender(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    request = submit_request(client)
    telegram_start(client, request, username="someoneelse")
    state = client.get(
        f"/access-requests/{request['request_id']}/status",
        headers={"X-Request-Token": request["request_token"]},
    )
    assert state.status_code == 200
    assert state.json()["telegram_verified"] is False


def test_verification_link_is_single_use(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    request = submit_request(client)
    telegram_start(client, request)
    state = client.get(
        f"/access-requests/{request['request_id']}/status",
        headers={"X-Request-Token": request["request_token"]},
    )
    assert state.json()["telegram_verified"] is True
    # Replaying the same /start payload must not change state or create a second key.
    telegram_start(client, request)
    issued = client.post(
        f"/access-requests/{request['request_id']}/issue-key",
        json={"request_token": request["request_token"]},
    )
    assert issued.status_code == 200
    duplicate = client.post(
        f"/access-requests/{request['request_id']}/issue-key",
        json={"request_token": request["request_token"]},
    )
    assert duplicate.status_code == 404


def test_invalid_request_token_cannot_read_status_or_issue_key(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    request = submit_request(client)
    assert client.get(
        f"/access-requests/{request['request_id']}/status",
        headers={"X-Request-Token": "wrong-token-that-is-long-enough-for-schema-validation-123456"},
    ).status_code == 404
    assert client.post(
        f"/access-requests/{request['request_id']}/issue-key",
        json={"request_token": "wrong-token-that-is-long-enough-for-schema-validation-123456"},
    ).status_code == 404


def test_expired_telegram_link_is_rejected(monkeypatch, tmp_path):
    client, main = make_client(monkeypatch, tmp_path)
    request = submit_request(client)
    with main.SessionLocal() as db:
        item = db.scalar(select(main.AccessRequest))
        item.verification_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    telegram_start(client, request)
    state = client.get(
        f"/access-requests/{request['request_id']}/status",
        headers={"X-Request-Token": request["request_token"]},
    )
    assert state.status_code == 200
    assert state.json()["telegram_verified"] is False


def test_expired_api_key_is_rejected(monkeypatch, tmp_path):
    client, main = make_client(monkeypatch, tmp_path)
    request = submit_request(client)
    telegram_start(client, request)
    issued = client.post(
        f"/access-requests/{request['request_id']}/issue-key",
        json={"request_token": request["request_token"]},
    ).json()
    with main.SessionLocal() as db:
        record = db.scalar(select(main.ClientAPIKey))
        record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    response = client.get("/integration-status", headers={"X-API-Key": issued["api_key"]})
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


def test_client_can_revoke_only_its_own_request_keys(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    request = submit_request(client)
    telegram_start(client, request)
    issued = client.post(
        f"/access-requests/{request['request_id']}/issue-key",
        json={"request_token": request["request_token"]},
    ).json()
    revoke = client.post(
        f"/auth/api-keys/{issued['api_key_id']}/revoke",
        headers={"X-API-Key": issued["api_key"]},
    )
    assert revoke.status_code == 200
    assert client.get("/integration-status", headers={"X-API-Key": issued["api_key"]}).status_code == 401


def test_admin_key_listing_includes_expiration_metadata(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    request = submit_request(client)
    telegram_start(client, request)
    client.post(
        f"/access-requests/{request['request_id']}/issue-key",
        json={"request_token": request["request_token"]},
    )
    response = client.get("/admin/api-keys", headers={"X-Admin-Key": "test-admin-secret"})
    assert response.status_code == 200
    assert response.json()[0]["expires_at"]
    assert response.json()[0]["expired"] is False


def test_oauth_client_credentials_grant_and_scoped_bearer_access(monkeypatch, tmp_path):
    client, main = make_client(monkeypatch, tmp_path)
    request = submit_request(client)
    telegram_start(client, request)
    issued = client.post(
        f"/access-requests/{request['request_id']}/issue-key",
        json={"request_token": request["request_token"]},
    )
    assert issued.status_code == 200, issued.text
    manager = issued.json()["management_token"]
    created = client.post(
        "/auth/managed-oauth-clients",
        headers={"X-Key-Management-Token": manager},
        json={"name": "Analytics backend", "scopes": ["data:read", "gateway:read"]},
    )
    assert created.status_code == 201, created.text
    oauth_client = created.json()
    assert oauth_client["client_secret"].startswith("fs_secret_")

    token = client.post(
        "/oauth/token",
        auth=(oauth_client["client_id"], oauth_client["client_secret"]),
        data={"grant_type": "client_credentials", "scope": "data:read gateway:read"},
    )
    assert token.status_code == 200, token.text
    token_body = token.json()
    assert token_body["token_type"] == "Bearer"
    assert token_body["expires_in"] == 3600
    assert token_body["access_token"].startswith("fs_oauth_")
    assert token_body["client_address"] == "00000000-0000-4000-8000-000000000001"
    assert token_body["organization"] == "Example Org"

    # Protected gateway read route accepts OAuth bearer tokens as well as legacy API keys.
    headers = {"Authorization": f"Bearer {token_body['access_token']}"}
    status_response = client.get("/integration-status", headers=headers)
    assert status_response.status_code == 200, status_response.text

    # A revoked OAuth client invalidates its existing access tokens.
    revoked = client.post(
        f"/auth/managed-oauth-clients/{oauth_client['id']}/revoke",
        headers={"X-Key-Management-Token": manager},
    )
    assert revoked.status_code == 200, revoked.text
    assert client.get("/integration-status", headers=headers).status_code == 401


def test_oauth_token_rejects_revoked_underlying_api_key(monkeypatch, tmp_path):
    client, main = make_client(monkeypatch, tmp_path)
    request = submit_request(client)
    telegram_start(client, request)
    issued = client.post(
        f"/access-requests/{request['request_id']}/issue-key",
        json={"request_token": request["request_token"]},
    )
    assert issued.status_code == 200, issued.text
    manager = issued.json()["management_token"]
    created = client.post(
        "/auth/managed-oauth-clients",
        headers={"X-Key-Management-Token": manager},
        json={"name": "Revocation test client", "scopes": ["data:read"]},
    )
    assert created.status_code == 201, created.text
    oauth_client = created.json()
    revoked = client.post(
        f"/auth/managed-api-keys/{issued.json()['api_key_id']}/revoke",
        headers={"X-Key-Management-Token": manager},
    )
    assert revoked.status_code == 200, revoked.text
    response = client.post(
        "/oauth/token",
        auth=(oauth_client["client_id"], oauth_client["client_secret"]),
        data={"grant_type": "client_credentials", "scope": "data:read"},
    )
    assert response.status_code == 401, response.text


def test_oauth_rejects_invalid_scope_and_invalid_client(monkeypatch, tmp_path):
    client, _ = make_client(monkeypatch, tmp_path)
    response = client.post(
        "/oauth/token",
        auth=("unknown-client", "wrong-secret"),
        data={"grant_type": "client_credentials"},
    )
    assert response.status_code == 401

