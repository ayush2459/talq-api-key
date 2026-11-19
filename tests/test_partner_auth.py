import base64
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.partner_auth import IntegrationAPIKey, IntegrationClient, OAuthAccessToken


@pytest.fixture()
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    main.Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[main.get_db] = override_db
    main.ADMIN_API_KEY = "test-admin-secret"

    with TestingSession() as db:
        request = main.AccessRequest(
            contact_name="Partner Contact",
            email="partner@example.test",
            organization="Partner Co",
            purpose="Read approved FlowSense device data for integration testing.",
            client_address="partner-lan-01",
            status="approved",
        )
        db.add(request)
        db.commit()
        db.refresh(request)
        request_id = request.id

    with TestClient(main.app) as test_client:
        test_client.request_id = request_id
        yield test_client

    main.app.dependency_overrides.clear()
    engine.dispose()


def provision_and_token(client, scopes=None):
    provision = client.post(
        f"/admin/integrations/{client.request_id}/provision",
        headers={"X-Admin-Key": "test-admin-secret"},
        json={"scopes": scopes or ["devices:read"]},
    )
    assert provision.status_code == 200, provision.text
    credentials = provision.json()
    basic = base64.b64encode(
        f"{credentials['client_id']}:{credentials['client_secret']}".encode()
    ).decode()
    token_response = client.post(
        "/oauth/token",
        headers={
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        content=urlencode({"grant_type": "client_credentials", "scope": "keys:manage devices:read"}),
    )
    assert token_response.status_code == 200, token_response.text
    return credentials, token_response.json()["access_token"]


def test_partner_can_issue_verify_rotate_and_retire_key(client):
    _, token = provision_and_token(client)
    bearer = {"Authorization": f"Bearer {token}"}

    issued = client.post("/integrations/me/api-keys", headers=bearer)
    assert issued.status_code == 200, issued.text
    first = issued.json()

    verified = client.get("/auth/verify", headers={"X-API-Key": first["api_key"]})
    assert verified.status_code == 200
    assert verified.json()["authenticated"] is True

    gateway_response = client.get(
        "/devices?clientAddress=partner-lan-01",
        headers={"X-API-Key": first["api_key"], "talq-api-version": "2.7.1"},
    )
    assert gateway_response.status_code == 200

    rotated = client.post(
        f"/integrations/me/api-keys/{first['key_id']}/rotate",
        headers=bearer,
    )
    assert rotated.status_code == 200, rotated.text
    second = rotated.json()

    assert client.get("/auth/verify", headers={"X-API-Key": second["api_key"]}).status_code == 200
    assert client.get("/auth/verify", headers={"X-API-Key": first["api_key"]}).status_code == 200

    retired = client.post(
        f"/integrations/me/api-keys/{first['key_id']}/retire",
        headers=bearer,
    )
    assert retired.status_code == 200
    assert client.get("/auth/verify", headers={"X-API-Key": first["api_key"]}).status_code == 401


def test_invalid_client_secret_is_rejected(client):
    credentials, _ = provision_and_token(client)
    basic = base64.b64encode(
        f"{credentials['client_id']}:wrong-secret".encode()
    ).decode()
    response = client.post(
        "/oauth/token",
        headers={
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        content="grant_type=client_credentials",
    )
    assert response.status_code == 401


def test_partner_cannot_request_unapproved_scope(client):
    response = client.post(
        f"/admin/integrations/{client.request_id}/provision",
        headers={"X-Admin-Key": "test-admin-secret"},
        json={"scopes": ["devices:read", "admin:all"]},
    )
    assert response.status_code == 422
