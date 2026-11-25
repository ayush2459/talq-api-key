import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

from app.main import app
from app.partner_app import partner_app
from app.onboarding import PartnerEnrollment


def make_public_private():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private, public_pem


def test_partner_surface_blocks_admin_docs_and_legacy_routes():
    client = TestClient(partner_app)
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/admin/access-requests").status_code == 404
    assert client.get("/admin/onboarding/1/audit").status_code == 404
    assert client.post("/admin/integrations/1/rotate-secret").status_code == 404
    assert client.post("/admin/integrations/1/provision").status_code == 404
    assert client.post("/access-requests", json={}).status_code == 404
    assert client.get("/v1/ping").status_code == 200


def test_partner_onboarding_encrypted_one_time_claim(monkeypatch, tmp_path):
    from app import main
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    main.engine = engine
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    main.SessionLocal = TestingSession
    main.Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(main, "ADMIN_API_KEY", "onboarding-admin-key")

    private, public_pem = make_public_private()
    client = TestClient(partner_app)
    response = client.post("/v1/onboarding/requests", json={
        "contact_name": "Partner Contact",
        "email": "partner@example.test",
        "organization": "Partner Example",
        "purpose": "Read authorized FlowSense device and energy data.",
        "client_address": "partner-example-01",
        "public_key_pem": public_pem,
    })
    assert response.status_code == 201, response.text
    created = response.json()
    request_id = created["request_id"]
    token = created["status_token"]
    partner_headers = {"X-Onboarding-Token": token}

    # Admin approval and OAuth provisioning happen only on the internal app.
    internal = TestClient(main.app)
    approval = internal.post(
        f"/admin/access-requests/{request_id}/approve",
        headers={"X-Admin-Key": "onboarding-admin-key"},
    )
    assert approval.status_code == 200, approval.text
    provision = internal.post(
        f"/admin/integrations/{request_id}/provision",
        headers={"X-Admin-Key": "onboarding-admin-key"},
        json={"scopes": ["devices:read"]},
    )
    assert provision.status_code == 200, provision.text
    body = provision.json()
    assert "client_secret" not in body
    assert body["credential_delivery"] == "encrypted_one_time_claim"

    status_response = client.get(f"/v1/onboarding/requests/{request_id}", headers=partner_headers)
    assert status_response.json()["status"] == "credentials_ready"
    claimed = client.post(
        f"/v1/onboarding/requests/{request_id}/claim",
        headers=partner_headers,
    )
    assert claimed.status_code == 200, claimed.text
    envelope = claimed.json()["encrypted_credentials"]

    aes_key = private.decrypt(
        base64.b64decode(envelope["encrypted_key"]),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    plaintext = AESGCM(aes_key).decrypt(
        base64.b64decode(envelope["nonce"]),
        base64.b64decode(envelope["ciphertext"]),
        None,
    )
    credentials = json.loads(plaintext)
    assert credentials["client_id"]
    assert credentials["client_secret"]

    repeated = client.post(
        f"/v1/onboarding/requests/{request_id}/claim",
        headers=partner_headers,
    )
    assert repeated.status_code == 409

    # Admin secret rotation also uses the encrypted one-time claim channel.
    rotated = internal.post(
        f"/admin/integrations/{body['integration_id']}/rotate-secret",
        headers={"X-Admin-Key": "onboarding-admin-key"},
    )
    assert rotated.status_code == 200, rotated.text
    assert "client_secret" not in rotated.json()
    assert rotated.json()["credential_delivery"] == "encrypted_one_time_claim"
    rotated_claim = client.post(
        f"/v1/onboarding/requests/{request_id}/claim",
        headers=partner_headers,
    )
    assert rotated_claim.status_code == 200, rotated_claim.text
    rotated_envelope = rotated_claim.json()["encrypted_credentials"]
    rotated_key = private.decrypt(
        base64.b64decode(rotated_envelope["encrypted_key"]),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    rotated_plaintext = AESGCM(rotated_key).decrypt(
        base64.b64decode(rotated_envelope["nonce"]),
        base64.b64decode(rotated_envelope["ciphertext"]),
        None,
    )
    rotated_credentials = json.loads(rotated_plaintext)
    assert rotated_credentials["client_secret"] != credentials["client_secret"]

    audit = internal.get(
        f"/admin/onboarding/{request_id}/audit",
        headers={"X-Admin-Key": "onboarding-admin-key"},
    )
    assert audit.status_code == 200, audit.text
    event_types = [event["event_type"] for event in audit.json()["events"]]
    assert event_types == [
        "request_submitted", "request_approved",
        "credentials_provisioned", "credentials_claimed",
        "client_secret_rotated", "credentials_claimed",
    ]
