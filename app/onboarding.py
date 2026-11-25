"""Partner API onboarding and one-time encrypted credential delivery."""
import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column, Session

from app import main as gateway

router = APIRouter(tags=["Partner onboarding"])
ONBOARDING_TOKEN_TTL_HOURS = 72
CREDENTIAL_CLAIM_TTL_MINUTES = 30


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class PartnerEnrollment(gateway.Base):
    __tablename__ = "partner_enrollments"

    id: Mapped[int] = mapped_column(primary_key=True)
    access_request_id: Mapped[int] = mapped_column(
        ForeignKey("access_requests.id"), unique=True, index=True
    )
    public_key_pem: Mapped[str] = mapped_column(Text)
    onboarding_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    encrypted_credentials: Mapped[str | None] = mapped_column(Text, nullable=True)
    onboarding_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    claim_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


gateway.Base.metadata.create_all(bind=gateway.engine)


class PartnerOnboardingInput(BaseModel):
    contact_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=5, max_length=254)
    organization: str = Field(min_length=2, max_length=160)
    purpose: str = Field(min_length=10, max_length=2000)
    client_address: str = Field(min_length=2, max_length=160)
    public_key_pem: str = Field(min_length=200, max_length=12000)


def _validate_public_key(pem: str):
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail="public_key_pem must be a valid PEM public key") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise HTTPException(status_code=422, detail="Use an RSA public key of at least 2048 bits")
    return key


def encrypt_credentials(public_key_pem: str, credentials: dict) -> str:
    """Hybrid RSA-OAEP + AES-256-GCM envelope; private key never reaches FlowSense."""
    public_key = _validate_public_key(public_key_pem)
    plaintext = json.dumps(credentials, separators=(",", ":")).encode("utf-8")
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return json.dumps({
        "version": 1,
        "algorithm": "RSA-OAEP-256+A256GCM",
        "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    })


def _authorized_enrollment(
    request_id: int,
    onboarding_token: str | None,
    db: Session,
) -> tuple[PartnerEnrollment, gateway.AccessRequest]:
    if not onboarding_token:
        raise HTTPException(status_code=401, detail="X-Onboarding-Token is required")
    enrollment = db.scalar(select(PartnerEnrollment).where(
        PartnerEnrollment.access_request_id == request_id,
        PartnerEnrollment.onboarding_token_hash == _hash(onboarding_token),
    ))
    if enrollment is None:
        raise HTTPException(status_code=404, detail="Onboarding request not found")
    expiry = enrollment.onboarding_expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= _now():
        raise HTTPException(status_code=410, detail="Onboarding token expired")
    access_request = db.get(gateway.AccessRequest, request_id)
    if access_request is None:
        raise HTTPException(status_code=404, detail="Onboarding request not found")
    return enrollment, access_request


@router.get("/v1/ping")
def partner_ping():
    return {"status": "ok", "service": "FlowSense Partner API", "api_version": "v1"}


@router.post("/v1/onboarding/requests", status_code=status.HTTP_201_CREATED)
def create_partner_request(
    payload: PartnerOnboardingInput,
    db: Session = Depends(gateway.get_db),
):
    public_key = _validate_public_key(payload.public_key_pem)
    if not gateway.validate_email(payload.email):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    email = payload.email.strip().lower()
    client_address = payload.client_address.strip()
    existing = db.scalar(select(gateway.AccessRequest).where(
        gateway.AccessRequest.email == email,
        gateway.AccessRequest.client_address == client_address,
        gateway.AccessRequest.status == "pending",
    ))
    if existing:
        enrollment = db.scalar(select(PartnerEnrollment).where(
            PartnerEnrollment.access_request_id == existing.id
        ))
        if enrollment:
            raise HTTPException(status_code=409, detail={
                "message": "A pending onboarding request already exists",
                "request_id": existing.id,
            })
    request_record = gateway.AccessRequest(
        contact_name=payload.contact_name.strip(),
        email=email,
        organization=payload.organization.strip(),
        purpose=payload.purpose.strip(),
        client_address=client_address,
        status="pending",
    )
    db.add(request_record)
    db.flush()
    onboarding_token = secrets.token_urlsafe(40)
    enrollment = PartnerEnrollment(
        access_request_id=request_record.id,
        public_key_pem=payload.public_key_pem,
        onboarding_token_hash=_hash(onboarding_token),
        status="pending",
        onboarding_expires_at=_now() + timedelta(hours=ONBOARDING_TOKEN_TTL_HOURS),
    )
    db.add(enrollment)
    db.commit()
    return {
        "request_id": request_record.id,
        "status": "pending",
        "status_token": onboarding_token,
        "status_url": f"/v1/onboarding/requests/{request_record.id}",
        "message": "Request submitted. Store status_token securely; it is shown once.",
    }


@router.get("/v1/onboarding/requests/{request_id}")
def get_partner_request_status(
    request_id: int,
    x_onboarding_token: str | None = Header(default=None, alias="X-Onboarding-Token"),
    db: Session = Depends(gateway.get_db),
):
    enrollment, request_record = _authorized_enrollment(request_id, x_onboarding_token, db)
    if request_record.status == "rejected":
        current_status = "rejected"
    elif enrollment.claimed_at is not None:
        current_status = "credentials_claimed"
    elif enrollment.encrypted_credentials:
        current_status = "credentials_ready"
    else:
        current_status = request_record.status
    return {
        "request_id": request_id,
        "status": current_status,
        "organization": request_record.organization,
        "created_at": enrollment.created_at.isoformat(),
        "claim_expires_at": enrollment.claim_expires_at.isoformat() if enrollment.claim_expires_at else None,
    }


@router.post("/v1/onboarding/requests/{request_id}/claim")
def claim_partner_credentials(
    request_id: int,
    x_onboarding_token: str | None = Header(default=None, alias="X-Onboarding-Token"),
    db: Session = Depends(gateway.get_db),
):
    enrollment, _ = _authorized_enrollment(request_id, x_onboarding_token, db)
    if enrollment.claimed_at is not None:
        raise HTTPException(status_code=409, detail="Credentials have already been claimed")
    if not enrollment.encrypted_credentials or not enrollment.claim_expires_at:
        raise HTTPException(status_code=409, detail="Credentials are not ready; check approval status")
    expiry = enrollment.claim_expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= _now():
        raise HTTPException(status_code=410, detail="Credential claim expired; contact FlowSense administrator")
    envelope = json.loads(enrollment.encrypted_credentials)
    enrollment.claimed_at = _now()
    enrollment.encrypted_credentials = None
    db.commit()
    return {
        "request_id": request_id,
        "encrypted_credentials": envelope,
        "message": "One-time encrypted credential package. Decrypt with the private key matching the submitted public key.",
    }
