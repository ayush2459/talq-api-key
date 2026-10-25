"""FlowSense TALQ Gateway pilot with approval-based client API keys.

This is a pilot access-management flow, not a complete TALQ implementation.
"""
import hashlib
import hmac
import os
import re
import secrets
import smtplib
import ssl
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

APP_ENV = os.getenv("APP_ENV", "production")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()
EXPECTED_CLIENT_ADDRESS = os.getenv("TALQ_CLIENT_ADDRESS", "").strip()
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
API_KEY_LIFETIME_DAYS = max(1, min(int(os.getenv("API_KEY_LIFETIME_DAYS", "90")), 3650))
EMAIL_VERIFICATION_MINUTES = max(5, min(int(os.getenv("EMAIL_VERIFICATION_MINUTES", "30")), 1440))
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://flowsense-talq-gateway.onrender.com").rstrip("/")
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "").strip()
SMTP_USE_STARTTLS = os.getenv("SMTP_USE_STARTTLS", "true").lower() == "true"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./flowsense_talq.db").strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class AccessRequest(Base):
    __tablename__ = "access_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    contact_name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(254), index=True)
    organization: Mapped[str] = mapped_column(String(160))
    purpose: Mapped[str] = mapped_column(Text)
    client_address: Mapped[str] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ClientAPIKey(Base):
    __tablename__ = "client_api_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    access_request_id: Mapped[int] = mapped_column(ForeignKey("access_requests.id"))
    label: Mapped[str] = mapped_column(String(160))
    organization: Mapped[str] = mapped_column(String(160))
    email: Mapped[str] = mapped_column(String(254))
    client_address: Mapped[str] = mapped_column(String(160), index=True)
    key_prefix: Mapped[str] = mapped_column(String(20))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc) + timedelta(days=API_KEY_LIFETIME_DAYS), index=True)


Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="FlowSense TALQ Gateway",
    version="0.2.0",
    description=(
        "Pilot gateway with approval-based API key issuance. This is not a complete "
        "or TALQ-certified implementation."
    ),
)

# Deliberately empty until real FlowSense device data is mapped and validated.
DEMO_DEVICES: list[dict[str, Any]] = []
DEMO_DATA_PACKAGES: list[dict[str, Any]] = []
SERVICES = ["device-management", "measurements", "events"]


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> ClientAPIKey:
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key required")
    record = db.scalar(select(ClientAPIKey).where(ClientAPIKey.key_hash == hash_api_key(x_api_key)))
    if record is None or record.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked API key")
    return record


def require_admin_key(x_admin_key: str | None = Header(default=None, alias="X-Admin-Key")) -> None:
    if not ADMIN_API_KEY:
        raise HTTPException(status_code=503, detail="Admin access is not configured. Set ADMIN_API_KEY.")
    if not x_admin_key or not secrets.compare_digest(x_admin_key, ADMIN_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing admin key")


def require_talq_headers(
    talq_api_version: str | None = Header(default=None, alias="talq-api-version"),
    client_address: UUID = Query(..., alias="clientAddress", description="UUID address of the CMS as required by TALQ 2.7.1"),
    api_key: ClientAPIKey = Depends(require_api_key),
) -> str:
    if talq_api_version != "2.7.1":
        raise HTTPException(status_code=400, detail="talq-api-version must be 2.7.1")
    client_address_text = str(client_address)
    if client_address_text != api_key.client_address:
        raise HTTPException(status_code=403, detail="clientAddress does not match the approved API key")
    if EXPECTED_CLIENT_ADDRESS and client_address_text != EXPECTED_CLIENT_ADDRESS:
        raise HTTPException(status_code=403, detail="Unapproved clientAddress")
    return client_address_text


class AccessRequestInput(BaseModel):
    contact_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=5, max_length=254)
    organization: str = Field(min_length=2, max_length=160)
    purpose: str = Field(min_length=10, max_length=2000)
    client_address: UUID = Field(description="Stable UUID address assigned to the partner CMS")


def validate_email(email: str) -> bool:
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email))


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok", "service": "FlowSense TALQ Gateway", "environment": APP_ENV}


def send_verification_email(recipient: str, organization: str, token: str) -> None:
    """Deliver the one-time verification token. No token is logged or persisted in plaintext."""
    if not all([SMTP_HOST, SMTP_FROM_EMAIL]):
        raise RuntimeError("Email delivery is not configured. Set SMTP_HOST and SMTP_FROM_EMAIL.")
    message = EmailMessage()
    message["Subject"] = "Verify your FlowSense TALQ Gateway API access"
    message["From"] = SMTP_FROM_EMAIL
    message["To"] = recipient
    message.set_content(
        f"Hello {organization},\n\n"
        "A request was made for a FlowSense TALQ Gateway API key using this email address.\n"
        f"The verification token expires in {EMAIL_VERIFICATION_MINUTES} minutes.\n\n"
        "To verify and automatically receive your API key, send a POST request to "
        f"{PUBLIC_BASE_URL}/verify-email with JSON body:\n\n"
        f'{{"token": "{token}"}}\n\n'
        "The response contains your API key once. Store it securely. Do not share this "
        "token or key. If you did not request access, ignore this message.\n"
    )
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
        if SMTP_USE_STARTTLS:
            server.starttls(context=context)
        if SMTP_USERNAME:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(message)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _new_client_key(item: AccessRequest, db: Session) -> tuple[ClientAPIKey, str]:
    raw_key = "fs_talq_" + secrets.token_urlsafe(36)
    now = datetime.now(timezone.utc)
    record = ClientAPIKey(
        access_request_id=item.id,
        label=f"{item.organization} API key",
        organization=item.organization,
        email=item.email,
        client_address=item.client_address,
        key_prefix=raw_key[:15],
        key_hash=hash_api_key(raw_key),
        created_at=now,
        expires_at=now + timedelta(days=API_KEY_LIFETIME_DAYS),
    )
    item.status = "verified"
    item.email_verified_at = now
    item.verification_token_hash = None
    item.verification_expires_at = None
    db.add(record)
    return record, raw_key


@app.post("/access-requests", status_code=201, tags=["Access management"])
def request_access(payload: AccessRequestInput, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Create a request and email a one-time verification token; no admin approval is needed."""
    if not validate_email(payload.email):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    email = payload.email.strip().lower()
    now = datetime.now(timezone.utc)
    token = secrets.token_urlsafe(32)
    token_hash = hash_api_key(token)
    item = db.scalar(
        select(AccessRequest).where(
            AccessRequest.email == email,
            AccessRequest.client_address == str(payload.client_address),
            AccessRequest.status == "pending_verification",
        )
    )
    if item is None:
        item = AccessRequest(
            contact_name=payload.contact_name.strip(),
            email=email,
            organization=payload.organization.strip(),
            purpose=payload.purpose.strip(),
            client_address=str(payload.client_address),
            status="pending_verification",
        )
        db.add(item)
    item.verification_token_hash = token_hash
    item.verification_expires_at = now + timedelta(minutes=EMAIL_VERIFICATION_MINUTES)
    try:
        send_verification_email(email, item.organization, token)
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail="Verification email could not be sent. Please try again later.",
        ) from exc
    db.commit()
    db.refresh(item)
    return {
        "request_id": item.id,
        "status": "pending_verification",
        "verification_expires_at": item.verification_expires_at.isoformat(),
        "message": "Check your email and submit the verification token to /verify-email. A key is issued automatically after verification.",
    }


class EmailVerificationInput(BaseModel):
    token: str = Field(min_length=20, max_length=256)


@app.post("/verify-email", tags=["Access management"])
def verify_email_and_issue_key(
    payload: EmailVerificationInput,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Verify email possession and issue a time-limited client key exactly once."""
    token_hash = hash_api_key(payload.token)
    item = db.scalar(
        select(AccessRequest).where(
            AccessRequest.verification_token_hash == token_hash,
            AccessRequest.status == "pending_verification",
        )
    )
    if item is None:
        raise HTTPException(status_code=400, detail="Invalid, expired, or already-used verification token")
    expires = _utc(item.verification_expires_at)
    now = datetime.now(timezone.utc)
    if expires is None or expires <= now:
        item.verification_token_hash = None
        item.verification_expires_at = None
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid, expired, or already-used verification token")
    record, raw_key = _new_client_key(item, db)
    db.commit()
    db.refresh(record)
    return {
        "status": "verified",
        "authenticated": False,
        "api_key_id": record.id,
        "api_key": raw_key,
        "client_address": record.client_address,
        "created_at": record.created_at.isoformat(),
        "expires_at": record.expires_at.isoformat(),
        "lifetime_days": API_KEY_LIFETIME_DAYS,
        "warning": "Copy this key now. It is shown once; only its hash is stored.",
    }


@app.get("/admin/access-requests", tags=["Admin"], dependencies=[Depends(require_admin_key)])
def list_access_requests(
    request_status: str = Query(default="pending_verification", alias="status", pattern="^(pending_verification|verified|all)$"),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    query = select(AccessRequest).order_by(AccessRequest.id.desc())
    if request_status != "all":
        query = query.where(AccessRequest.status == request_status)
    rows = db.scalars(query).all()
    return [
        {
            "id": row.id,
            "contact_name": row.contact_name,
            "email": row.email,
            "organization": row.organization,
            "purpose": row.purpose,
            "client_address": row.client_address,
            "status": row.status,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "email_verified_at": row.email_verified_at.isoformat() if row.email_verified_at else None,
        }
        for row in rows
    ]


@app.get("/admin/api-keys", tags=["Admin"], dependencies=[Depends(require_admin_key)])
def list_api_keys(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.scalars(select(ClientAPIKey).order_by(ClientAPIKey.id.desc())).all()
    now = datetime.now(timezone.utc)
    return [
        {
            "id": row.id,
            "label": row.label,
            "organization": row.organization,
            "email": row.email,
            "client_address": row.client_address,
            "key_prefix": row.key_prefix,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "expired": _utc(row.expires_at) <= now if row.expires_at else False,
            "revoked": row.revoked_at is not None,
        }
        for row in rows
    ]


@app.post("/admin/api-keys/{key_id}/revoke", tags=["Admin"], dependencies=[Depends(require_admin_key)])
def revoke_api_key(key_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    record = db.get(ClientAPIKey, key_id)
    if record is None:
        raise HTTPException(status_code=404, detail="API key not found")
    if record.revoked_at is None:
        record.revoked_at = datetime.now(timezone.utc)
        db.commit()
    return {"api_key_id": record.id, "revoked": True}


@app.get("/auth/verify", tags=["Authentication"])
def verify_api_key(api_key: ClientAPIKey = Depends(require_api_key)) -> dict[str, Any]:
    """Verify a client credential and return safe metadata for the authenticated integration."""
    return {
        "authenticated": True,
        "organization": api_key.organization,
        "client_address": api_key.client_address,
        "api_key_id": api_key.id,
        "key_prefix": api_key.key_prefix,
        "created_at": api_key.created_at.isoformat() if api_key.created_at else None,
        "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
        "message": "API key is valid. Do not share the key in logs or support tickets.",
    }


@app.get("/integration-status", dependencies=[Depends(require_api_key)])
def integration_status(api_key: ClientAPIKey = Depends(require_api_key)) -> dict[str, Any]:
    return {
        "status": "pilot",
        "demo_mode": DEMO_MODE,
        "authorized_organization": api_key.organization,
        "device_count": len(DEMO_DEVICES),
        "data_package_count": len(DEMO_DATA_PACKAGES),
        "notes": [
            "This is a limited pilot scaffold, not a complete TALQ implementation.",
            "Real FlowSense data mapping and official schema validation are still required.",
        ],
    }


@app.get("/devices", dependencies=[Depends(require_api_key)])
def list_devices(client_address: str = Depends(require_talq_headers)) -> dict[str, Any]:
    return {"devices": DEMO_DEVICES, "clientAddress": client_address}


@app.get("/devices/count", dependencies=[Depends(require_api_key)])
def count_devices(client_address: str = Depends(require_talq_headers)) -> dict[str, Any]:
    return {"count": len(DEMO_DEVICES), "clientAddress": client_address}


@app.get("/devices/{deviceAddress}", dependencies=[Depends(require_api_key)])
def get_device(deviceAddress: str, client_address: str = Depends(require_talq_headers)) -> JSONResponse:
    for device in DEMO_DEVICES:
        address = device.get("deviceAddress") or device.get("address")
        if address == deviceAddress:
            return JSONResponse({"device": device, "clientAddress": client_address})
    raise HTTPException(status_code=404, detail="Device not found in configured gateway data")


@app.get("/services", dependencies=[Depends(require_api_key)])
def list_services(client_address: str = Depends(require_talq_headers)) -> dict[str, Any]:
    return {"services": SERVICES, "clientAddress": client_address}


@app.get("/services/{serviceName}", dependencies=[Depends(require_api_key)])
def get_service(serviceName: str, client_address: str = Depends(require_talq_headers)) -> dict[str, Any]:
    if serviceName not in SERVICES:
        raise HTTPException(status_code=404, detail="Service not found")
    return {"serviceName": serviceName, "available": True, "clientAddress": client_address}


@app.get("/data-packages", dependencies=[Depends(require_api_key)])
def list_data_packages(client_address: str = Depends(require_talq_headers)) -> dict[str, Any]:
    return {"dataPackages": DEMO_DATA_PACKAGES, "clientAddress": client_address}
