"""FlowSense TALQ Gateway pilot with approval-based client API keys.

This is a pilot access-management flow, not a complete TALQ implementation.
"""
import hashlib
import hmac
import os
import re
import secrets
import json
from urllib.error import URLError, HTTPError
from urllib.request import Request as URLRequest, urlopen
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, String, Text, create_engine, select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from dotenv import load_dotenv

load_dotenv()
APP_ENV = os.getenv("APP_ENV", "production")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()
EXPECTED_CLIENT_ADDRESS = os.getenv("TALQ_CLIENT_ADDRESS", "").strip()
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
API_KEY_LIFETIME_DAYS = max(1, min(int(os.getenv("API_KEY_LIFETIME_DAYS", "90")), 3650))
TELEGRAM_VERIFICATION_MINUTES = max(5, min(int(os.getenv("TELEGRAM_VERIFICATION_MINUTES", "30")), 1440))
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://flowsense-talq-gateway.onrender.com").rstrip("/")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_BOT_USERNAME = os.getenv("TELEGRAM_BOT_USERNAME", "").strip().lstrip("@")
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()
FRONTEND_ORIGINS = [origin.strip().rstrip("/") for origin in os.getenv("FRONTEND_ORIGINS", "http://127.0.0.1:5500,http://localhost:5500,http://127.0.0.1:8000").split(",") if origin.strip()]
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
    status: Mapped[str] = mapped_column(String(32), default="pending_verification", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    verification_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    verification_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)  # legacy column retained for migration compatibility
    telegram_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    telegram_chat_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    telegram_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    request_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)


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
    version="0.3.0",
    description="FlowSense TALQ Gateway pilot with Telegram-verified API key issuance; not a complete or TALQ-certified implementation.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "X-Admin-Key", "X-Request-Token", "X-Telegram-Bot-Api-Secret-Token", "talq-api-version"],
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
    expires_at = _utc(record.expires_at)
    if expires_at is not None and expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key expired; request a new key")
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
    telegram_username: str = Field(min_length=3, max_length=32, pattern=r"^@?[A-Za-z][A-Za-z0-9_]{4,31}$")
    purpose: str = Field(min_length=10, max_length=2000)
    client_address: UUID = Field(description="Stable UUID address assigned to the partner CMS")


def validate_email(email: str) -> bool:
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email))


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok", "service": "FlowSense TALQ Gateway", "environment": APP_ENV}


def telegram_api(method: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Call Telegram Bot API without logging bot tokens or verification links."""
    if not TELEGRAM_BOT_TOKEN:
        raise RuntimeError("Telegram bot is not configured.")
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}"
    body = json.dumps(payload).encode("utf-8")
    request = URLRequest(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=12) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (URLError, HTTPError, TimeoutError, ValueError) as exc:
        raise RuntimeError("Telegram Bot API request failed.") from exc
    if not result.get("ok"):
        raise RuntimeError("Telegram Bot API rejected the request.")
    return result.get("result", {})


def send_telegram_message(chat_id: str, text: str) -> None:
    telegram_api("sendMessage", {"chat_id": chat_id, "text": text})


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
    item.status = "key_issued"
    item.verification_token_hash = None
    item.verification_expires_at = None
    item.request_token_hash = None
    db.add(record)
    return record, raw_key


class RequestTokenInput(BaseModel):
    request_token: str = Field(min_length=32, max_length=128)


@app.post("/access-requests", status_code=201, tags=["Access management"])
def request_access(payload: AccessRequestInput, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Create a request and return a one-time Telegram deep link; no key is issued yet."""
    if not validate_email(payload.email):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_BOT_USERNAME or not TELEGRAM_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Telegram verification is not configured. Please try again later.")
    email = payload.email.strip().lower()
    telegram_username = payload.telegram_username.strip().lstrip("@").lower()
    now = datetime.now(timezone.utc)
    verification_token = secrets.token_urlsafe(32)
    request_token = secrets.token_urlsafe(32)
    item = db.scalar(select(AccessRequest).where(
        AccessRequest.email == email,
        AccessRequest.client_address == str(payload.client_address),
        AccessRequest.status == "pending_verification",
    ))
    if item is None:
        item = AccessRequest(
            contact_name=payload.contact_name.strip(), email=email,
            organization=payload.organization.strip(), purpose=payload.purpose.strip(),
            client_address=str(payload.client_address), status="pending_verification",
        )
        db.add(item)
    item.telegram_username = telegram_username
    item.telegram_chat_id = None
    item.telegram_verified_at = None
    item.verification_token_hash = hash_api_key(verification_token)
    item.verification_expires_at = now + timedelta(minutes=TELEGRAM_VERIFICATION_MINUTES)
    item.request_token_hash = hash_api_key(request_token)
    db.commit()
    db.refresh(item)
    return {
        "request_id": item.id,
        "status": item.status,
        "request_token": request_token,
        "telegram_url": f"https://t.me/{TELEGRAM_BOT_USERNAME}?start={verification_token}",
        "verification_expires_at": item.verification_expires_at.isoformat(),
        "message": "Open the Telegram link and press Start. Return here and check verification status; the API key is issued only after verification.",
    }


@app.post("/telegram/webhook", include_in_schema=False)
async def telegram_webhook(request: Request, db: Session = Depends(get_db), secret: str | None = Header(default=None, alias="X-Telegram-Bot-Api-Secret-Token")) -> dict[str, bool]:
    """Accept Telegram webhook updates and bind a request to the real Telegram sender."""
    if not TELEGRAM_WEBHOOK_SECRET or not secret or not secrets.compare_digest(secret, TELEGRAM_WEBHOOK_SECRET):
        raise HTTPException(status_code=401, detail="Invalid webhook secret")
    update = await request.json()
    message = update.get("message") or {}
    sender = message.get("from") or {}
    chat = message.get("chat") or {}
    text = (message.get("text") or "").strip()
    chat_id = chat.get("id")
    parts = text.split(maxsplit=1)
    if not chat_id or not parts or parts[0].split("@")[0] != "/start":
        return {"ok": True}
    if len(parts) != 2:
        try:
            send_telegram_message(str(chat_id), "Welcome to FlowSense Gateway. To verify your account, open the unique verification link from your access request.")
        except Exception as exc:
            print(f"Telegram reply failed: {type(exc).__name__}: {exc}", flush=True)
        return {"ok": True}
    token = parts[1].strip()
    item = db.scalar(select(AccessRequest).where(
        AccessRequest.verification_token_hash == hash_api_key(token),
        AccessRequest.status == "pending_verification",
    ))
    if item is None:
        try:
            send_telegram_message(str(chat_id), "This verification link is invalid or has already been used. Return to the FlowSense console and request a new link.")
        except Exception as exc:
            print(f"Telegram reply failed: {type(exc).__name__}: {exc}", flush=True)
        return {"ok": True}
    expires = _utc(item.verification_expires_at)
    now = datetime.now(timezone.utc)
    if expires is None or expires <= now:
        item.verification_token_hash = None
        item.verification_expires_at = None
        db.commit()
        try:
            send_telegram_message(str(chat_id), "This verification link has expired. Return to the FlowSense console and submit a new request.")
        except Exception as exc:
            print(f"Telegram reply failed: {type(exc).__name__}: {exc}", flush=True)
        return {"ok": True}
    sender_username = str(sender.get("username") or "").lstrip("@").lower()
    if not sender_username or not item.telegram_username or not secrets.compare_digest(sender_username, item.telegram_username):
        try:
            send_telegram_message(str(chat_id), "The Telegram username does not match the username supplied in the access request. Return to the console and check the username.")
        except Exception as exc:
            print(f"Telegram reply failed: {type(exc).__name__}: {exc}", flush=True)
        return {"ok": True}
    item.telegram_chat_id = str(chat_id)
    item.telegram_verified_at = now
    item.verification_token_hash = None
    item.verification_expires_at = None
    item.status = "verified"
    db.commit()
    try:
        send_telegram_message(str(chat_id), "Your FlowSense TALQ Gateway Telegram account is verified. Return to the browser to issue your API key. Keep the key private.")
    except Exception:
        pass
    return {"ok": True}


@app.get("/access-requests/{request_id}/status", tags=["Access management"])
def access_request_status(request_id: int, db: Session = Depends(get_db), x_request_token: str | None = Header(default=None, alias="X-Request-Token")) -> dict[str, Any]:
    item = db.get(AccessRequest, request_id)
    if item is None or not x_request_token or not item.request_token_hash or not secrets.compare_digest(hash_api_key(x_request_token), item.request_token_hash):
        raise HTTPException(status_code=404, detail="Access request not found")
    return {"request_id": item.id, "status": item.status, "telegram_verified": item.telegram_verified_at is not None, "expires_at": item.verification_expires_at.isoformat() if item.verification_expires_at else None}


@app.post("/access-requests/{request_id}/issue-key", tags=["Access management"])
def issue_key_after_telegram_verification(request_id: int, payload: RequestTokenInput, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(AccessRequest, request_id)
    if item is None or not item.request_token_hash or not secrets.compare_digest(hash_api_key(payload.request_token), item.request_token_hash):
        raise HTTPException(status_code=404, detail="Access request not found")
    if item.status != "verified" or item.telegram_verified_at is None:
        raise HTTPException(status_code=409, detail="Telegram verification is not complete")
    # Atomically claim this request so concurrent submissions cannot issue two keys.
    claim = db.execute(
        update(AccessRequest)
        .where(
            AccessRequest.id == request_id,
            AccessRequest.status == "verified",
            AccessRequest.request_token_hash == hash_api_key(payload.request_token),
        )
        .values(status="issuing")
    )
    if claim.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="This access request has already been used or is being processed")
    item.status = "issuing"
    record, raw_key = _new_client_key(item, db)
    db.commit()
    db.refresh(record)
    return {
        "status": "issued", "authenticated": False, "api_key_id": record.id,
        "api_key": raw_key, "client_address": record.client_address,
        "created_at": record.created_at.isoformat(), "expires_at": record.expires_at.isoformat(),
        "lifetime_days": API_KEY_LIFETIME_DAYS,
        "warning": "Copy this key now. It is shown once; only its hash is stored.",
    }


@app.get("/admin/access-requests", tags=["Admin"], dependencies=[Depends(require_admin_key)])
def list_access_requests(
    request_status: str = Query(default="pending_verification", alias="status", pattern="^(pending_verification|verified|issuing|key_issued|all)$"),
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
            "telegram_username": row.telegram_username,
        "telegram_verified_at": row.telegram_verified_at.isoformat() if row.telegram_verified_at else None,
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


@app.post("/auth/api-keys/{key_id}/revoke", tags=["Authentication"])
def revoke_own_api_key(
    key_id: int,
    api_key: ClientAPIKey = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Allow an authenticated integration to revoke keys belonging to the same access request."""
    target = db.get(ClientAPIKey, key_id)
    if target is None or target.access_request_id != api_key.access_request_id:
        raise HTTPException(status_code=404, detail="API key not found")
    if target.revoked_at is None:
        target.revoked_at = datetime.now(timezone.utc)
        db.commit()
    return {"api_key_id": target.id, "revoked": True}


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
