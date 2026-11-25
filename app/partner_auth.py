"""OAuth client credentials and partner-owned TALQ API key lifecycle.

This module extends the existing FlowSense gateway pilot. It is LAN-deployable
and does not require a partner-facing web application.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Mapped, Session, mapped_column
from pydantic import BaseModel, Field

from app import main as gateway
router = APIRouter(tags=["Partner integrations"])
basic_auth = HTTPBasic(auto_error=False)

ALLOWED_DATA_SCOPES = {"energy:read", "water:read", "devices:read", "alerts:read"}
ACCESS_TOKEN_TTL_SECONDS = 3600
DEFAULT_API_KEY_TTL_DAYS = 30


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ProvisionIntegrationInput(BaseModel):
    # Least privilege: device-read access is the default. Admins may explicitly
    # approve additional data categories when provisioning a partner.
    scopes: list[str] = Field(default_factory=lambda: ["devices:read"])
class GrantFacilityAccessInput(BaseModel):
    facility_code: str = Field(min_length=1, max_length=80)

class IntegrationClient(gateway.Base):
    __tablename__ = "integration_clients"

    id: Mapped[int] = mapped_column(primary_key=True)
    access_request_id: Mapped[int] = mapped_column(
        ForeignKey("access_requests.id"), unique=True, index=True
    )
    client_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    client_secret_hash: Mapped[str] = mapped_column(String(64))
    scopes: Mapped[str] = mapped_column(Text, default="keys:manage energy:read water:read devices:read alerts:read")
    is_active: Mapped[bool] = mapped_column(default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class OAuthAccessToken(gateway.Base):
    __tablename__ = "oauth_access_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Existing PostgreSQL installations have oauth_client_id pointing to the
    # legacy oauth_clients table. Keep it nullable for backward compatibility;
    # new partner tokens use integration_client_id.
    oauth_client_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    integration_client_id: Mapped[int | None] = mapped_column(
        ForeignKey("integration_clients.id"), nullable=True, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scopes: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class IntegrationAPIKey(gateway.Base):
    __tablename__ = "integration_api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    integration_client_id: Mapped[int] = mapped_column(
        ForeignKey("integration_clients.id"), index=True
    )
    label: Mapped[str] = mapped_column(String(160))
    organization: Mapped[str] = mapped_column(String(160))
    email: Mapped[str] = mapped_column(String(254))
    client_address: Mapped[str] = mapped_column(String(160), index=True)
    key_prefix: Mapped[str] = mapped_column(String(20))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scopes: Mapped[str] = mapped_column(Text, default="devices:read")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class IntegrationFacilityAccess(gateway.Base):
    """Facility-level authorization for partner integrations."""
    __tablename__ = "integration_facility_access"

    __table_args__ = (
        UniqueConstraint(
            "integration_client_id",
            "facility_id",
            name="uq_integration_facility_access",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    integration_client_id: Mapped[int] = mapped_column(
        ForeignKey("integration_clients.id"),
        index=True,
    )

    # These identifiers belong to the separate FlowSense RDS database.
    # No cross-database foreign key is used.
    facility_id: Mapped[str] = mapped_column(String(36), index=True)
    facility_code: Mapped[str] = mapped_column(String(80), index=True)

    is_active: Mapped[bool] = mapped_column(default=True, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_now,
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

# Create only the new tables; existing gateway tables are left unchanged.
gateway.Base.metadata.create_all(bind=gateway.engine)
# The gateway's existing X-API-Key dependency uses this model as an additional
# credential store, so keys issued here work on the existing protected routes.
gateway.IntegrationAPIKey = IntegrationAPIKey


def _scopes(client: IntegrationClient) -> set[str]:
    return {part for part in client.scopes.split() if part}

@router.post("/admin/integrations/{integration_id}/facilities", tags=["Admin"])
def grant_facility_access(
    integration_id: int,
    payload: GrantFacilityAccessInput,
    _: None = Depends(gateway.require_admin_key),
    db: Session = Depends(gateway.get_db),
) -> dict[str, Any]:
    """Grant an integration access to one verified FlowSense facility."""

    client = db.get(IntegrationClient, integration_id)

    if client is None:
        raise HTTPException(status_code=404, detail="Integration not found")

    if not client.is_active:
        raise HTTPException(status_code=409, detail="Integration is inactive")

    facility_code = payload.facility_code.strip()

    if not facility_code:
        raise HTTPException(status_code=422, detail="facility_code cannot be blank")

    # Verify the facility against the actual FlowSense RDS database.
    try:
        # Initialize the FlowSense RDS engine only when this endpoint is used.
        # This keeps application startup and CI tests independent of RDS secrets.
        from app.rds_database import rds_engine

        with rds_engine.connect() as connection:
            facility = connection.execute(
                text("""
                    SELECT
                        facility_id::text AS facility_id,
                        facility_code,
                        facility_name,
                        status
                    FROM facilities
                    WHERE facility_code = :facility_code
                    LIMIT 1
                """),
                {"facility_code": facility_code},
            ).mappings().first()

    except (SQLAlchemyError, RuntimeError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to validate facility against FlowSense RDS",
        ) from exc

    if facility is None:
        raise HTTPException(status_code=404, detail="Facility not found in FlowSense")

    # Reuse an existing permission if it was previously revoked.
    access = db.scalar(
        select(IntegrationFacilityAccess).where(
            IntegrationFacilityAccess.integration_client_id == client.id,
            IntegrationFacilityAccess.facility_id == facility["facility_id"],
        )
    )

    if access is not None:
        access.facility_code = facility["facility_code"]
        access.is_active = True
        access.revoked_at = None
    else:
        access = IntegrationFacilityAccess(
            integration_client_id=client.id,
            facility_id=facility["facility_id"],
            facility_code=facility["facility_code"],
            is_active=True,
        )
        db.add(access)

    db.commit()
    db.refresh(access)

    return {
        "message": "Facility access granted",
        "integration_id": client.id,
        "facility_id": access.facility_id,
        "facility_code": access.facility_code,
        "facility_name": facility["facility_name"],
        "facility_status": facility["status"],
        "active": access.is_active,
    }


@router.get("/admin/integrations/{integration_id}/facilities", tags=["Admin"])
def list_integration_facilities(
    integration_id: int,
    _: None = Depends(gateway.require_admin_key),
    db: Session = Depends(gateway.get_db),
) -> dict[str, Any]:
    """List all facility permissions assigned to an integration."""

    client = db.get(IntegrationClient, integration_id)

    if client is None:
        raise HTTPException(status_code=404, detail="Integration not found")

    rows = db.scalars(
        select(IntegrationFacilityAccess)
        .where(
            IntegrationFacilityAccess.integration_client_id == client.id
        )
        .order_by(IntegrationFacilityAccess.facility_code)
    ).all()

    return {
        "integration_id": client.id,
        "count": len(rows),
        "facilities": [
            {
                "facility_id": row.facility_id,
                "facility_code": row.facility_code,
                "active": row.is_active,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
            }
            for row in rows
        ],
    }


@router.delete(
    "/admin/integrations/{integration_id}/facilities/{facility_code}",
    tags=["Admin"],
)
def revoke_facility_access(
    integration_id: int,
    facility_code: str,
    _: None = Depends(gateway.require_admin_key),
    db: Session = Depends(gateway.get_db),
) -> dict[str, Any]:
    """Revoke a partner's access to a specific facility."""

    client = db.get(IntegrationClient, integration_id)

    if client is None:
        raise HTTPException(status_code=404, detail="Integration not found")

    access = db.scalar(
        select(IntegrationFacilityAccess).where(
            IntegrationFacilityAccess.integration_client_id == client.id,
            IntegrationFacilityAccess.facility_code == facility_code,
        )
    )

    if access is None:
        raise HTTPException(status_code=404, detail="Facility permission not found")

    if access.is_active:
        access.is_active = False
        access.revoked_at = _now()
        db.commit()

    return {
        "message": "Facility access revoked",
        "integration_id": client.id,
        "facility_code": access.facility_code,
        "active": False,
        "revoked_at": access.revoked_at.isoformat() if access.revoked_at else None,
    }


def require_oauth_token(
    authorization: str | None = Header(default=None, alias="Authorization"),
    db: Session = Depends(gateway.get_db),
) -> OAuthAccessToken:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer access token required")
    raw_token = authorization[7:].strip()
    if not raw_token:
        raise HTTPException(status_code=401, detail="Bearer access token required")
    token = db.scalar(select(OAuthAccessToken).where(OAuthAccessToken.token_hash == _hash(raw_token)))
    if token is None or token.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Invalid or revoked access token")
    expires = token.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= _now():
        raise HTTPException(status_code=401, detail="Access token expired")
    client = (
        db.get(IntegrationClient, token.integration_client_id)
        if token.integration_client_id is not None else None
    )
    if client is None or not client.is_active:
        raise HTTPException(status_code=401, detail="Integration client is inactive")
    return token


def require_scope(required: str):
    def dependency(token: OAuthAccessToken = Depends(require_oauth_token)) -> OAuthAccessToken:
        if required not in set(token.scopes.split()):
            raise HTTPException(status_code=403, detail=f"Required scope: {required}")
        return token
    return dependency


@router.post("/admin/integrations/{integration_id}/rotate-secret", tags=["Admin"])
def rotate_client_secret(
    integration_id: int,
    _: None = Depends(gateway.require_admin_key),
    db: Session = Depends(gateway.get_db),
) -> dict[str, Any]:
    """Rotate a partner client secret; the new value is returned exactly once."""
    client = db.get(IntegrationClient, integration_id)
    if client is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    if not client.is_active:
        raise HTTPException(status_code=409, detail="Cannot rotate credentials for an inactive integration")

    new_secret = secrets.token_urlsafe(48)
    client.client_secret_hash = _hash(new_secret)

    # Revoke outstanding bearer tokens so the partner must authenticate again.
    now = _now()
    active_tokens = db.scalars(
        select(OAuthAccessToken).where(
            OAuthAccessToken.integration_client_id == client.id,
            OAuthAccessToken.revoked_at.is_(None),
        )
    ).all()
    for token in active_tokens:
        token.revoked_at = now

    db.commit()
    return {
        "integration_id": client.id,
        "client_id": client.client_id,
        "client_secret": new_secret,
        "revoked_access_tokens": len(active_tokens),
        "warning": "Save the new client secret now. It is shown once and cannot be retrieved.",
    }


@router.post("/admin/integrations/{request_id}/provision", tags=["Admin"])
def provision_integration(
    request_id: int,
    payload: ProvisionIntegrationInput = ProvisionIntegrationInput(),
    _: None = Depends(gateway.require_admin_key),
    db: Session = Depends(gateway.get_db),
) -> dict[str, Any]:
    """Provision permanent client credentials for an approved access request."""
    request_record = db.get(gateway.AccessRequest, request_id)
    if request_record is None:
        raise HTTPException(status_code=404, detail="Access request not found")
    if request_record.status != "approved":
        raise HTTPException(status_code=409, detail="Approve the access request before provisioning")
    existing = db.scalar(
        select(IntegrationClient).where(IntegrationClient.access_request_id == request_id)
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail="An integration client already exists for this request")

    requested_scopes = set(payload.scopes)
    if not requested_scopes or not requested_scopes.issubset(ALLOWED_DATA_SCOPES):
        raise HTTPException(status_code=422, detail={"allowed_scopes": sorted(ALLOWED_DATA_SCOPES)})

    client_id = "fs_client_" + secrets.token_urlsafe(18)
    client_secret = secrets.token_urlsafe(48)
    client = IntegrationClient(
        access_request_id=request_record.id,
        client_id=client_id,
        client_secret_hash=_hash(client_secret),
        scopes=" ".join(sorted(requested_scopes | {"keys:manage"})),
        is_active=True,
    )
    db.add(client)
    db.flush()

    # API-originated partner enrollments have a submitted public key. In that
    # case the client secret is never returned to the administrator or logged:
    # it is sealed to the partner's public key and claimed exactly once.
    from app.onboarding import PartnerEnrollment, audit_enrollment, encrypt_credentials
    enrollment = db.scalar(select(PartnerEnrollment).where(
        PartnerEnrollment.access_request_id == request_record.id
    ))
    if enrollment is not None:
        enrollment.encrypted_credentials = encrypt_credentials(
            enrollment.public_key_pem,
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "integration_id": client.id,
                "scopes": sorted(requested_scopes | {"keys:manage"}),
                "token_url": "/oauth/token",
            },
        )
        enrollment.status = "credentials_ready"
        enrollment.claim_expires_at = _now() + timedelta(minutes=30)
        audit_enrollment(
            db, request_record.id, "credentials_provisioned", "admin",
            {"integration_id": client.id, "scopes": sorted(requested_scopes | {"keys:manage"})},
        )
        db.commit()
        db.refresh(client)
        return {
            "integration_id": client.id,
            "client_id": client.client_id,
            "scopes": sorted(requested_scopes | {"keys:manage"}),
            "credential_delivery": "encrypted_one_time_claim",
            "claim_expires_at": enrollment.claim_expires_at.isoformat(),
            "message": "Credentials encrypted for the partner public key. The partner must claim them within 30 minutes.",
        }

    db.commit()
    db.refresh(client)
    return {
        "integration_id": client.id,
        "client_id": client.client_id,
        "client_secret": client_secret,
        "scopes": sorted(requested_scopes | {"keys:manage"}),
        "warning": "Legacy internal provisioning: save the client secret now. It is shown once and cannot be retrieved.",
    }


@router.post("/oauth/token", tags=["Authentication"])
async def issue_access_token(
    request: Request,
    credentials: HTTPBasicCredentials | None = Depends(basic_auth),
    db: Session = Depends(gateway.get_db),
) -> dict[str, Any]:
    """OAuth 2.0 client-credentials token endpoint (HTTP Basic client authentication)."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Client authentication required",
                            headers={"WWW-Authenticate": "Basic"})
    form = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
    grant_type = form.get("grant_type", [""])[0]
    if grant_type != "client_credentials":
        raise HTTPException(status_code=400, detail="grant_type must be client_credentials")

    client = db.scalar(select(IntegrationClient).where(IntegrationClient.client_id == credentials.username))
    if client is None or not client.is_active or not secrets.compare_digest(
        client.client_secret_hash, _hash(credentials.password)
    ):
        raise HTTPException(status_code=401, detail="Invalid client credentials",
                            headers={"WWW-Authenticate": "Basic"})

    requested = set(form.get("scope", [""])[0].split())
    allowed = _scopes(client)
    granted = requested if requested else allowed
    if not granted.issubset(allowed):
        raise HTTPException(status_code=400, detail="Requested scope is not allowed for this client")

    raw_token = secrets.token_urlsafe(48)
    expires_at = _now() + timedelta(seconds=ACCESS_TOKEN_TTL_SECONDS)
    token = OAuthAccessToken(
        integration_client_id=client.id,
        token_hash=_hash(raw_token),
        scopes=" ".join(sorted(granted)),
        expires_at=expires_at,
    )
    db.add(token)
    db.commit()
    return {
        "access_token": raw_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        "scope": " ".join(sorted(granted)),
    }


def _client_for_token(token: OAuthAccessToken, db: Session) -> tuple[IntegrationClient, gateway.AccessRequest]:
    client = (
        db.get(IntegrationClient, token.integration_client_id)
        if token.integration_client_id is not None else None
    )
    if client is None or not client.is_active:
        raise HTTPException(status_code=401, detail="Integration client is inactive")
    request_record = db.get(gateway.AccessRequest, client.access_request_id)
    if request_record is None or request_record.status != "approved":
        raise HTTPException(status_code=403, detail="Partner access is not approved")
    return client, request_record


@router.get("/integrations/me", tags=["Partner integrations"])
def get_my_integration(
    token: OAuthAccessToken = Depends(require_oauth_token),
    db: Session = Depends(gateway.get_db),
) -> dict[str, Any]:
    client, request_record = _client_for_token(token, db)
    return {
        "integration_id": client.id,
        "client_id": client.client_id,
        "organization": request_record.organization,
        "client_address": request_record.client_address,
        "scopes": sorted(_scopes(client)),
        "active": client.is_active,
    }


@router.post("/integrations/me/api-keys", tags=["Partner API keys"])
def create_partner_api_key(
    token: OAuthAccessToken = Depends(require_scope("keys:manage")),
    db: Session = Depends(gateway.get_db),
) -> dict[str, Any]:
    client, request_record = _client_for_token(token, db)
    raw_key = "fs_talq_" + secrets.token_urlsafe(36)
    expires_at = _now() + timedelta(days=DEFAULT_API_KEY_TTL_DAYS)
    record = IntegrationAPIKey(
        integration_client_id=client.id,
        label=f"{request_record.organization} integration key",
        organization=request_record.organization,
        email=request_record.email,
        client_address=request_record.client_address,
        key_prefix=raw_key[:15],
        key_hash=_hash(raw_key),
        scopes=" ".join(sorted(set(token.scopes.split()) - {"keys:manage"})),
        expires_at=expires_at,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return {
        "key_id": record.id,
        "api_key": raw_key,
        "status": "active",
        "scopes": record.scopes.split(),
        "expires_at": expires_at.isoformat(),
        "warning": "Save this API key now. It is returned once and cannot be retrieved.",
    }


@router.get("/integrations/me/api-keys", tags=["Partner API keys"])
def list_partner_api_keys(
    token: OAuthAccessToken = Depends(require_scope("keys:manage")),
    db: Session = Depends(gateway.get_db),
) -> list[dict[str, Any]]:
    client, _ = _client_for_token(token, db)
    rows = db.scalars(
        select(IntegrationAPIKey)
        .where(IntegrationAPIKey.integration_client_id == client.id)
        .order_by(IntegrationAPIKey.id.desc())
    ).all()
    return [{
        "key_id": row.id,
        "key_prefix": row.key_prefix,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "revoked": row.revoked_at is not None,
    } for row in rows]


@router.post("/integrations/me/api-keys/{key_id}/rotate", tags=["Partner API keys"])
def rotate_partner_api_key(
    key_id: int,
    token: OAuthAccessToken = Depends(require_scope("keys:manage")),
    db: Session = Depends(gateway.get_db),
) -> dict[str, Any]:
    """Issue replacement key; old key remains valid until explicitly retired."""
    client, request_record = _client_for_token(token, db)
    old = db.get(IntegrationAPIKey, key_id)
    if old is None or old.integration_client_id != client.id:
        raise HTTPException(status_code=404, detail="API key not found for this integration")
    if old.revoked_at is not None:
        raise HTTPException(status_code=409, detail="Cannot rotate a revoked API key")
    old_expiry = old.expires_at
    if old_expiry.tzinfo is None:
        old_expiry = old_expiry.replace(tzinfo=timezone.utc)
    if old_expiry <= _now():
        raise HTTPException(status_code=409, detail="Cannot rotate an expired API key")

    raw_key = "fs_talq_" + secrets.token_urlsafe(36)
    expires_at = _now() + timedelta(days=DEFAULT_API_KEY_TTL_DAYS)
    replacement = IntegrationAPIKey(
        integration_client_id=client.id,
        label=f"{request_record.organization} rotated integration key",
        organization=request_record.organization,
        email=request_record.email,
        client_address=request_record.client_address,
        key_prefix=raw_key[:15],
        key_hash=_hash(raw_key),
        scopes=" ".join(sorted(set(token.scopes.split()) - {"keys:manage"})),
        expires_at=expires_at,
    )
    db.add(replacement)
    db.commit()
    db.refresh(replacement)
    return {
        "key_id": replacement.id,
        "api_key": raw_key,
        "expires_at": expires_at.isoformat(),
        "scopes": replacement.scopes.split(),
        "previous_key_id": old.id,
        "previous_key_remains_active": True,
        "next_step": f"Test the new key, then POST /integrations/me/api-keys/{old.id}/retire",
    }


@router.post("/integrations/me/api-keys/{key_id}/retire", tags=["Partner API keys"])
def retire_partner_api_key(
    key_id: int,
    token: OAuthAccessToken = Depends(require_scope("keys:manage")),
    db: Session = Depends(gateway.get_db),
) -> dict[str, Any]:
    client, _ = _client_for_token(token, db)
    record = db.get(IntegrationAPIKey, key_id)
    if record is None or record.integration_client_id != client.id:
        raise HTTPException(status_code=404, detail="API key not found for this integration")
    if record.revoked_at is None:
        record.revoked_at = _now()
        db.commit()
    return {"key_id": record.id, "revoked": True}


@router.post("/integrations/me/api-keys/{key_id}/revoke", tags=["Partner API keys"])
def revoke_partner_api_key(
    key_id: int,
    token: OAuthAccessToken = Depends(require_scope("keys:manage")),
    db: Session = Depends(gateway.get_db),
) -> dict[str, Any]:
    return retire_partner_api_key(key_id, token, db)




@router.post("/admin/integrations/{integration_id}/suspend", tags=["Admin"])
def suspend_integration(
    integration_id: int,
    _: None = Depends(gateway.require_admin_key),
    db: Session = Depends(gateway.get_db),
) -> dict[str, Any]:
    """Immediately disable a partner and revoke its outstanding credentials."""
    client = db.get(IntegrationClient, integration_id)
    if client is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    client.is_active = False
    now = _now()
    tokens = db.scalars(
        select(OAuthAccessToken).where(
            OAuthAccessToken.integration_client_id == client.id,
            OAuthAccessToken.revoked_at.is_(None),
        )
    ).all()
    keys = db.scalars(
        select(IntegrationAPIKey).where(
            IntegrationAPIKey.integration_client_id == client.id,
            IntegrationAPIKey.revoked_at.is_(None),
        )
    ).all()
    for token in tokens:
        token.revoked_at = now
    for key in keys:
        key.revoked_at = now
    db.commit()
    return {
        "integration_id": client.id,
        "active": False,
        "revoked_access_tokens": len(tokens),
        "revoked_api_keys": len(keys),
    }
