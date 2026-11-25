"""FlowSense TALQ Gateway pilot with approval-based client API keys.

This is a pilot access-management flow, not a complete TALQ implementation.
"""
import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from sqlalchemy import DateTime, ForeignKey, String, Text, bindparam, create_engine, select, text
from sqlalchemy.exc import SQLAlchemyError
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from dotenv import load_dotenv
load_dotenv()
APP_ENV = os.getenv("APP_ENV", "production")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()
EXPECTED_CLIENT_ADDRESS = os.getenv("TALQ_CLIENT_ADDRESS", "").strip()
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
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
    # Existing PostgreSQL pilot schema requires expires_at for every legacy key.
    # Keep the ORM model aligned and give newly approved legacy keys a 30-day TTL.
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc) + timedelta(days=30),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


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
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> ClientAPIKey:
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key required")
    record = db.scalar(select(ClientAPIKey).where(ClientAPIKey.key_hash == hash_api_key(x_api_key)))
    if record is None:
        # Partner-managed keys are stored separately so the legacy key table
        # and its existing rows do not require a destructive schema change.
        integration_key_model = globals().get("IntegrationAPIKey")
        if integration_key_model is not None:
            record = db.scalar(
                select(integration_key_model).where(
                    integration_key_model.key_hash == hash_api_key(x_api_key)
                )
            )
    if record is None or record.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked API key")
    expires_at = getattr(record, "expires_at", None)
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key expired")
    # OAuth-managed partner keys carry explicit data scopes. Legacy manually
    # issued pilot keys retain their existing behavior for backward compatibility.
    granted_scopes = set(getattr(record, "scopes", "").split())
    if hasattr(record, "integration_client_id"):
        path = request.url.path
        required_any = None
        if path.startswith("/devices") or path.startswith("/services") or path == "/integration-status":
            required_any = {"devices:read"}
        elif path.startswith("/measurements"):
            required_any = {"energy:read", "water:read"}
        elif path.startswith("/alerts") or path.startswith("/events"):
            required_any = {"alerts:read"}
        elif path.startswith("/data-packages"):
            required_any = {"energy:read", "water:read", "alerts:read"}
        if required_any and not (granted_scopes & required_any):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="API key lacks the required data scope")
    return record


def require_admin_key(x_admin_key: str | None = Header(default=None, alias="X-Admin-Key")) -> None:
    if not ADMIN_API_KEY:
        raise HTTPException(status_code=503, detail="Admin access is not configured. Set ADMIN_API_KEY.")
    if not x_admin_key or not secrets.compare_digest(x_admin_key, ADMIN_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing admin key")


def require_talq_headers(
    talq_api_version: str | None = Header(default=None, alias="talq-api-version"),
    client_address: str = Query(..., alias="clientAddress"),
    api_key: ClientAPIKey = Depends(require_api_key),
) -> str:
    if talq_api_version != "2.7.1":
        raise HTTPException(status_code=400, detail="talq-api-version must be 2.7.1")
    if client_address != api_key.client_address:
        raise HTTPException(status_code=403, detail="clientAddress does not match the approved API key")
    if EXPECTED_CLIENT_ADDRESS and client_address != EXPECTED_CLIENT_ADDRESS:
        raise HTTPException(status_code=403, detail="Unapproved clientAddress")
    return client_address


class AccessRequestInput(BaseModel):
    contact_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=5, max_length=254)
    organization: str = Field(min_length=2, max_length=160)
    purpose: str = Field(min_length=10, max_length=2000)
    client_address: str = Field(min_length=2, max_length=160)


def validate_email(email: str) -> bool:
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email))


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok", "service": "FlowSense TALQ Gateway", "environment": APP_ENV}


@app.post("/access-requests", status_code=201, tags=["Access management"])
def request_access(payload: AccessRequestInput, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Public endpoint for clients to request API access; issuance requires admin approval."""
    if not validate_email(payload.email):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    email = payload.email.strip().lower()
    pending = db.scalar(
        select(AccessRequest).where(
            AccessRequest.email == email,
            AccessRequest.client_address == payload.client_address.strip(),
            AccessRequest.status == "pending",
        )
    )
    if pending:
        return {"request_id": pending.id, "status": "pending", "message": "A pending request already exists."}
    item = AccessRequest(
        contact_name=payload.contact_name.strip(),
        email=email,
        organization=payload.organization.strip(),
        purpose=payload.purpose.strip(),
        client_address=payload.client_address.strip(),
        status="pending",
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return {
        "request_id": item.id,
        "status": item.status,
        "message": "Access request submitted. An administrator must approve it before an API key is issued.",
    }


@app.get("/admin/access-requests", tags=["Admin"], dependencies=[Depends(require_admin_key)])
def list_access_requests(
    request_status: str = Query(default="pending", alias="status", pattern="^(pending|approved|rejected|all)$"),
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
        }
        for row in rows
    ]


@app.post("/admin/access-requests/{request_id}/approve", tags=["Admin"], dependencies=[Depends(require_admin_key)])
def approve_access_request(request_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(AccessRequest, request_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Access request not found")
    if item.status != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {item.status}")
    enrollment_model = globals().get("PartnerEnrollment")
    enrollment = (
        db.scalar(select(enrollment_model).where(enrollment_model.access_request_id == item.id))
        if enrollment_model is not None else None
    )
    item.status = "approved"
    if enrollment is not None:
        enrollment.status = "approved"
        db.commit()
        return {
            "request_id": item.id,
            "status": "approved",
            "credential_delivery": "partner_public_key_encrypted_claim",
            "message": "OAuth credentials will be delivered to the partner through its one-time encrypted claim.",
        }

    # Backward-compatible legacy approval for requests created through the
    # internal-only legacy endpoint. New partner API requests never receive
    # a legacy API key from the approval operation.
    raw_key = "fs_talq_" + secrets.token_urlsafe(36)
    record = ClientAPIKey(
        access_request_id=item.id,
        label=f"{item.organization} API key",
        organization=item.organization,
        email=item.email,
        client_address=item.client_address,
        key_prefix=raw_key[:15],
        key_hash=hash_api_key(raw_key),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return {
        "request_id": item.id,
        "api_key_id": record.id,
        "status": "approved",
        "client_address": record.client_address,
        "api_key": raw_key,
        "warning": "Copy this key now. It cannot be retrieved later; only its hash is stored.",
    }


@app.post("/admin/access-requests/{request_id}/reject", tags=["Admin"], dependencies=[Depends(require_admin_key)])
def reject_access_request(request_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(AccessRequest, request_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Access request not found")
    if item.status != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {item.status}")
    item.status = "rejected"
    enrollment_model = globals().get("PartnerEnrollment")
    if enrollment_model is not None:
        enrollment = db.scalar(select(enrollment_model).where(
            enrollment_model.access_request_id == item.id
        ))
        if enrollment is not None:
            enrollment.status = "rejected"
            enrollment.encrypted_credentials = None
    db.commit()
    return {"request_id": item.id, "status": "rejected"}


@app.get("/admin/api-keys", tags=["Admin"], dependencies=[Depends(require_admin_key)])
def list_api_keys(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.scalars(select(ClientAPIKey).order_by(ClientAPIKey.id.desc())).all()
    return [
        {
            "id": row.id,
            "label": row.label,
            "organization": row.organization,
            "email": row.email,
            "client_address": row.client_address,
            "key_prefix": row.key_prefix,
            "created_at": row.created_at.isoformat() if row.created_at else None,
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


def get_authorized_facility_ids(
    api_key: Any,
    db: Session,
) -> list[str]:
    """
    Return active facility IDs assigned to an OAuth-managed integration.
    Legacy keys without facility grants receive no RDS data access.
    """
    integration_id = getattr(api_key, "integration_client_id", None)

    if integration_id is None:
        return []

    # Import locally to avoid changing the existing circular-import structure.
    from app.partner_auth import IntegrationFacilityAccess

    facility_ids = db.scalars(
        select(IntegrationFacilityAccess.facility_id).where(
            IntegrationFacilityAccess.integration_client_id == integration_id,
            IntegrationFacilityAccess.is_active.is_(True),
            IntegrationFacilityAccess.revoked_at.is_(None),
        )
    ).all()

    return list(facility_ids)


def fetch_authorized_devices(
    facility_ids: list[str],
    device_code: str | None = None,
) -> list[dict[str, Any]]:
    """Fetch only devices belonging to the supplied authorized facilities."""

    if not facility_ids:
        return []

    device_filter = ""
    params: dict[str, Any] = {"facility_ids": facility_ids}

    if device_code is not None:
        device_filter = "AND d.device_code = :device_code"
        params["device_code"] = device_code

    query = text(f"""
        SELECT
            d.iot_device_id::text AS device_id,
            d.device_code AS device_address,
            d.device_name AS device_name,
            d.device_model AS device_model,
            d.firmware_version AS firmware_version,
            d.communication_protocol AS communication_protocol,
            d.installation_location AS installation_location,
            d.status AS status,
            d.last_seen_at AS last_seen_at,
            f.facility_code AS facility_code
        FROM iot_devices d
        INNER JOIN facilities f
            ON f.facility_id = d.facility_id
        WHERE d.facility_id::text IN :facility_ids
        {device_filter}
        ORDER BY d.device_code
    """).bindparams(
        bindparam("facility_ids", expanding=True)
    )

    try:
        from app.rds_database import rds_engine
        with rds_engine.connect() as connection:
            rows = connection.execute(query, params).mappings().all()

        devices = []

        for row in rows:
            devices.append({
                "deviceId": row["device_id"],
                "deviceAddress": row["device_address"],
                "deviceName": row["device_name"],
                "deviceModel": row["device_model"],
                "firmwareVersion": row["firmware_version"],
                "communicationProtocol": row["communication_protocol"],
                "installationLocation": row["installation_location"],
                "status": row["status"],
                "lastSeenAt": (
                    row["last_seen_at"].isoformat()
                    if row["last_seen_at"] else None
                ),
                "facilityCode": row["facility_code"],
            })

        return devices

    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to retrieve authorized FlowSense devices",
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail="FlowSense RDS is not configured or unavailable",
        ) from exc


def _normalize_time_window(
    start: datetime | None,
    end: datetime | None,
) -> tuple[datetime, datetime]:
    """Default to seven days and reject unbounded or reversed data windows."""
    now = datetime.now(timezone.utc)
    end_time = end or now
    start_time = start or (end_time - timedelta(days=7))
    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=timezone.utc)
    if end_time.tzinfo is None:
        end_time = end_time.replace(tzinfo=timezone.utc)
    if start_time >= end_time:
        raise HTTPException(status_code=422, detail="start must be earlier than end")
    if end_time > now + timedelta(minutes=5):
        raise HTTPException(status_code=422, detail="end cannot be in the future")
    if end_time - start_time > timedelta(days=90):
        raise HTTPException(status_code=422, detail="Time windows cannot exceed 90 days")
    return start_time, end_time


def _partner_measurement_scopes(api_key: Any, requested: str | None = None) -> list[str]:
    """Return only measurement resource types explicitly granted to this key."""
    if getattr(api_key, "integration_client_id", None) is None:
        return []
    scopes = set(getattr(api_key, "scopes", "").split())
    allowed = []
    if "energy:read" in scopes:
        allowed.append("energy")
    if "water:read" in scopes:
        allowed.append("water")
    if requested is not None and requested not in allowed:
        raise HTTPException(status_code=403, detail=f"API key is not authorized for {requested} measurements")
    return [requested] if requested else allowed


def fetch_authorized_measurements(
    facility_ids: list[str], start_time: datetime, end_time: datetime,
    resource_types: list[str], limit: int = 100, offset: int = 0,
) -> list[dict[str, Any]]:
    """Read meter and sensor measurements using facility-filtered, bounded SQL."""
    if not facility_ids or not resource_types:
        return []
    query = text("""
        SELECT *
        FROM (
            SELECT
                'meter' AS source_type,
                mr.reading_id::text AS reading_id,
                mr.reading_time AS reading_time,
                mr.reading_value::double precision AS value,
                m.unit AS unit,
                CASE
                    WHEN lower(m.resource_type) LIKE '%water%' THEN 'water'
                    WHEN lower(m.resource_type) LIKE '%energy%' OR lower(m.resource_type) LIKE '%electric%' THEN 'energy'
                    ELSE lower(m.resource_type)
                END AS resource_type,
                m.meter_code AS source_code,
                m.meter_name AS source_name,
                f.facility_code AS facility_code,
                mr.quality_status AS quality_status
            FROM meter_readings mr
            INNER JOIN meters m ON m.meter_id = mr.meter_id
            INNER JOIN facilities f ON f.facility_id = m.facility_id
            WHERE m.facility_id::text IN :meter_facility_ids
              AND mr.reading_time >= :start_time AND mr.reading_time < :end_time
              AND (
                    (lower(m.resource_type) LIKE '%water%' AND 'water' IN :resource_types)
                 OR ((lower(m.resource_type) LIKE '%energy%' OR lower(m.resource_type) LIKE '%electric%')
                     AND 'energy' IN :resource_types)
              )
            UNION ALL
            SELECT
                'sensor' AS source_type,
                sr.reading_id::text AS reading_id,
                sr.reading_time AS reading_time,
                sr.numeric_value::double precision AS value,
                s.unit AS unit,
                CASE
                    WHEN lower(coalesce(m.resource_type, s.measurement, s.sensor_type)) LIKE '%water%' THEN 'water'
                    WHEN lower(coalesce(m.resource_type, s.measurement, s.sensor_type)) LIKE '%energy%'
                      OR lower(coalesce(m.resource_type, s.measurement, s.sensor_type)) LIKE '%electric%' THEN 'energy'
                    ELSE lower(coalesce(m.resource_type, s.measurement, s.sensor_type))
                END AS resource_type,
                s.sensor_code AS source_code,
                s.sensor_name AS source_name,
                f.facility_code AS facility_code,
                sr.quality_status AS quality_status
            FROM sensor_readings sr
            INNER JOIN iot_sensors s ON s.sensor_id = sr.sensor_id
            INNER JOIN iot_devices d ON d.iot_device_id = s.iot_device_id
            INNER JOIN facilities f ON f.facility_id = d.facility_id
            LEFT JOIN meters m ON m.meter_id = s.source_meter_id
            WHERE d.facility_id::text IN :sensor_facility_ids
              AND sr.reading_time >= :start_time AND sr.reading_time < :end_time
              AND sr.numeric_value IS NOT NULL
              AND (
                    (lower(coalesce(m.resource_type, s.measurement, s.sensor_type)) LIKE '%water%'
                     AND 'water' IN :resource_types)
                 OR ((lower(coalesce(m.resource_type, s.measurement, s.sensor_type)) LIKE '%energy%'
                      OR lower(coalesce(m.resource_type, s.measurement, s.sensor_type)) LIKE '%electric%')
                     AND 'energy' IN :resource_types)
              )
        ) AS authorized_measurements
        ORDER BY reading_time DESC, reading_id DESC
        LIMIT :limit OFFSET :offset
    """).bindparams(
        bindparam("meter_facility_ids", expanding=True),
        bindparam("sensor_facility_ids", expanding=True),
        bindparam("resource_types", expanding=True),
    )
    params = {
        "meter_facility_ids": facility_ids, "sensor_facility_ids": facility_ids,
        "resource_types": resource_types, "start_time": start_time, "end_time": end_time,
        "limit": limit, "offset": offset,
    }
    try:
        from app.rds_database import rds_engine
        with rds_engine.connect() as connection:
            rows = connection.execute(query, params).mappings().all()
        return [{
            "readingId": row["reading_id"],
            "sourceType": row["source_type"],
            "timestamp": row["reading_time"].isoformat() if row["reading_time"] else None,
            "value": row["value"], "unit": row["unit"], "resourceType": row["resource_type"],
            "sourceCode": row["source_code"], "sourceName": row["source_name"],
            "facilityCode": row["facility_code"], "qualityStatus": row["quality_status"],
        } for row in rows]
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="Unable to retrieve authorized FlowSense measurements") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="FlowSense RDS is not configured or unavailable") from exc


def fetch_authorized_alerts(
    facility_ids: list[str], start_time: datetime, end_time: datetime,
    limit: int = 100, offset: int = 0,
) -> list[dict[str, Any]]:
    """Read FlowSense alerts only for facilities granted to this partner."""
    if not facility_ids:
        return []
    query = text("""
        SELECT a.alert_id::text AS alert_id, a.anomaly_id::text AS anomaly_id,
               a.facility_id::text AS facility_id, f.facility_code AS facility_code,
               a.alert_title AS alert_title, a.alert_message AS alert_message,
               a.severity AS severity, a.triggered_at AS triggered_at, a.status AS status
        FROM alerts a
        INNER JOIN facilities f ON f.facility_id = a.facility_id
        WHERE a.facility_id::text IN :facility_ids
          AND a.triggered_at >= :start_time AND a.triggered_at < :end_time
        ORDER BY a.triggered_at DESC, a.alert_id DESC
        LIMIT :limit OFFSET :offset
    """).bindparams(bindparam("facility_ids", expanding=True))
    try:
        from app.rds_database import rds_engine
        with rds_engine.connect() as connection:
            rows = connection.execute(query, {
                "facility_ids": facility_ids, "start_time": start_time,
                "end_time": end_time, "limit": limit, "offset": offset,
            }).mappings().all()
        return [{
            "alertId": row["alert_id"], "anomalyId": row["anomaly_id"],
            "facilityId": row["facility_id"], "facilityCode": row["facility_code"],
            "title": row["alert_title"], "message": row["alert_message"],
            "severity": row["severity"],
            "triggeredAt": row["triggered_at"].isoformat() if row["triggered_at"] else None,
            "status": row["status"],
        } for row in rows]
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="Unable to retrieve authorized FlowSense alerts") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="FlowSense RDS is not configured or unavailable") from exc


@app.get("/measurements", tags=["Measurements"])
def list_measurements(
    client_address: str = Depends(require_talq_headers),
    api_key: Any = Depends(require_api_key), db: Session = Depends(get_db),
    start: datetime | None = Query(default=None), end: datetime | None = Query(default=None),
    resource_type: str | None = Query(default=None, pattern="^(energy|water)$"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=100000),
) -> dict[str, Any]:
    start_time, end_time = _normalize_time_window(start, end)
    resource_types = _partner_measurement_scopes(api_key, resource_type)
    facility_ids = get_authorized_facility_ids(api_key, db)
    rows = fetch_authorized_measurements(facility_ids, start_time, end_time, resource_types, limit + 1, offset)
    has_more = len(rows) > limit
    rows = rows[:limit]
    return {
        "measurements": rows, "count": len(rows), "limit": limit, "offset": offset,
        "hasMore": has_more, "start": start_time.isoformat(), "end": end_time.isoformat(),
        "clientAddress": client_address,
    }


@app.get("/alerts", tags=["Alerts"])
def list_alerts(
    client_address: str = Depends(require_talq_headers),
    api_key: Any = Depends(require_api_key), db: Session = Depends(get_db),
    start: datetime | None = Query(default=None), end: datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=100000),
) -> dict[str, Any]:
    start_time, end_time = _normalize_time_window(start, end)
    facility_ids = get_authorized_facility_ids(api_key, db)
    rows = fetch_authorized_alerts(facility_ids, start_time, end_time, limit + 1, offset)
    has_more = len(rows) > limit
    rows = rows[:limit]
    return {
        "alerts": rows, "count": len(rows), "limit": limit, "offset": offset,
        "hasMore": has_more, "start": start_time.isoformat(), "end": end_time.isoformat(),
        "clientAddress": client_address,
    }


@app.get("/events", tags=["Events"])
def list_events(
    client_address: str = Depends(require_talq_headers),
    api_key: Any = Depends(require_api_key), db: Session = Depends(get_db),
    start: datetime | None = Query(default=None), end: datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=100000),
) -> dict[str, Any]:
    """Expose FlowSense alert lifecycle records as gateway events."""
    start_time, end_time = _normalize_time_window(start, end)
    facility_ids = get_authorized_facility_ids(api_key, db)
    rows = fetch_authorized_alerts(facility_ids, start_time, end_time, limit + 1, offset)
    has_more = len(rows) > limit
    events = [{
        "eventId": row["alertId"], "eventType": "alert", "eventTime": row["triggeredAt"],
        "facilityCode": row["facilityCode"], "severity": row["severity"],
        "status": row["status"], "title": row["title"], "message": row["message"],
        "anomalyId": row["anomalyId"],
    } for row in rows[:limit]]
    return {
        "events": events, "count": len(events), "limit": limit, "offset": offset,
        "hasMore": has_more, "start": start_time.isoformat(), "end": end_time.isoformat(),
        "clientAddress": client_address,
    }


@app.get("/data-packages", tags=["Data packages"])
def list_data_packages(
    client_address: str = Depends(require_talq_headers),
    api_key: Any = Depends(require_api_key), db: Session = Depends(get_db),
    start: datetime | None = Query(default=None), end: datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """Build data packages from live records within the partner's granted facilities."""
    start_time, end_time = _normalize_time_window(start, end)
    facility_ids = get_authorized_facility_ids(api_key, db)
    scopes = set(getattr(api_key, "scopes", "").split())
    packages: list[dict[str, Any]] = []
    resource_types = _partner_measurement_scopes(api_key)
    if resource_types:
        measurements = fetch_authorized_measurements(facility_ids, start_time, end_time, resource_types, limit, 0)
        packages.append({
            "packageId": "flow-measurements", "packageType": "measurements",
            "resourceTypes": resource_types, "count": len(measurements), "records": measurements,
        })
    if "alerts:read" in scopes:
        alerts = fetch_authorized_alerts(facility_ids, start_time, end_time, limit, 0)
        packages.append({
            "packageId": "flow-alert-events", "packageType": "alerts-and-events",
            "count": len(alerts), "records": alerts,
        })
    return {
        "dataPackages": packages, "count": len(packages),
        "start": start_time.isoformat(), "end": end_time.isoformat(),
        "clientAddress": client_address,
    }


@app.get("/devices")
def list_devices(
    client_address: str = Depends(require_talq_headers),
    api_key: Any = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    facility_ids = get_authorized_facility_ids(api_key, db)
    devices = fetch_authorized_devices(facility_ids)

    return {
        "devices": devices,
        "clientAddress": client_address,
        "count": len(devices),
    }


@app.get("/devices/count")
def count_devices(
    client_address: str = Depends(require_talq_headers),
    api_key: Any = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    facility_ids = get_authorized_facility_ids(api_key, db)
    devices = fetch_authorized_devices(facility_ids)

    return {
        "count": len(devices),
        "clientAddress": client_address,
    }


@app.get("/devices/{deviceAddress}")
def get_device(
    deviceAddress: str,
    client_address: str = Depends(require_talq_headers),
    api_key: Any = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> JSONResponse:
    facility_ids = get_authorized_facility_ids(api_key, db)

    devices = fetch_authorized_devices(
        facility_ids,
        device_code=deviceAddress,
    )

    if not devices:
        raise HTTPException(
            status_code=404,
            detail="Device not found in authorized facilities",
        )

    return JSONResponse({
        "device": devices[0],
        "clientAddress": client_address,
    })

@app.get("/services", dependencies=[Depends(require_api_key)])
def list_services(client_address: str = Depends(require_talq_headers)) -> dict[str, Any]:
    return {"services": SERVICES, "clientAddress": client_address}


@app.get("/services/{serviceName}", dependencies=[Depends(require_api_key)])
def get_service(serviceName: str, client_address: str = Depends(require_talq_headers)) -> dict[str, Any]:
    if serviceName not in SERVICES:
        raise HTTPException(status_code=404, detail="Service not found")
    return {"serviceName": serviceName, "available": True, "clientAddress": client_address}




# Register the backend-only OAuth and partner key lifecycle routes after the
# existing gateway models and dependencies have been defined.
from app.partner_auth import router as partner_auth_router  # noqa: E402
from app.onboarding import PartnerEnrollment, router as onboarding_router  # noqa: E402

app.include_router(partner_auth_router)
app.include_router(onboarding_router)
