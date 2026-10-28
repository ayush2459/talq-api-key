"""Read-only FlowSense PostgreSQL data API for the TALQ gateway.

Uses a separate FLOW_SENSE_DATABASE_URL so the gateway's own key/Telegram
database remains isolated. Configure that URL with a least-privilege, read-only
PostgreSQL account.
"""
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

router = APIRouter(prefix="/data", tags=["FlowSense live data"])

DATABASE_URL = os.getenv("FLOW_SENSE_DATABASE_URL", "").strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

# Do not fall back to the gateway's key database. Missing configuration should
# fail closed instead of accidentally returning unrelated data.
IAM_AUTH = os.getenv("FLOW_SENSE_IAM_AUTH", "false").strip().lower() in {"1", "true", "yes"}
AWS_REGION = (os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "ap-southeast-1").strip()
_db_url = make_url(DATABASE_URL) if DATABASE_URL else None
engine = create_engine(
    _db_url,
    pool_pre_ping=True,
    # IAM auth tokens expire after 15 minutes; recycle pooled connections early.
    pool_recycle=600 if IAM_AUTH else 1800,
) if _db_url else None

if engine is not None and IAM_AUTH:
    if _db_url.drivername not in {"postgresql+psycopg", "postgresql"}:
        raise RuntimeError("FLOW_SENSE_IAM_AUTH requires a PostgreSQL FLOW_SENSE_DATABASE_URL")
    if not _db_url.host or not _db_url.username:
        raise RuntimeError("IAM auth requires a database hostname and username in FLOW_SENSE_DATABASE_URL")

    @event.listens_for(engine, "do_connect")
    def _add_iam_auth_token(dialect, conn_rec, cargs, cparams):
        # Generate a fresh token for every new DB connection; never store it in the URL.
        rds = boto3.client("rds", region_name=AWS_REGION)
        cparams["password"] = rds.generate_db_auth_token(
            DBHostname=_db_url.host,
            Port=_db_url.port or 5432,
            DBUsername=_db_url.username,
            Region=AWS_REGION,
        )
        cparams["sslmode"] = "require"


def _db():
    if engine is None:
        raise HTTPException(
            status_code=503,
            detail="FlowSense data source is not configured. Set FLOW_SENSE_DATABASE_URL.",
        )
    return engine.connect()


def _rows(sql: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        with _db() as conn:
            result = conn.execute(text(sql), params).mappings().all()
            return [dict(row) for row in result]
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        # Avoid returning connection strings or raw DB errors to API consumers.
        print(f"[FlowSense data] Query failed: {type(exc).__name__}", flush=True)
        raise HTTPException(status_code=503, detail="FlowSense data source is temporarily unavailable") from exc


def _payload(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Normalize UUIDs and Decimals while preserving timestamps for FastAPI's encoder.
    result = []
    for row in rows:
        result.append({
            key: (str(value) if value is not None and value.__class__.__name__ == "UUID"
                  else float(value) if value is not None and value.__class__.__name__ == "Decimal"
                  else value)
            for key, value in row.items()
        })
    return result


def _filters(facility_code: str | None) -> tuple[str, dict[str, Any]]:
    if facility_code and (len(facility_code) > 30 or not facility_code.replace("-", "").replace("_", "").isalnum()):
        raise HTTPException(status_code=422, detail="Invalid facility_code")
    if facility_code:
        return " AND f.facility_code = :facility_code ", {"facility_code": facility_code}
    return " ", {}


@router.get("/facilities")
def list_facilities(
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    rows = _rows("""
        SELECT facility_id, facility_code, facility_name, facility_type,
               city, state, country, area_sq_m, status, created_at
        FROM facilities
        ORDER BY facility_code
        LIMIT :limit
    """, {"limit": limit})
    data = _payload(rows)
    return {"count": len(data), "facilities": data}


@router.get("/devices")
def list_live_devices(
    facility_code: str | None = Query(default=None, max_length=30),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    clause, params = _filters(facility_code)
    params["limit"] = limit
    # iot_devices has no created_at column in the FlowSense ORM schema.
    rows = _rows("""
        SELECT d.iot_device_id, d.device_code, d.device_name, d.device_model,
               d.firmware_version, d.communication_protocol, d.installation_location,
               d.status, d.last_seen_at,
               f.facility_id, f.facility_code, f.facility_name
        FROM iot_devices d
        JOIN facilities f ON f.facility_id = d.facility_id
        WHERE 1=1
    """ + clause + """
        ORDER BY d.device_code
        LIMIT :limit
    """, params)
    data = _payload(rows)
    return {"count": len(data), "devices": data}


@router.get("/energy")
def energy_readings(
    facility_code: str | None = Query(default=None, max_length=30),
    hours: int = Query(default=24, ge=1, le=8760),
    limit: int = Query(default=500, ge=1, le=5000),
) -> dict[str, Any]:
    clause, params = _filters(facility_code)
    params.update({"since": datetime.now(timezone.utc) - timedelta(hours=hours), "limit": limit})
    meters = _rows("""
        SELECT f.facility_code, f.facility_name, m.meter_code, m.meter_name,
               m.resource_type, m.unit, r.reading_time, r.reading_value,
               r.quality_status, r.source
        FROM meter_readings r
        JOIN meters m ON m.meter_id = r.meter_id
        JOIN facilities f ON f.facility_id = m.facility_id
        WHERE m.resource_type = 'energy' AND r.reading_time >= :since
    """ + clause + """
        ORDER BY r.reading_time DESC
        LIMIT :limit
    """, params)
    data = _payload(meters)
    return {"count": len(data), "hours": hours, "readings": data}


@router.get("/water")
def water_readings(
    facility_code: str | None = Query(default=None, max_length=30),
    hours: int = Query(default=24, ge=1, le=8760),
    limit: int = Query(default=500, ge=1, le=5000),
) -> dict[str, Any]:
    clause, params = _filters(facility_code)
    params.update({"since": datetime.now(timezone.utc) - timedelta(hours=hours), "limit": limit})
    meters = _rows("""
        SELECT f.facility_code, f.facility_name, m.meter_code, m.meter_name,
               m.resource_type, m.unit, r.reading_time, r.reading_value,
               r.quality_status, r.source
        FROM meter_readings r
        JOIN meters m ON m.meter_id = r.meter_id
        JOIN facilities f ON f.facility_id = m.facility_id
        WHERE m.resource_type = 'water' AND r.reading_time >= :since
    """ + clause + """
        ORDER BY r.reading_time DESC
        LIMIT :limit
    """, params)
    sensor_params = dict(params)
    sensor_params["sensor_limit"] = limit
    sensors = _rows("""
        SELECT f.facility_code, f.facility_name, s.sensor_code, s.sensor_name,
               s.measurement, s.unit, r.reading_time, r.numeric_value,
               r.boolean_value, r.quality_status
        FROM sensor_readings r
        JOIN iot_sensors s ON s.sensor_id = r.sensor_id
        JOIN iot_devices d ON d.iot_device_id = s.iot_device_id
        JOIN facilities f ON f.facility_id = d.facility_id
        WHERE (s.sensor_type = 'water' OR s.measurement IN ('Water Consumption', 'Water Flow', 'Pressure', 'Leak Detected'))
          AND r.reading_time >= :since
    """ + clause + """
        ORDER BY r.reading_time DESC
        LIMIT :sensor_limit
    """, sensor_params)
    meter_data, sensor_data = _payload(meters), _payload(sensors)
    return {
        "meter_reading_count": len(meter_data),
        "sensor_reading_count": len(sensor_data),
        "hours": hours,
        "meter_readings": meter_data,
        "sensor_readings": sensor_data,
    }


@router.get("/alerts")
def list_alerts(
    facility_code: str | None = Query(default=None, max_length=30),
    status: str | None = Query(default=None, max_length=20),
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    clause, params = _filters(facility_code)
    if status:
        if status not in {"active", "acknowledged", "resolved", "closed"}:
            raise HTTPException(status_code=422, detail="Invalid alert status")
        clause += " AND a.status = :alert_status "
        params["alert_status"] = status
    params["limit"] = limit
    rows = _rows("""
        SELECT a.alert_id, a.anomaly_id, a.alert_title, a.alert_message,
               a.severity, a.triggered_at, a.status,
               f.facility_code, f.facility_name,
               n.anomaly_type, n.resource_type, n.deviation_percent,
               n.estimated_loss, n.loss_unit, n.description AS anomaly_description
        FROM alerts a
        JOIN facilities f ON f.facility_id = a.facility_id
        LEFT JOIN anomalies n ON n.anomaly_id = a.anomaly_id
        WHERE 1=1
    """ + clause + """
        ORDER BY a.triggered_at DESC NULLS LAST
        LIMIT :limit
    """, params)
    data = _payload(rows)
    return {"count": len(data), "alerts": data}
