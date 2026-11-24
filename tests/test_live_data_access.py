from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app import main
from app.partner_auth import IntegrationClient, IntegrationFacilityAccess


def test_facility_lookup_returns_only_active_unrevoked_grants():
    engine = create_engine("sqlite://")
    main.Base.metadata.create_all(bind=engine)
    try:
        with Session(engine) as db:
            request = main.AccessRequest(
                contact_name="Facility Test",
                email="facility@example.test",
                organization="Facility Partner",
                purpose="Test facility-level data authorization.",
                client_address="facility-partner-01",
                status="approved",
            )
            db.add(request)
            db.commit()
            db.refresh(request)

            client = IntegrationClient(
                access_request_id=request.id,
                client_id="fs_client_facility_test",
                client_secret_hash="a" * 64,
                scopes="keys:manage energy:read water:read alerts:read",
                is_active=True,
            )
            db.add(client)
            db.commit()
            db.refresh(client)

            db.add_all([
                IntegrationFacilityAccess(
                    integration_client_id=client.id,
                    facility_id="facility-active",
                    facility_code="FS-ACTIVE",
                    is_active=True,
                    revoked_at=None,
                ),
                IntegrationFacilityAccess(
                    integration_client_id=client.id,
                    facility_id="facility-revoked",
                    facility_code="FS-REVOKED",
                    is_active=False,
                    revoked_at=datetime.now(timezone.utc),
                ),
                IntegrationFacilityAccess(
                    integration_client_id=client.id,
                    facility_id="facility-inactive",
                    facility_code="FS-INACTIVE",
                    is_active=False,
                    revoked_at=None,
                ),
            ])
            db.commit()

            api_key = SimpleNamespace(integration_client_id=client.id)
            assert main.get_authorized_facility_ids(api_key, db) == ["facility-active"]
    finally:
        engine.dispose()


def test_legacy_key_has_no_rds_facility_access():
    class NoFacilities:
        def scalars(self, statement):
            raise AssertionError("Legacy keys must not query facility grants")

    assert main.get_authorized_facility_ids(SimpleNamespace(), NoFacilities()) == []


def test_measurement_scope_is_limited_to_explicitly_granted_resources():
    energy_key = SimpleNamespace(
        integration_client_id=7,
        scopes="keys:manage energy:read",
    )
    assert main._partner_measurement_scopes(energy_key) == ["energy"]
    assert main._partner_measurement_scopes(energy_key, "energy") == ["energy"]
    with pytest.raises(main.HTTPException) as exc:
        main._partner_measurement_scopes(energy_key, "water")
    assert exc.value.status_code == 403


def test_measurement_time_window_is_bounded_to_90_days():
    now = datetime.now(timezone.utc)
    start, end = main._normalize_time_window(None, None)
    assert end - start == timedelta(days=7)

    with pytest.raises(main.HTTPException) as exc:
        main._normalize_time_window(now - timedelta(days=91), now)
    assert exc.value.status_code == 422


def test_measurement_time_window_rejects_reversed_dates():
    now = datetime.now(timezone.utc)
    with pytest.raises(main.HTTPException) as exc:
        main._normalize_time_window(now, now - timedelta(hours=1))
    assert exc.value.status_code == 422
