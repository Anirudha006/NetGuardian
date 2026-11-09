import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from sqlalchemy import text
from app.main import app
from app.database import Base, engine, SessionLocal
from app.utils.seed_data import seed_database
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.models.audit_log import AuditLog
from app.models.traffic import TrafficRecord
from app.models.device import Device
from app.simulation.traffic_generator import traffic_generator
from app.detection.rule_engine import RuleDetectionEngine
from app.utils.time_utils import utcnow

# Ensure schema has all columns
Base.metadata.create_all(bind=engine)
with engine.connect() as conn:
    for sql in [
        "ALTER TABLE security_events ADD COLUMN occurrence_count INTEGER DEFAULT 1",
        "ALTER TABLE security_events ADD COLUMN last_seen DATETIME",
        "ALTER TABLE alerts ADD COLUMN occurrence_count INTEGER DEFAULT 1",
        "ALTER TABLE alerts ADD COLUMN last_seen DATETIME",
        "ALTER TABLE alerts ADD COLUMN event_type VARCHAR(100)"
    ]:
        try:
            conn.execute(text(sql))
            conn.commit()
        except Exception:
            pass

client = TestClient(app)

def get_admin_headers():
    res = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert res.status_code == 200
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def get_analyst_headers():
    res = client.post("/api/auth/login", json={"username": "analyst", "password": "analyst123"})
    assert res.status_code == 200
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def clear_alerts_and_traffic():
    db = SessionLocal()
    db.query(Alert).delete()
    db.query(SecurityEvent).delete()
    db.query(TrafficRecord).delete()
    db.commit()
    db.close()


def test_acceptance_check_1_normal_traffic_zero_alerts():
    """Acceptance Check 1: 30+ ticks of normal traffic produce ZERO alerts."""
    clear_alerts_and_traffic()
    db = SessionLocal()
    seed_database(db, force_reset=False)

    # Run 35 ticks of normal simulated traffic
    for tick in range(35):
        traffic_generator.generate_tick(db, count=8, scenario="NORMAL")

    alert_count = db.query(Alert).count()
    event_count = db.query(SecurityEvent).count()
    db.close()

    assert alert_count == 0, f"Expected 0 alerts during normal traffic, found {alert_count}"
    assert event_count == 0, f"Expected 0 security events during normal traffic, found {event_count}"


def test_acceptance_check_2_unknown_device_medium_alert():
    """Acceptance Check 2: Unknown device -> MEDIUM alert."""
    clear_alerts_and_traffic()
    db = SessionLocal()

    # Inject unknown device scenario from unregistered IP
    res = client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "UNKNOWN_DEVICE", "source_ip": "192.168.1.99"},
        headers=get_analyst_headers()
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["severity"] == "MEDIUM"

    alert = db.query(Alert).filter(Alert.event_type == "UNKNOWN_DEVICE").first()
    assert alert is not None
    assert alert.severity == "MEDIUM"
    assert "Unknown Device Detected" in alert.title
    assert "Verify device ownership and isolate if unauthorized" in alert.recommendation
    db.close()


def test_acceptance_check_3_port_scan_high_alert():
    """Acceptance Check 3: Port scan -> HIGH alert."""
    clear_alerts_and_traffic()
    db = SessionLocal()

    res = client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "PORT_SCAN", "source_ip": "192.168.1.10"},
        headers=get_analyst_headers()
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["severity"] == "HIGH"

    alert = db.query(Alert).filter(Alert.event_type == "PORT_SCAN").first()
    assert alert is not None
    assert alert.severity == "HIGH"
    assert "Port Scanning" in alert.title
    assert "Review exposed services" in alert.recommendation
    db.close()


def test_acceptance_check_4_traffic_spike_medium_alert():
    """Acceptance Check 4: Traffic spike -> traffic anomaly alert (MEDIUM)."""
    clear_alerts_and_traffic()
    db = SessionLocal()

    res = client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "TRAFFIC_ANOMALY", "source_ip": "192.168.1.11"},
        headers=get_analyst_headers()
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["severity"] == "MEDIUM"

    alert = db.query(Alert).filter(Alert.event_type == "TRAFFIC_ANOMALY").first()
    assert alert is not None
    assert alert.severity == "MEDIUM"
    assert "Traffic Volume Anomaly" in alert.title
    assert "Investigate the source and compare to baseline" in alert.recommendation
    db.close()


def test_acceptance_check_5_failed_authentication_alert():
    """Acceptance Check 5: Failed authentication -> alert (HIGH, brute force pattern)."""
    clear_alerts_and_traffic()
    db = SessionLocal()

    res = client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "FAILED_AUTH", "source_ip": "192.168.1.12"},
        headers=get_analyst_headers()
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["severity"] == "HIGH"

    alert = db.query(Alert).filter(Alert.event_type == "FAILED_AUTH").first()
    assert alert is not None
    assert alert.severity == "HIGH"
    assert "Brute-Force Pattern" in alert.title
    assert "Audit authentication logs" in alert.recommendation
    db.close()


def test_acceptance_check_6_triggering_same_event_3_times_updates_1_event():
    """Acceptance Check 6: Triggering same event 3 times updates 1 event (occurrence count = 3)."""
    clear_alerts_and_traffic()
    db = SessionLocal()

    # Trigger PORT_SCAN 3 times for the same source device
    for i in range(3):
        res = client.post(
            "/api/simulation/trigger-event",
            json={"event_type": "PORT_SCAN", "source_ip": "192.168.1.10"},
            headers=get_analyst_headers()
        )
        assert res.status_code == 200

    # Verify de-duplication: exactly 1 alert and 1 security_event exist
    alerts = db.query(Alert).filter(Alert.event_type == "PORT_SCAN").all()
    events = db.query(SecurityEvent).filter(SecurityEvent.event_type == "PORT_SCAN").all()

    assert len(alerts) == 1, f"Expected exactly 1 collapsed alert, found {len(alerts)}"
    assert len(events) == 1, f"Expected exactly 1 collapsed security event, found {len(events)}"

    assert alerts[0].occurrence_count == 3
    assert events[0].occurrence_count == 3
    db.close()


def test_acceptance_check_7_status_change_persistence_and_audit_log():
    """Acceptance Check 7: Status change persists after reload and appears in audit log."""
    clear_alerts_and_traffic()
    headers = get_analyst_headers()

    # 1. Trigger an alert
    res = client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "TRAFFIC_ANOMALY", "source_ip": "192.168.1.11"},
        headers=headers
    )
    alert_id = res.json()["alert_id"]

    # 2. Analyst updates status to INVESTIGATING
    res_update1 = client.patch(f"/api/alerts/{alert_id}", json={"status": "INVESTIGATING"}, headers=headers)
    assert res_update1.status_code == 200
    assert res_update1.json()["status"] == "INVESTIGATING"

    # 3. Analyst updates status to CONTAINED
    res_update2 = client.patch(f"/api/alerts/{alert_id}", json={"status": "CONTAINED"}, headers=headers)
    assert res_update2.status_code == 200
    assert res_update2.json()["status"] == "CONTAINED"

    # 4. Verify persistence in a completely fresh DB session
    db_fresh = SessionLocal()
    persisted_alert = db_fresh.query(Alert).filter(Alert.id == alert_id).first()
    assert persisted_alert is not None
    assert persisted_alert.status == "CONTAINED"

    # Also verify linked SecurityEvent status
    if persisted_alert.event_id:
        persisted_event = db_fresh.query(SecurityEvent).filter(SecurityEvent.id == persisted_alert.event_id).first()
        assert persisted_event is not None
        assert persisted_event.status == "CONTAINED"

    # 5. Verify Audit Log entry exists
    audit_entries = db_fresh.query(AuditLog).filter(
        AuditLog.action == "UPDATE_ALERT_STATUS",
        AuditLog.username == "analyst"
    ).all()
    assert len(audit_entries) >= 2
    last_log = audit_entries[-1]
    assert f"Alert #{alert_id}" in last_log.details
    assert "CONTAINED" in last_log.details
    db_fresh.close()


def test_acceptance_check_8_analyst_can_change_status_unauthenticated_gets_401():
    """Acceptance Check 8: Analyst can change status; unauthenticated users get 401."""
    clear_alerts_and_traffic()
    client.cookies.clear()
    analyst_headers = get_analyst_headers()

    # 1. Trigger an alert
    res = client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "PORT_SCAN", "source_ip": "192.168.1.10"},
        headers=analyst_headers
    )
    alert_id = res.json()["alert_id"]

    # 2. Unauthenticated request MUST receive 401
    anon_client = TestClient(app)
    res_unauth = anon_client.patch(f"/api/alerts/{alert_id}", json={"status": "RESOLVED"})
    assert res_unauth.status_code == 401, f"Expected 401 Unauthorized, got {res_unauth.status_code}"

    # 3. Authenticated Analyst request MUST succeed (200 OK)
    res_analyst = client.patch(f"/api/alerts/{alert_id}", json={"status": "RESOLVED"}, headers=analyst_headers)
    assert res_analyst.status_code == 200
    assert res_analyst.json()["status"] == "RESOLVED"

    # 4. Invalid status returns 400 Bad Request
    res_invalid = client.patch(f"/api/alerts/{alert_id}", json={"status": "INVALID_STATUS"}, headers=analyst_headers)
    assert res_invalid.status_code == 400


def test_threats_page_api_filters_and_pagination():
    """Verify backend supports all Threats page filters (severity, status, search, pagination)."""
    clear_alerts_and_traffic()
    headers = get_analyst_headers()

    # Generate 3 distinct events
    client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "UNKNOWN_DEVICE", "source_ip": "192.168.1.99"},
        headers=headers
    )
    client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "PORT_SCAN", "source_ip": "192.168.1.10"},
        headers=headers
    )
    client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "FAILED_AUTH", "source_ip": "192.168.1.12"},
        headers=headers
    )

    # Filter by severity
    res_high = client.get("/api/alerts?severity=HIGH")
    assert res_high.status_code == 200
    high_items = res_high.json()
    assert all(a["severity"] == "HIGH" for a in high_items)

    # Filter by status
    res_new = client.get("/api/alerts?status=NEW")
    assert res_new.status_code == 200
    assert len(res_new.json()) >= 3

    # Filter by search
    res_search = client.get("/api/alerts?search=PORT_SCAN")
    assert res_search.status_code == 200
    assert any("Port" in a["title"] or a.get("rule_name") == "RULE-02: PORT_SCAN" for a in res_search.json())

    # Pagination test
    res_paged = client.get("/api/alerts?skip=0&limit=2&paged=true")
    assert res_paged.status_code == 200
    paged_data = res_paged.json()
    assert "items" in paged_data
    assert "total" in paged_data
    assert len(paged_data["items"]) == 2
    assert paged_data["total"] >= 3

    # Header count check
    assert "x-total-count" in res_high.headers


def test_rule_pipeline_window_evaluation():
    """Verify 3-tick window detection pipeline evaluates flows accurately."""
    clear_alerts_and_traffic()
    db = SessionLocal()
    rule_engine = RuleDetectionEngine(db)

    # Inject 16 port flows in recent window
    for p in range(1, 18):
        rec = TrafficRecord(
            timestamp=utcnow(),
            source_ip="192.168.1.13",
            destination_ip="192.168.1.20",
            protocol="TCP",
            source_port=40000 + p,
            destination_port=p,
            packet_count=2,
            bytes=120,
            duration=0.01
        )
        db.add(rec)
    db.commit()

    alerts = rule_engine.run_detection_pipeline(window_seconds=30)
    assert any(a.event_type == "PORT_SCAN" for a in alerts)
    db.close()
