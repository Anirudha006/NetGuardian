import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
import time
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.database import SessionLocal
from app.models.device import Device
from app.models.alert import Alert
from app.models.connection import NetworkConnection
from app.models.traffic import TrafficRecord
from app.models.audit_log import AuditLog, SystemSetting
from app.models.user import User
from app.services.health_calculator import calculate_network_health
from app.detection.rule_engine import RuleDetectionEngine
from app.simulation.traffic_generator import traffic_generator
from app.digital_twin.twin_engine import digital_twin

client = TestClient(app)

def get_admin_headers():
    res = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert res.status_code == 200
    token = res.json()["access_token"]
    csrf = res.json().get("csrf_token", "")
    return {
        "Authorization": f"Bearer {token}",
        "X-CSRF-Token": csrf
    }

def get_analyst_headers():
    res = client.post("/api/auth/login", json={"username": "analyst", "password": "analyst123"})
    assert res.status_code == 200
    token = res.json()["access_token"]
    csrf = res.json().get("csrf_token", "")
    return {
        "Authorization": f"Bearer {token}",
        "X-CSRF-Token": csrf
    }

def test_acceptance_check_1_kpi_values_equal_database_counts():
    """
    Acceptance Check 1:
    KPI values equal database counts after:
    1. Adding a device
    2. Injecting an event
    3. Isolating a device
    """
    admin_headers = get_admin_headers()
    db = SessionLocal()

    try:
        # Reset any isolated devices to baseline
        for d in db.query(Device).filter(Device.is_isolated == True).all():
            d.is_isolated = False
            d.status = "ONLINE"
        db.commit()
        digital_twin.sync_from_database(db)

        # Baseline check
        res = client.get("/api/dashboard", headers=admin_headers)
        assert res.status_code == 200
        dash = res.json()
        kpis = dash["kpis"]

        expected_online = db.query(Device).filter(Device.status.in_(["ONLINE", "SUSPICIOUS"])).count()
        expected_threats = db.query(Alert).filter(Alert.status.in_(["NEW", "INVESTIGATING"])).count()
        expected_conns = db.query(NetworkConnection).count()

        assert kpis["devices_online"] == expected_online
        assert kpis["threats_detected"] == expected_threats
        assert kpis["active_connections"] == expected_conns

        # 1. Add a device
        new_mac = f"02:7A:DE:AD:BE:{int(time.time()) % 100:02d}"
        new_ip = f"192.168.1.{210 + (int(time.time()) % 20)}"
        res_add = client.post("/api/devices", json={
            "device_name": f"PC-Test-{int(time.time()) % 1000}",
            "ip_address": new_ip,
            "mac_address": new_mac,
            "device_type": "Workstation",
            "criticality": "MEDIUM",
            "trust_level": "HIGH"
        }, headers=admin_headers)
        assert res_add.status_code == 200
        added_dev_id = res_add.json()["id"]

        # Verify KPI updated
        res_post_add = client.get("/api/dashboard", headers=admin_headers).json()
        db.expire_all()
        db_online_after_add = db.query(Device).filter(Device.status.in_(["ONLINE", "SUSPICIOUS"])).count()
        assert res_post_add["kpis"]["devices_online"] == db_online_after_add
        assert res_post_add["kpis"]["devices_online"] == expected_online + 1

        # 2. Inject an event
        res_ev = client.post("/api/simulation/trigger-event", json={
            "event_type": "TRAFFIC_ANOMALY",
            "source_ip": "192.168.1.10",
            "target_ip": "192.168.1.20"
        }, headers=admin_headers)
        assert res_ev.status_code == 200

        # Verify KPI threats updated
        res_post_ev = client.get("/api/dashboard", headers=admin_headers).json()
        db.expire_all()
        db_threats_after_ev = db.query(Alert).filter(Alert.status.in_(["NEW", "INVESTIGATING"])).count()
        assert res_post_ev["kpis"]["threats_detected"] == db_threats_after_ev
        assert res_post_ev["kpis"]["threats_detected"] >= expected_threats

        # 3. Isolate a device
        target_to_iso = db.query(Device).filter(Device.id == added_dev_id).first()
        res_iso = client.post("/api/simulation/isolate", json={
            "target_device_id": target_to_iso.id
        }, headers=admin_headers)
        assert res_iso.status_code == 200

        # Verify KPI after isolation: device is ISOLATED so devices_online decreases by 1
        res_post_iso = client.get("/api/dashboard", headers=admin_headers).json()
        db.expire_all()
        db_online_after_iso = db.query(Device).filter(Device.status.in_(["ONLINE", "SUSPICIOUS"])).count()
        assert res_post_iso["kpis"]["devices_online"] == db_online_after_iso
        assert res_post_iso["kpis"]["devices_online"] == expected_online

    finally:
        # Cleanup added device
        test_dev = db.query(Device).filter(Device.id == added_dev_id).first()
        if test_dev:
            db.delete(test_dev)
            db.commit()
        db.close()

def test_acceptance_check_2_dashboard_health_equals_api_and_breakdown_sums():
    """
    Acceptance Check 2:
    Health on the dashboard equals the health in the API and its breakdown sums correctly.
    """
    admin_headers = get_admin_headers()
    db = SessionLocal()

    try:
        res = client.get("/api/dashboard", headers=admin_headers)
        assert res.status_code == 200
        dash_health = res.json()["network_health"]

        api_health = calculate_network_health(db)

        # 1. Health score matches exactly
        assert dash_health["score"] == api_health["score"]
        assert dash_health["health_status"] == api_health["health_status"]

        # 2. Penalty breakdown sums up to raw_deductions
        penalties = dash_health["penalties"]
        raw_sum = round(
            penalties["active_threats"] +
            penalties["suspicious_devices"] +
            penalties["high_risk_nodes"] +
            penalties["traffic_anomalies"] +
            penalties["offline_devices"],
            1
        )
        assert raw_sum == dash_health["raw_deductions"]

        # 3. Clamped health score calculation
        expected_score = max(0.0, min(100.0, round(100.0 - raw_sum, 1)))
        assert dash_health["score"] == expected_score

    finally:
        db.close()

def test_acceptance_check_3_settings_behavior_change_audit_log_validation_analyst_403():
    """
    Acceptance Check 3:
    1. Changing a setting changes behavior (lower port-scan threshold flags smaller scan).
    2. Writes an audit log.
    3. Invalid values are rejected with friendly messages.
    4. An analyst gets 403 on changes.
    """
    admin_headers = get_admin_headers()
    analyst_headers = get_analyst_headers()
    db = SessionLocal()

    try:
        # 1. Admin lowers port_scan_threshold to 3
        res_update = client.patch("/api/settings", json={
            "port_scan_threshold": 3
        }, headers=admin_headers)
        assert res_update.status_code == 200
        assert "port_scan_threshold=3" in res_update.json()["updated_keys"][0]

        # Verify audit log was recorded
        db.expire_all()
        last_audit = db.query(AuditLog).filter(
            AuditLog.action == "UPDATE_SETTINGS"
        ).order_by(AuditLog.timestamp.desc()).first()
        assert last_audit is not None
        assert "port_scan_threshold=3" in last_audit.details

        # Test behavior change: With threshold=3, accessing 3 distinct ports triggers a port scan alert
        rule_engine = RuleDetectionEngine(db)
        # Clear existing alerts for test IP
        test_ip = "192.168.1.188"
        db.query(Alert).filter(Alert.source_ip == test_ip).delete()
        db.commit()

        # Add 3 records to different ports (80, 443, 8080)
        t_now = db.query(TrafficRecord).order_by(TrafficRecord.timestamp.desc()).first()
        base_ts = t_now.timestamp if t_now else None

        for p in [80, 443, 8080]:
            r = TrafficRecord(
                timestamp=base_ts,
                source_ip=test_ip,
                destination_ip="192.168.1.20",
                protocol="TCP",
                source_port=50000 + p,
                destination_port=p,
                packet_count=5,
                bytes=1000,
                duration=0.1,
                is_anomalous=0
            )
            db.add(r)
        db.commit()

        # Check port scan trigger
        scan_alert = rule_engine.check_port_scan(test_ip)
        assert scan_alert is not None, "Threshold of 3 must trigger port scan alert on 3 unique ports"
        assert scan_alert.severity == "HIGH"

        # 2. Reject invalid values with friendly messages
        # a) Simulated devices out of range [10, 100]
        res_bad_devs = client.patch("/api/settings", json={"simulated_devices_count": 5}, headers=admin_headers)
        assert res_bad_devs.status_code == 400
        assert "Number of simulated devices must be between 10 and 100" in res_bad_devs.json()["detail"]

        res_bad_devs_high = client.patch("/api/settings", json={"simulated_devices_count": 150}, headers=admin_headers)
        assert res_bad_devs_high.status_code == 400
        assert "Number of simulated devices must be between 10 and 100" in res_bad_devs_high.json()["detail"]

        # b) Session timeout out of range
        res_bad_sess = client.patch("/api/settings", json={"session_timeout_minutes": 0}, headers=admin_headers)
        assert res_bad_sess.status_code == 400
        assert "Session timeout must be between 1 and 10080 minutes" in res_bad_sess.json()["detail"]

        # c) Password min length too short (< 8)
        res_bad_pw = client.patch("/api/settings", json={"password_min_length": 4}, headers=admin_headers)
        assert res_bad_pw.status_code == 400
        assert "Password minimum length must be at least 8 characters" in res_bad_pw.json()["detail"]

        # 3. Analyst gets 403 on changes but can view read-only
        res_analyst_view = client.get("/api/settings", headers=analyst_headers)
        assert res_analyst_view.status_code == 200
        assert res_analyst_view.json()["is_admin"] is False

        res_analyst_patch = client.patch("/api/settings", json={"port_scan_threshold": 10}, headers=analyst_headers)
        assert res_analyst_patch.status_code == 403
        assert "Administrative privileges required" in res_analyst_patch.json()["detail"]

    finally:
        # Restore threshold back to 15
        client.patch("/api/settings", json={"port_scan_threshold": 15}, headers=admin_headers)
        db.query(TrafficRecord).filter(TrafficRecord.source_ip == "192.168.1.188").delete()
        db.query(Alert).filter(Alert.source_ip == "192.168.1.188").delete()
        db.commit()
        db.close()

def test_acceptance_check_4_traffic_pause_resume_and_step():
    """
    Acceptance Check 4:
    Pausing stops new traffic records, single-step advances 1 tick, and resuming continues them.
    """
    analyst_headers = get_analyst_headers()
    db = SessionLocal()

    try:
        # 1. Pause traffic
        res_pause = client.post("/api/traffic/pause", headers=analyst_headers)
        assert res_pause.status_code == 200
        assert res_pause.json()["is_paused"] is True

        ctrl = client.get("/api/traffic/control").json()
        assert ctrl["is_paused"] is True
        assert ctrl["status"] == "PAUSED"

        count_before = db.query(TrafficRecord).count()

        # 2. Pulse while paused must generate 0 new traffic records
        res_pulse = client.post("/api/traffic/pulse?count=6", headers=analyst_headers)
        assert res_pulse.status_code == 200
        assert len(res_pulse.json()) == 0

        db.expire_all()
        count_during_pause = db.query(TrafficRecord).count()
        assert count_during_pause == count_before, "Paused simulation must not generate new records on pulse"

        # 3. Single-step generates exactly 1 tick of records even when paused
        res_step = client.post("/api/traffic/step?count=6", headers=analyst_headers)
        assert res_step.status_code == 200
        step_records = res_step.json()
        assert len(step_records) > 0

        db.expire_all()
        count_after_step = db.query(TrafficRecord).count()
        assert count_after_step == count_before + len(step_records)

        # 4. Resume traffic
        res_resume = client.post("/api/traffic/resume", headers=analyst_headers)
        assert res_resume.status_code == 200
        assert res_resume.json()["is_paused"] is False

        # 5. Pulse while running generates records normally
        res_pulse_running = client.post("/api/traffic/pulse?count=6", headers=analyst_headers)
        assert res_pulse_running.status_code == 200
        assert len(res_pulse_running.json()) > 0

        db.expire_all()
        count_after_resume = db.query(TrafficRecord).count()
        assert count_after_resume > count_after_step

    finally:
        traffic_generator.resume()
        db.close()

def test_acceptance_check_5_system_status_subsystem_probes_and_reasons():
    """
    Acceptance Check 5:
    System status panel: Backend, Database, AI Engine, Digital Twin, Network Collector,
    each from a real probe, with a reason when not ready.
    """
    res = client.get("/api/settings/status")
    assert res.status_code == 200
    data = res.json()

    # Legacy strings
    assert data["backend"] == "ONLINE"
    assert data["database"] == "ONLINE"
    assert data["ai_engine"] in ["READY", "UNAVAILABLE"]
    assert data["digital_twin"] in ["SYNCHRONIZED", "OUT_OF_SYNC"]
    assert "SIMULATION" in data["network_collector"]

    # Component probe objects
    components = data["components"]
    assert "backend" in components
    assert "database" in components
    assert "ai_engine" in components
    assert "digital_twin" in components
    assert "network_collector" in components

    # Check that each probe has a reason
    for comp_key, comp in components.items():
        assert "status" in comp
        assert "ok" in comp
        assert "reason" in comp
        assert len(comp["reason"]) > 0

    # Specifically check Network Collector in Simulation Mode
    assert "Simulation Mode remains available" in components["network_collector"]["reason"]

def test_acceptance_check_6_user_notifications_read_state_on_server():
    """
    Acceptance Check 6:
    Notifications read state is stored per user on the server.
    """
    admin_headers = get_admin_headers()
    analyst_headers = get_analyst_headers()
    db = SessionLocal()

    try:
        # Create a fresh alert
        alert = Alert(
            title="Notification Test Alert",
            message="Notification test alert description",
            recommendation="Review test alert",
            severity="MEDIUM",
            source_ip="192.168.1.10",
            destination_ip="192.168.1.20",
            status="NEW"
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        aid = alert.id

        # 1. Admin marks alert as read on the server
        res_mark = client.post("/api/alerts/read-state", json={"alert_id": aid}, headers=admin_headers)
        assert res_mark.status_code == 200

        # Admin reads back read-state
        admin_reads = client.get("/api/alerts/read-state", headers=admin_headers).json()["read_alert_ids"]
        assert aid in admin_reads

        # 2. Analyst logs in - the alert is NOT in analyst's read state
        analyst_reads = client.get("/api/alerts/read-state", headers=analyst_headers).json()["read_alert_ids"]
        assert aid not in analyst_reads, "Read state must be per-user on the server, not shared across users"

    finally:
        test_a = db.query(Alert).filter(Alert.title == "Notification Test Alert").first()
        if test_a:
            db.delete(test_a)
            db.commit()
        db.close()
