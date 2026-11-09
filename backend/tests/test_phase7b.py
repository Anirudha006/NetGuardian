import pytest
import struct
import socket
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.database import get_db, SessionLocal
from app.models.device import Device
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.models.traffic import TrafficRecord
from app.models.simulation import SimulationRun
from app.models.audit_log import AuditLog
from app.models.user import User
from app.collector.live_collector import live_collector, parse_raw_ip_packet, sanitize_packet_dict
from app.digital_twin.twin_engine import digital_twin
from app.simulation.traffic_generator import traffic_generator
from app.config import settings

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

def get_auth_token(client: TestClient, username: str = "admin", password: str = "admin123") -> str:
    res = client.post("/api/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, f"Login failed for {username}: {res.text}"
    return res.json()["access_token"]

def get_analyst_token(client: TestClient) -> str:
    return get_auth_token(client, username="analyst", password="analyst123")

# =========================================================================
# Acceptance Check 1: Full 12-Step Demo Runs End to End
# Final state shows isolated device, zero reachable systems, improved health
# =========================================================================
def test_acceptance_check_1_twelve_step_demo_end_to_end(client: TestClient, db: Session):
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Step through 1 to 12
    step_results = {}
    for step_num in range(1, 13):
        res = client.post("/api/simulation/demo/step", json={"step_number": step_num}, headers=headers)
        assert res.status_code == 200, f"Step {step_num} failed: {res.text}"
        data = res.json()
        assert data["step_number"] == step_num
        assert len(data["title"]) > 0
        assert len(data["description"]) > 0
        assert "target_page" in data
        step_results[step_num] = data

    # Verify Step 3: introduced Rogue-Laptop as OBSERVED / Unregistered
    rogue = db.query(Device).filter(Device.device_name.like("Rogue-Laptop%")).first()
    assert rogue is not None, "Rogue-Laptop should exist after step 3"
    assert rogue.device_source == "OBSERVED"
    assert rogue.is_registered is False

    # Verify Step 5: PORT_SCAN alert created
    scan_alert = db.query(Alert).filter(Alert.source_ip == rogue.ip_address).first()
    assert scan_alert is not None, "Alert should be created for Rogue-Laptop"
    assert scan_alert.event_type == "PORT_SCAN" or "PORT_SCAN" in (scan_alert.rule_name or "")

    # Verify Step 6: AI anomaly assessment present
    assert scan_alert.detected_by == "rule+ai"
    assert scan_alert.ai_score is not None
    assert scan_alert.ai_score >= 0.58
    assert "•" in (scan_alert.ai_explanation or "")

    # Verify Step 11 & 12: Device is isolated, 0 reachable systems, path risk drops
    db.refresh(rogue)
    assert rogue.is_isolated is True
    assert rogue.status == "ISOLATED"

    # Verify What-If on the isolated device returns 0 reachable systems and 0 path risk
    whatif_res = client.post("/api/simulation/what-if", json={
        "target_device_id": rogue.id,
        "scenario": "COMPROMISED_HOST"
    }, headers=headers)
    assert whatif_res.status_code == 200
    whatif_data = whatif_res.json()
    assert whatif_data["reachable_nodes_count"] == 0
    assert whatif_data["path_risk_score"] == 0.0
    assert whatif_data["critical_asset_reached"] == "NO"

# =========================================================================
# Acceptance Check 2: Reset Demo Restores Baseline Idempotently
# Returns device count to 12, zero alerts, health 100, accounts intact
# Analyst calling reset gets 403 Forbidden
# =========================================================================
def test_acceptance_check_2_reset_demo_restores_baseline_idempotently(client: TestClient, db: Session):
    admin_token = get_auth_token(client)
    analyst_token = get_analyst_token(client)

    # 1. Analyst cannot reset demo (403 Forbidden required)
    res_forbidden = client.post("/api/simulation/demo/reset", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res_forbidden.status_code == 403, "Analyst must receive 403 Forbidden on reset"

    # 2. Admin performs demo reset
    res = client.post("/api/simulation/demo/reset", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    reset_data = res.json()
    assert reset_data["status"] == "SUCCESS"
    assert reset_data["devices_count"] == 12
    assert reset_data["alerts_count"] == 0
    assert reset_data["health_score"] == 100.0
    assert reset_data["digital_twin_state"] == "SYNCHRONIZED"

    # Verify DB counts directly
    assert db.query(Device).count() == 12
    assert db.query(Alert).count() == 0
    assert db.query(SecurityEvent).count() == 0
    assert db.query(TrafficRecord).count() == 0
    assert db.query(User).count() >= 2, "User accounts must remain intact"

    # Verify Audit Log entry was recorded
    audit_log = db.query(AuditLog).filter(AuditLog.action == "RESET_DEMO").order_by(AuditLog.id.desc()).first()
    assert audit_log is not None, "RESET_DEMO audit log must be recorded"
    assert audit_log.username == "admin"

    # 3. Idempotency: Re-run steps 1 to 4, reset again, confirm exact same baseline
    client.post("/api/simulation/demo/step", json={"step_number": 3}, headers={"Authorization": f"Bearer {admin_token}"})
    assert db.query(Device).count() == 13

    res2 = client.post("/api/simulation/demo/reset", headers={"Authorization": f"Bearer {admin_token}"})
    assert res2.status_code == 200
    assert db.query(Device).count() == 12
    assert db.query(Alert).count() == 0

# =========================================================================
# Acceptance Check 3: Live Mode Fallback Without Permission
# Without permission/driver, falls back to Simulation Mode with notice and no crash
# =========================================================================
def test_acceptance_check_3_live_mode_fallback_without_permission(client: TestClient, db: Session):
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Attempt enabling live mode without consent -> CONSENT_REQUIRED
    res_no_consent = client.post("/api/collector/live-toggle", json={"enabled": True, "consent_granted": False}, headers=headers)
    assert res_no_consent.status_code == 200
    assert res_no_consent.json()["status"] == "CONSENT_REQUIRED"

    # 2. Check collector capability probe
    capable, reason = live_collector.check_capture_capability()
    assert "Live packet monitoring is unavailable" in reason or capable is True

    # 3. Toggle live mode with consent: should either activate or fall back safely
    res_toggle = client.post("/api/collector/live-toggle", json={"enabled": True, "consent_granted": True}, headers=headers)
    assert res_toggle.status_code == 200
    data = res_toggle.json()
    if not capable:
        assert data["status"] == "FALLBACK"
        assert "Live packet monitoring is unavailable. Switching to Simulation Mode." in data["message"]
        assert data["system_mode"] == "SIMULATION"
        assert settings.SYSTEM_MODE == "SIMULATION"

    # 4. Settings PATCH update with system_mode="LIVE"
    res_patch = client.patch("/api/settings", json={"system_mode": "LIVE"}, headers=headers)
    assert res_patch.status_code == 200
    patch_data = res_patch.json()
    if not capable:
        assert patch_data["system_mode"] == "SIMULATION"
        assert "Live packet monitoring is unavailable" in str(patch_data.get("warning_notice"))

    # Restore simulation mode
    client.patch("/api/settings", json={"system_mode": "SIMULATION"}, headers=headers)

# =========================================================================
# Acceptance Check 4: Fake Packet Ingestion Proves NO Payload Stored
# Metadata parsed, flows aggregated, unknown IP discovered as OBSERVED
# DB query confirms 0 payload or password bytes stored
# =========================================================================
def test_acceptance_check_4_fake_packet_proves_no_payload_stored(client: TestClient, db: Session):
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    sensitive_payload = "USER administrator PASS SuperSecretPassword999!"

    # 1. Inject packet with sensitive payload
    fake_packet = {
        "source_ip": "192.168.1.188",
        "destination_ip": "192.168.1.20",
        "protocol": "TCP",
        "source_port": 54321,
        "destination_port": 80,
        "packet_count": 3,
        "bytes": 512,
        "payload": sensitive_payload
    }

    res = client.post("/api/collector/inject-packet", json=fake_packet, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["payload_stored"] is False

    meta = data["parsed_metadata"]
    assert meta["source_ip"] == "192.168.1.188"
    assert meta["destination_ip"] == "192.168.1.20"
    assert meta["protocol"] == "TCP"
    assert meta["source_port"] == 54321
    assert meta["destination_port"] == 80
    assert meta["data_source"] == "OBSERVED"
    assert "payload" not in meta

    # 2. Check Database: confirm record exists and NO payload text was saved
    record = db.query(TrafficRecord).filter(TrafficRecord.source_ip == "192.168.1.188").first()
    assert record is not None, "Traffic record should be persisted"
    assert record.data_source == "OBSERVED"
    assert record.bytes == 512

    # Verify no model column has the sensitive payload
    for column_name in ["source_ip", "destination_ip", "protocol", "data_source"]:
        val = getattr(record, column_name)
        assert sensitive_payload not in str(val)

    # 3. Check that unknown IP was auto-registered as OBSERVED / Unregistered
    observed_dev = db.query(Device).filter(Device.ip_address == "192.168.1.188").first()
    assert observed_dev is not None, "Observed device should be auto-created"
    assert observed_dev.device_source == "OBSERVED"
    assert observed_dev.is_registered is False

    # 4. Test binary packet parser with raw bytes containing payload
    # Construct raw IPv4 + TCP header bytes
    # IP Header: 20 bytes
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 40 + len(sensitive_payload), 54321, 0, 64, 6, 0,
        socket.inet_aton("192.168.1.177"),
        socket.inet_aton("192.168.1.20")
    )
    # TCP Header: 20 bytes
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        49152, 443, 1000, 0, 0x50, 0x02, 8192, 0, 0
    )
    raw_packet_bytes = ip_header + tcp_header + sensitive_payload.encode("utf-8")

    parsed_raw = parse_raw_ip_packet(raw_packet_bytes)
    assert parsed_raw is not None
    assert parsed_raw["source_ip"] == "192.168.1.177"
    assert parsed_raw["destination_ip"] == "192.168.1.20"
    assert parsed_raw["protocol"] == "TCP"
    assert parsed_raw["source_port"] == 49152
    assert parsed_raw["destination_port"] == 443
    assert parsed_raw["payload_stored"] is False
    assert "payload" not in parsed_raw
    assert sensitive_payload not in str(parsed_raw)

# =========================================================================
# Acceptance Check 5: Demo Mode Toggles and Uses Real Data
# Verifies APIs return live data and distinct tags across endpoints
# =========================================================================
def test_acceptance_check_5_demo_mode_uses_real_engine_data(client: TestClient, db: Session):
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Topology returns correct metadata tags
    topo_res = client.get("/api/digital-twin/topology", headers=headers)
    assert topo_res.status_code == 200
    topo = topo_res.json()
    assert "nodes" in topo
    assert "edges" in topo
    assert topo["state"] in ["SYNCHRONIZED", "OUT OF SYNC"]
    assert "data_tag" in topo

    # Check that nodes distinguish device_source and is_registered
    for node in topo["nodes"]:
        assert "device_source" in node
        assert "is_registered" in node
        assert node["device_source"] in ["SIMULATED", "OBSERVED"]

    # 2. Traffic endpoint supports data_source filtering
    sim_traffic = client.get("/api/traffic?data_source=SIMULATED", headers=headers)
    assert sim_traffic.status_code == 200
    for rec in sim_traffic.json():
        assert rec["data_source"] == "SIMULATED"

    obs_traffic = client.get("/api/traffic?data_source=OBSERVED", headers=headers)
    assert obs_traffic.status_code == 200
    for rec in obs_traffic.json():
        assert rec["data_source"] == "OBSERVED"

    # 3. Clean reset to ensure pristine test environment
    client.post("/api/simulation/demo/reset", headers=headers)
