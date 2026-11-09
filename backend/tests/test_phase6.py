import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.database import SessionLocal, Base, engine
from app.models.device import Device
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.models.simulation import SimulationRun, AttackPath
from app.models.traffic import TrafficRecord
from app.models.connection import NetworkConnection
from app.utils.seed_data import seed_database
from app.digital_twin.twin_engine import digital_twin
from app.simulation.traffic_generator import traffic_generator as synthetic_traffic_engine
from app.services.health_calculator import calculate_network_health

client = TestClient(app)

def get_auth_tokens(username="admin", password="admin123"):
    res = client.post("/api/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200
    token = res.json()["access_token"]
    csrf_token = res.cookies.get("csrf_token") or ""
    return token, csrf_token, res.cookies

def get_analyst_headers():
    token, csrf, _ = get_auth_tokens("analyst", "analyst123")
    return {
        "Authorization": f"Bearer {token}",
        "X-CSRF-Token": csrf
    }

@pytest.fixture(autouse=True)
def reset_db_before_test():
    """Reset database and digital twin before each test."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    seed_database(db)
    digital_twin.sync_from_database(db)
    db.close()
    yield

# ==============================================================================
# PHASE 6 ACCEPTANCE CHECK 1:
# A compromised PC reaches Switch, Server and Database, with the Database path
# at 3 hops, and Critical Asset Reached is YES.
# ==============================================================================
def test_acceptance_check_1_compromised_pc_reaches_switch_server_database_3_hops_critical_asset_yes():
    headers = get_analyst_headers()
    db = SessionLocal()
    pc04 = db.query(Device).filter(Device.device_name == "PC-04").first()
    assert pc04 is not None

    res = client.post("/api/simulation/what-if", json={
        "target_device_id": pc04.id,
        "scenario": "COMPROMISED_HOST"
    }, headers=headers)

    assert res.status_code == 200, res.text
    data = res.json()

    # Reachable systems must include all 10 active internal nodes
    reachable = data["reachable_systems"]
    assert len(reachable) == 10
    expected_nodes = ["Router", "Switch", "Server", "Database", "PC-01", "PC-02", "PC-03", "Phone-01", "Printer", "IoT-Camera"]
    for expected in expected_nodes:
        assert expected in reachable, f"Missing {expected} from reachable systems"
    assert data["reachable_nodes_count"] == 10

    # Primary path must reach Database (critical asset prioritized)
    assert data["critical_asset_reached"] == "YES"
    assert data["is_critical_asset_reached"] is True

    # Database path must be 3 hops: PC-04 -> Switch -> Server -> Database
    primary_path = data["potential_reach_path"]
    assert primary_path == ["PC-04", "Switch", "Server", "Database"]
    assert data["hop_count"] == 3
    assert data["path_length"] == 3
    assert data["path_display"] == "PC-04 → Switch → Server → Database"

    # Scenario text check
    assert "PC-04 is hypothetically compromised" in data["scenario_text"]

    # Recommended controls check (matching spec)
    expected_controls = [
        "Restrict unnecessary communication",
        "Review trust relationships",
        "Isolate the suspicious endpoint",
        "Monitor server connections"
    ]
    assert data["recommended_controls"] == expected_controls
    db.close()

# ==============================================================================
# PHASE 6 ACCEPTANCE CHECK 2:
# The path risk equals the documented formula exactly, and the breakdown shown matches.
# Formula: 0.30 * Source_Risk + 0.35 * Target_Crit_Val + 0.15 * Hop_Factor + 0.20 * Avg_Trust
# ==============================================================================
def test_acceptance_check_2_path_risk_formula_and_breakdown_exact_match():
    headers = get_analyst_headers()
    db = SessionLocal()
    pc04 = db.query(Device).filter(Device.device_name == "PC-04").first()
    assert pc04 is not None

    res = client.post("/api/simulation/what-if", json={
        "target_device_id": pc04.id,
        "scenario": "COMPROMISED_HOST"
    }, headers=headers)

    assert res.status_code == 200
    data = res.json()

    # Expected values for PC-04 (seeded: risk=0.0, trust=80.0) -> Database:
    # Path: PC-04 (80), Switch (95), Server (95), Database (95)
    # Hops = 3 -> Hop Factor = max(0, 100 - 20 * (3 - 1)) = 60.0
    # Target Criticality = CRITICAL -> Target Criticality Val = 95.0
    # Avg Trust = (80.0 + 95.0 + 95.0 + 95.0) / 4 = 91.25
    # Source Risk = 0.0
    #
    # Component points:
    # Source Risk: 0.30 * 0.0 = 0.0
    # Target Crit: 0.35 * 95.0 = 33.25
    # Hop Factor:  0.15 * 60.0 = 9.0
    # Avg Trust:   0.20 * 91.25 = 18.25
    # Total Path Risk = 0.0 + 33.25 + 9.0 + 18.25 = 60.5
    expected_risk = 60.5
    assert data["path_risk_score"] == expected_risk
    assert data["max_path_risk"] == expected_risk
    assert data["simulated_risk_level"] == "HIGH"  # 55 <= 60.5 < 80 -> HIGH

    # Check breakdown matches exact components
    bd = data["breakdown"]
    assert bd["source_risk"]["points"] == 0.0
    assert bd["target_criticality"]["points"] == 33.25
    assert bd["target_criticality"]["value"] == 95.0
    assert bd["hop_factor"]["points"] == 9.0
    assert bd["hop_factor"]["value"] == 60.0
    assert bd["path_trust"]["points"] == 18.25
    assert bd["path_trust"]["average_trust"] == 91.25
    assert bd["total_simulated_risk"] == 60.5
    db.close()

# ==============================================================================
# PHASE 6 ACCEPTANCE CHECK 3:
# A compromised Printer or Phone gives a different path and risk from a PC,
# and the risk changes when the source device's risk changes.
# ==============================================================================
def test_acceptance_check_3_printer_or_phone_different_risk_and_source_risk_variation():
    headers = get_analyst_headers()
    db = SessionLocal()

    pc01 = db.query(Device).filter(Device.device_name == "PC-01").first()
    phone = db.query(Device).filter(Device.device_name == "Phone-01").first()

    # 1. Run for PC-01 (base trust 80.0, risk 0.0) -> Risk = 60.5
    res_pc = client.post("/api/simulation/what-if", json={"target_device_id": pc01.id}, headers=headers)
    risk_pc = res_pc.json()["path_risk_score"]
    assert risk_pc == 60.5

    # 2. Run for Phone-01 (base trust 50.0, risk 0.0)
    # Path: Phone-01 (50), Switch (95), Server (95), Database (95)
    # Avg trust = (50 + 95 + 95 + 95) / 4 = 83.75
    # Path Risk = 0 + 33.25 + 9.0 + 0.20 * 83.75 = 59.0
    res_phone = client.post("/api/simulation/what-if", json={"target_device_id": phone.id}, headers=headers)
    risk_phone = res_phone.json()["path_risk_score"]
    assert risk_phone == 59.0
    assert risk_phone != risk_pc, "Phone-01 must produce a different simulated path risk from PC-01"

    # 3. Elevate PC-01 source risk by injecting an alert (e.g. port scan -> risk = 25.0, trust = 55.0)
    client.post("/api/simulation/trigger-event", json={
        "event_type": "PORT_SCAN",
        "source_ip": "192.168.1.10",
        "target_ip": "192.168.1.20"
    }, headers=headers)

    db.refresh(pc01)
    assert pc01.risk_score == 25.0

    # 4. Re-run what-if on PC-01 with elevated risk
    res_pc_elevated = client.post("/api/simulation/what-if", json={"target_device_id": pc01.id}, headers=headers)
    risk_pc_elevated = res_pc_elevated.json()["path_risk_score"]

    # Source Risk: 0.30 * 25.0 = 7.5
    # Target Server trust is dynamically updated based on the incoming threat finding:
    # Server trust = 65.0, Switch trust = 95.0, Database trust = 95.0
    # Avg Trust: (55.0 + 95.0 + 65.0 + 95.0) / 4 = 77.5 -> 0.20 * 77.5 = 15.5
    # Total = 7.5 + 33.25 + 9.0 + 15.5 = 65.25
    assert risk_pc_elevated == 65.25
    assert risk_pc_elevated > risk_pc, "Elevated source device risk must increase simulated path risk"
    db.close()

# ==============================================================================
# PHASE 6 ACCEPTANCE CHECK 4:
# Isolating the compromised device gives zero reachable systems, its open events
# become Contained, health improves, and the device stops creating traffic.
# ==============================================================================
def test_acceptance_check_4_simulate_isolation_zero_reachability_events_contained_health_improves_traffic_silenced():
    headers = get_analyst_headers()
    db = SessionLocal()
    pc01 = db.query(Device).filter(Device.device_name == "PC-01").first()

    # 1. Trigger security alert on PC-01
    client.post("/api/simulation/trigger-event", json={
        "event_type": "PORT_SCAN",
        "source_ip": "192.168.1.10",
        "target_ip": "192.168.1.20"
    }, headers=headers)

    db.refresh(pc01)
    assert pc01.status == "SUSPICIOUS"

    # Confirm open alert exists
    open_alerts_before = db.query(Alert).filter(Alert.source_ip == pc01.ip_address, Alert.status == "NEW").count()
    assert open_alerts_before >= 1

    # Confirm health degraded before isolation
    health_before = calculate_network_health(db)["health_score"]
    assert health_before < 100.0

    # Generate normal traffic tick before isolation: PC-01 produces traffic
    synthetic_traffic_engine.generate_tick(db, count=15, scenario="NORMAL")
    db.commit()
    traffic_before_count = db.query(TrafficRecord).filter(TrafficRecord.source_ip == pc01.ip_address).count()

    # 2. Execute simulated isolation on PC-01
    iso_res = client.post("/api/simulation/isolate", json={
        "target_device_id": pc01.id,
        "reason": "What-If automated isolation verification"
    }, headers=headers)

    assert iso_res.status_code == 200
    iso_data = iso_res.json()

    # Exact required message check
    expected_msg = f"SIMULATED ACTION — {pc01.device_name} isolated. Potential attack path interrupted. No real network changes were performed."
    assert iso_data["message"] == expected_msg
    assert iso_data["is_isolated"] is True
    assert iso_data["status"] == "ISOLATED"
    assert iso_data["reachability_before"] == 10
    assert iso_data["reachability_after"] == 0

    # 3. Verify open events became Contained
    open_alerts_after = db.query(Alert).filter(Alert.source_ip == pc01.ip_address, Alert.status.in_(["NEW", "INVESTIGATING"])).count()
    assert open_alerts_after == 0
    contained_alerts = db.query(Alert).filter(Alert.source_ip == pc01.ip_address, Alert.status == "CONTAINED").count()
    assert contained_alerts >= 1

    # 4. Verify health improved
    health_after = calculate_network_health(db)["health_score"]
    assert health_after > health_before, f"Health {health_after} should improve after isolation (was {health_before})"

    # 5. Verify isolated device stops creating traffic
    for _ in range(5):
        synthetic_traffic_engine.generate_tick(db, count=15, scenario="NORMAL")
    db.commit()

    traffic_after_count = db.query(TrafficRecord).filter(TrafficRecord.source_ip == pc01.ip_address).count()
    assert traffic_after_count == traffic_before_count, "Isolated device must NOT create any new traffic records"

    # 6. Verify what-if on isolated device gives zero reachable systems
    what_if_res = client.post("/api/simulation/what-if", json={"target_device_id": pc01.id}, headers=headers)
    assert what_if_res.status_code == 200
    what_if_data = what_if_res.json()
    assert what_if_data["reachable_nodes_count"] == 0
    assert what_if_data["reachable_systems"] == []
    assert what_if_data["critical_asset_reached"] == "NO"
    db.close()

# ==============================================================================
# PHASE 6 ACCEPTANCE CHECK 5:
# Restore brings the links back and the same what-if gives the original result.
# ==============================================================================
def test_acceptance_check_5_restore_device_links_and_reproducible_what_if():
    headers = get_analyst_headers()
    db = SessionLocal()
    pc04 = db.query(Device).filter(Device.device_name == "PC-04").first()

    # Pre-isolation what-if baseline
    orig_res = client.post("/api/simulation/what-if", json={"target_device_id": pc04.id}, headers=headers)
    orig_data = orig_res.json()
    assert orig_data["path_risk_score"] == 60.5
    assert len(orig_data["reachable_systems"]) > 0

    # Isolate
    client.post("/api/simulation/isolate", json={"target_device_id": pc04.id}, headers=headers)

    # Restore
    restore_res = client.post(f"/api/simulation/restore/{pc04.id}", headers=headers)
    assert restore_res.status_code == 200
    restore_data = restore_res.json()
    assert restore_data["is_isolated"] is False
    assert restore_data["status"] == "ONLINE"

    # Post-restore what-if matches original result exactly
    post_res = client.post("/api/simulation/what-if", json={"target_device_id": pc04.id}, headers=headers)
    assert post_res.status_code == 200
    post_data = post_res.json()
    assert post_data["path_risk_score"] == orig_data["path_risk_score"]
    assert post_data["reachable_systems"] == orig_data["reachable_systems"]
    assert post_data["critical_asset_reached"] == "YES"
    assert post_data["potential_reach_path"] == ["PC-04", "Switch", "Server", "Database"]
    db.close()

# ==============================================================================
# PHASE 6 ACCEPTANCE CHECK 6:
# An isolated or offline source returns "no reachable systems" without an error.
# ==============================================================================
def test_acceptance_check_6_isolated_or_offline_source_returns_no_reachable_systems_without_error():
    headers = get_analyst_headers()
    db = SessionLocal()
    pc02 = db.query(Device).filter(Device.device_name == "PC-02").first()
    pc03 = db.query(Device).filter(Device.device_name == "PC-03").first()

    # 1. Test Isolated Device
    pc02.is_isolated = True
    pc02.status = "ISOLATED"
    db.commit()
    digital_twin.sync_from_database(db)

    res_iso = client.post("/api/simulation/what-if", json={"target_device_id": pc02.id}, headers=headers)
    assert res_iso.status_code == 200
    data_iso = res_iso.json()
    assert data_iso["reachable_nodes_count"] == 0
    assert data_iso["reachable_systems"] == []
    assert data_iso["critical_asset_reached"] == "NO"
    assert data_iso["hop_count"] == 0
    assert data_iso["path_risk_score"] == 0.0

    # 2. Test Offline Device
    pc03.status = "OFFLINE"
    db.commit()
    digital_twin.sync_from_database(db)

    res_off = client.post("/api/simulation/what-if", json={"target_device_id": pc03.id}, headers=headers)
    assert res_off.status_code == 200
    data_off = res_off.json()
    assert data_off["reachable_nodes_count"] == 0
    assert data_off["reachable_systems"] == []
    assert data_off["critical_asset_reached"] == "NO"
    assert data_off["hop_count"] == 0
    assert data_off["path_risk_score"] == 0.0
    db.close()

# ==============================================================================
# PHASE 6 ACCEPTANCE CHECK 7:
# The simulation never writes to traffic_records or changes real device data other
# than the isolation status.
# ==============================================================================
def test_acceptance_check_7_simulation_never_writes_traffic_or_changes_real_device_data():
    headers = get_analyst_headers()
    db = SessionLocal()
    pc04 = db.query(Device).filter(Device.device_name == "PC-04").first()
    orig_ip = pc04.ip_address
    orig_mac = pc04.mac_address
    orig_type = pc04.device_type
    orig_crit = pc04.criticality

    traffic_count_before = db.query(TrafficRecord).count()
    sim_runs_before = db.query(SimulationRun).count()

    # Run what-if
    res = client.post("/api/simulation/what-if", json={"target_device_id": pc04.id}, headers=headers)
    assert res.status_code == 200

    # 1. Traffic records must NOT increase
    traffic_count_after = db.query(TrafficRecord).count()
    assert traffic_count_before == traffic_count_after, "What-If simulation must NEVER write to traffic_records"

    # 2. Real device hardware/network fields unchanged
    db.refresh(pc04)
    assert pc04.ip_address == orig_ip
    assert pc04.mac_address == orig_mac
    assert pc04.device_type == orig_type
    assert pc04.criticality == orig_crit

    # 3. Simulation run saved with HYPOTHETICAL label
    sim_runs_after = db.query(SimulationRun).count()
    assert sim_runs_after == sim_runs_before + 1
    latest_run = db.query(SimulationRun).order_by(SimulationRun.created_at.desc()).first()
    assert latest_run.target_device == "PC-04"
    assert "HYPOTHETICAL" in latest_run.result
    db.close()

# ==============================================================================
# PHASE 6 ACCEPTANCE CHECK 8:
# Unauthenticated calls get 401 and calls without CSRF get 403.
# ==============================================================================
def test_acceptance_check_8_security_unauthenticated_401_no_csrf_403():
    # 1. Unauthenticated requests -> 401
    unauth_client = TestClient(app)
    res1 = unauth_client.post("/api/simulation/what-if", json={"target_device_id": 1})
    assert res1.status_code == 401

    res2 = unauth_client.post("/api/simulation/isolate", json={"target_device_id": 1})
    assert res2.status_code == 401

    res3 = unauth_client.post("/api/simulation/restore/1")
    assert res3.status_code == 401

    # 2. Cookie authentication without X-CSRF-Token header -> 403
    cookie_client = TestClient(app)
    login_res = cookie_client.post("/api/auth/login", json={"username": "analyst", "password": "analyst123"})
    assert login_res.status_code == 200

    res_no_csrf = cookie_client.post(
        "/api/simulation/what-if",
        json={"target_device_id": 1}
    )
    assert res_no_csrf.status_code == 403
    assert "CSRF" in res_no_csrf.json()["detail"]

    res_iso_no_csrf = cookie_client.post(
        "/api/simulation/isolate",
        json={"target_device_id": 1}
    )
    assert res_iso_no_csrf.status_code == 403
    assert "CSRF" in res_iso_no_csrf.json()["detail"]

    res_res_no_csrf = cookie_client.post(
        "/api/simulation/restore/1"
    )
    assert res_res_no_csrf.status_code == 403
    assert "CSRF" in res_res_no_csrf.json()["detail"]

# ==============================================================================
# PHASE 6 ACCEPTANCE CHECK 9:
# What-If results for different seeds or target states NEVER mutate live
# device risk, status, trust, or traffic (DB comparison before vs after).
# ==============================================================================
def test_acceptance_check_9_what_if_read_only_never_mutates_device_risk_status_or_traffic():
    headers = get_analyst_headers()
    db = SessionLocal()

    # 1. Capture complete pre-simulation database snapshot
    devices_before = {
        d.id: {
            "name": d.device_name,
            "ip": d.ip_address,
            "status": d.status,
            "risk_score": d.risk_score,
            "trust_score": d.trust_score,
            "is_isolated": d.is_isolated
        }
        for d in db.query(Device).all()
    }
    traffic_count_before = db.query(TrafficRecord).count()
    connections_count_before = db.query(NetworkConnection).count()
    alerts_count_before = db.query(Alert).count()
    events_count_before = db.query(SecurityEvent).count()

    pc04 = db.query(Device).filter(Device.device_name == "PC-04").first()
    printer = db.query(Device).filter(Device.device_name == "Printer").first()
    phone = db.query(Device).filter(Device.device_name == "Phone-01").first()

    # 2. Run What-If Simulation on PC-04
    res_pc04 = client.post("/api/simulation/what-if", json={
        "target_device_id": pc04.id,
        "scenario": "COMPROMISED_HOST"
    }, headers=headers)
    assert res_pc04.status_code == 200

    # 3. Run What-If Simulation on Printer
    res_printer = client.post("/api/simulation/what-if", json={
        "target_device_id": printer.id,
        "scenario": "COMPROMISED_HOST"
    }, headers=headers)
    assert res_printer.status_code == 200

    # 4. Run What-If Simulation on Phone-01
    res_phone = client.post("/api/simulation/what-if", json={
        "target_device_id": phone.id,
        "scenario": "COMPROMISED_HOST"
    }, headers=headers)
    assert res_phone.status_code == 200

    # 5. Capture post-simulation database snapshot
    db.expire_all()
    devices_after = {
        d.id: {
            "name": d.device_name,
            "ip": d.ip_address,
            "status": d.status,
            "risk_score": d.risk_score,
            "trust_score": d.trust_score,
            "is_isolated": d.is_isolated
        }
        for d in db.query(Device).all()
    }
    traffic_count_after = db.query(TrafficRecord).count()
    connections_count_after = db.query(NetworkConnection).count()
    alerts_count_after = db.query(Alert).count()
    events_count_after = db.query(SecurityEvent).count()

    # Verify: Device states are 100% untouched
    assert devices_after == devices_before, "What-If simulation must NEVER mutate device risk, status, trust or isolation"

    # Verify: Zero synthetic traffic, connections, or alerts generated
    assert traffic_count_after == traffic_count_before, "What-If simulation must NEVER produce traffic records"
    assert connections_count_after == connections_count_before, "What-If simulation must NEVER mutate network connections"
    assert alerts_count_after == alerts_count_before, "What-If simulation must NEVER generate live security alerts"
    assert events_count_after == events_count_before, "What-If simulation must NEVER generate live security events"

    db.close()

