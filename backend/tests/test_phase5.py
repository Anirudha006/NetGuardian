import time
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, engine, SessionLocal
from app.utils.seed_data import seed_database
from app.digital_twin.twin_engine import digital_twin, DigitalTwinEngine, sync_state_on_change
from app.models.device import Device
from app.models.alert import Alert
from app.models.connection import NetworkConnection
from app.services.health_calculator import calculate_network_health, calculate_device_risk_breakdown
from app.utils.time_utils import utcnow

Base.metadata.create_all(bind=engine)
client = TestClient(app)

def get_admin_headers():
    res = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert res.status_code == 200
    token = res.json()["access_token"]
    csrf_token = res.cookies.get("csrf_token") or ""
    headers = {"Authorization": f"Bearer {token}"}
    if csrf_token:
        headers["X-CSRF-Token"] = csrf_token
    return headers

def get_analyst_headers():
    res = client.post("/api/auth/login", json={"username": "analyst", "password": "analyst123"})
    assert res.status_code == 200
    token = res.json()["access_token"]
    csrf_token = res.cookies.get("csrf_token") or ""
    headers = {"Authorization": f"Bearer {token}"}
    if csrf_token:
        headers["X-CSRF-Token"] = csrf_token
    return headers

@pytest.fixture(autouse=True)
def setup_db():
    db = SessionLocal()
    seed_database(db, force_reset=True)
    digital_twin.sync_from_database(db)
    db.close()

# -------------------------------------------------------------
# USER ITEM 1: Zero Baseline Risk & Health 100 with NO Events
# -------------------------------------------------------------
def test_item1_seeded_network_no_events_risk_zero_health_100():
    """
    User Item 1: With the seeded network and NO events, show every device's risk score
    and the network health score. Health must be 100 (HEALTHY) and no device should be
    flagged suspicious. Criticality does not create baseline risk.
    """
    db = SessionLocal()
    devices = db.query(Device).all()
    assert len(devices) == 12, f"Expected 12 seeded devices, found {len(devices)}"

    for dev in devices:
        assert dev.risk_score == 0.0, f"Device {dev.device_name} has non-zero risk: {dev.risk_score}"
        assert dev.status == "ONLINE", f"Device {dev.device_name} status is {dev.status}, expected ONLINE"
        assert dev.status != "SUSPICIOUS", f"Device {dev.device_name} is flagged suspicious!"
        # Risk breakdown calculation confirms 0 factors and 0 risk
        bd = calculate_device_risk_breakdown(dev, db)
        assert bd["risk_score"] == 0.0, f"Device {dev.device_name} calculated risk is {bd['risk_score']}"
        assert len(bd["factors"]) == 0, f"Device {dev.device_name} has unexpected risk factors: {bd['factors']}"

    # Verify Network Health is 100 (HEALTHY)
    health = calculate_network_health(db)
    assert health["health_score"] == 100.0, f"Health score is {health['health_score']}, expected 100.0"
    assert health["health_status"] == "HEALTHY", f"Health status is {health['health_status']}, expected HEALTHY"
    assert health["raw_deductions"] == 0.0
    assert health["total_deductions"] == 0.0
    db.close()

# -------------------------------------------------------------
# USER ITEM 2: Remove Double Counting (Single Port Scan Factor List)
# -------------------------------------------------------------
def test_item2_single_port_scan_factor_list_no_double_counting():
    """
    User Item 2: Remove double counting: one event may add points only once.
    Show the factor list for a single port scan and explain each line.
    Every factor must come from a different cause.
    """
    headers = get_analyst_headers()
    # Trigger a single port scan from PC-01 (192.168.1.10)
    ev_res = client.post("/api/simulation/trigger-event", json={
        "event_type": "PORT_SCAN",
        "source_ip": "192.168.1.10",
        "target_ip": "192.168.1.20"
    }, headers=headers)
    assert ev_res.status_code == 200

    db = SessionLocal()
    dev = db.query(Device).filter(Device.device_name == "PC-01").first()
    assert dev is not None

    bd = calculate_device_risk_breakdown(dev, db)
    factors = bd["factors"]

    # Exactly 1 factor for a single port scan with no other events
    assert len(factors) == 1, f"Expected exactly 1 factor, found {len(factors)}: {factors}"
    factor = factors[0]
    assert "Port Scanning" in factor["name"]
    # PC-01 is MEDIUM criticality (multiplier 1.0x) -> 25.0 * 1.0 = 25.0 pts
    assert factor["impact"] == 25.0
    assert "Cause: Injected security event finding" in factor["description"]

    # Sum of factor impacts equals total risk score exactly
    assert round(sum(f["impact"] for f in factors), 1) == bd["risk_score"]
    assert bd["risk_score"] == 25.0
    # Trust score derives from base trust (80.0) - risk (25.0) = 55.0
    assert bd["trust_score"] == 55.0
    db.close()

# -------------------------------------------------------------
# USER ITEM 3: Remove Circular Dependency Between Risk and Trust
# -------------------------------------------------------------
def test_item3_recomputing_twice_gives_same_numbers_no_circular_dependency():
    """
    User Item 3: Remove the circular dependency between risk and trust.
    Risk comes only from events and device state; trust = base trust minus risk.
    Recomputing twice gives the same numbers (idempotent).
    """
    headers = get_analyst_headers()
    client.post("/api/simulation/trigger-event", json={
        "event_type": "PORT_SCAN",
        "source_ip": "192.168.1.10",
        "target_ip": "192.168.1.20"
    }, headers=headers)

    db = SessionLocal()
    dev = db.query(Device).filter(Device.device_name == "PC-01").first()

    # Pass 1
    bd1 = calculate_device_risk_breakdown(dev, db)
    risk1, trust1 = bd1["risk_score"], bd1["trust_score"]

    # Update device model with Pass 1 values
    dev.risk_score = risk1
    dev.trust_score = trust1
    db.flush()

    # Pass 2
    bd2 = calculate_device_risk_breakdown(dev, db)
    risk2, trust2 = bd2["risk_score"], bd2["trust_score"]

    # Pass 3
    dev.risk_score = risk2
    dev.trust_score = trust2
    db.flush()
    bd3 = calculate_device_risk_breakdown(dev, db)
    risk3, trust3 = bd3["risk_score"], bd3["trust_score"]

    assert risk1 == risk2 == risk3 == 25.0, "Risk score diverged across recomputations!"
    assert trust1 == trust2 == trust3 == 55.0, "Trust score diverged across recomputations!"
    db.close()

# -------------------------------------------------------------
# USER ITEM 4: Strong Sync Check (Database Risk Only Divergence)
# -------------------------------------------------------------
def test_item4_strong_sync_check_database_risk_only_divergence():
    """
    User Item 4: Make the sync check stronger: compare device IDs, status, risk
    and the set of structural links between the database and the graph.
    Changing a device's risk in the database only shows OUT OF SYNC.
    """
    headers = get_analyst_headers()

    # 1. Initially synchronized
    res1 = client.get("/api/digital-twin/topology")
    assert res1.status_code == 200
    assert res1.json()["state"] == "SYNCHRONIZED"

    # 2. Mutate a device's risk score in the database ONLY (bypass sync)
    db = SessionLocal()
    dev = db.query(Device).filter(Device.device_name == "PC-01").first()
    assert dev is not None
    dev.risk_score = 42.0  # Divergence
    db.commit()
    db.close()

    # 3. Strong sync check immediately flags OUT OF SYNC
    res2 = client.get("/api/digital-twin/topology")
    assert res2.status_code == 200
    assert res2.json()["state"] == "OUT OF SYNC"

    # 4. Trigger resynchronization
    sync_res = client.post("/api/digital-twin/sync", headers=headers)
    assert sync_res.status_code == 200
    assert sync_res.json()["status"] == "SUCCESS"

    # 5. Graph is now synchronized with DB
    res3 = client.get("/api/digital-twin/topology")
    assert res3.status_code == 200
    assert res3.json()["state"] == "SYNCHRONIZED"
    node = next(n for n in res3.json()["nodes"] if n["name"] == "PC-01")
    assert node["risk_score"] == 42.0

# -------------------------------------------------------------
# USER ITEM 5: Health Formula Clamping Under Extreme Threats
# -------------------------------------------------------------
def test_item5_health_score_clamped_with_extreme_threats():
    """
    User Item 5: Fix the health formula claim: state that the score is clamped
    between 0 and 100, and make sure the breakdown shown in the UI explains the clamp.
    Test with extreme threats.
    """
    db = SessionLocal()
    # Inject multiple severe alerts to trigger penalties > 100 pts
    for i in range(8):
        db.add(Alert(
            event_type="COMPROMISED_HOST",
            severity="CRITICAL",
            title=f"Severe Breach #{i}",
            message=f"Critical C2 compromised host finding #{i}",
            rule_name="RULE-07: COMPROMISED_HOST",
            recommendation="Isolate infected host and initiate incident response.",
            source_ip=f"192.168.1.{10+i}",
            destination_ip="203.0.113.1",
            status="NEW",
            occurrence_count=1,
            last_seen=utcnow(),
            created_at=utcnow()
        ))
    # Mark devices compromised
    for d in db.query(Device).limit(5).all():
        d.status = "COMPROMISED"
        d.risk_score = 90.0
    db.commit()

    health = calculate_network_health(db)
    # Raw deductions exceed 100.0
    assert health["raw_deductions"] > 100.0, f"Raw deductions {health['raw_deductions']} should exceed 100"
    # Health score is clamped strictly at 0.0
    assert health["health_score"] == 0.0
    assert health["health_status"] == "CRITICAL"
    assert health["is_clamped"] is True
    assert "clamped at 0.0" in health["clamp_explanation"]
    assert health["total_deductions"] == 100.0
    db.close()

# -------------------------------------------------------------
# USER ITEM 6: Graph Rebuilt from DB at Startup / New Twin Object
# -------------------------------------------------------------
def test_item6_graph_rebuilt_from_db_on_startup_and_new_twin_matches():
    """
    User Item 6: Confirm the graph is rebuilt from the database at server startup.
    Add a test that creates a new twin object and checks it matches the database.
    """
    db = SessionLocal()
    db_count = db.query(Device).count()
    assert db_count == 12

    # Instantiate fresh standalone twin engine
    new_twin = DigitalTwinEngine()
    assert not new_twin.is_synchronized
    assert len(new_twin.graph.nodes) == 0

    # Sync fresh twin from DB (mirroring startup logic in main.py)
    new_twin.sync_from_database(db)

    assert new_twin.is_synchronized is True
    assert len(new_twin.graph.nodes) == db_count

    # Verify all devices and structural links match
    for d in db.query(Device).all():
        assert d.device_name in new_twin.graph
        node_data = new_twin.graph.nodes[d.device_name]
        assert node_data["id"] == d.id
        assert node_data["ip"] == d.ip_address
        assert node_data["status"] == d.status

    # Verify structural links exist
    structural_edges = [
        (u, v) for u, v, d in new_twin.graph.edges(data=True)
        if d.get("edge_type") == "structural"
    ]
    assert len(structural_edges) >= 11
    assert new_twin.check_sync_status(db) == "SYNCHRONIZED"
    db.close()

# -------------------------------------------------------------
# Phase 5 Standard Acceptance Checks (Recovered / Regressions)
# -------------------------------------------------------------
def test_acceptance_check_1_add_device_updates_graph_counts():
    headers = get_admin_headers()
    init_node_count = len(digital_twin.graph.nodes)

    res = client.post("/api/devices", json={
        "device_name": "Test-Twin-PC",
        "ip_address": "192.168.1.99",
        "mac_address": "00:50:56:C0:00:99",
        "device_type": "Workstation",
        "os_type": "Linux",
        "criticality": "MEDIUM",
        "trust_level": "MEDIUM",
        "status": "ONLINE"
    }, headers=headers)
    assert res.status_code == 200
    created = res.json()

    assert len(digital_twin.graph.nodes) == init_node_count + 1
    assert "Test-Twin-PC" in digital_twin.graph

    top_res = client.get("/api/digital-twin/topology")
    assert top_res.status_code == 200
    assert top_res.json()["total_nodes"] == init_node_count + 1
    assert top_res.json()["state"] == "SYNCHRONIZED"

    del_res = client.delete(f"/api/devices/{created['id']}", headers=headers)
    assert del_res.status_code == 200

def test_acceptance_check_3_resolving_or_false_positive_lowers_risk_and_recovers_health():
    headers = get_analyst_headers()
    ev_res = client.post("/api/simulation/trigger-event", json={
        "event_type": "PORT_SCAN",
        "source_ip": "192.168.1.10",
        "target_ip": "192.168.1.20"
    }, headers=headers)
    assert ev_res.status_code == 200
    alert_id = ev_res.json()["alert_id"]

    db = SessionLocal()
    dev = db.query(Device).filter(Device.ip_address == "192.168.1.10").first()
    high_risk = dev.risk_score
    assert high_risk == 25.0
    assert dev.status == "SUSPICIOUS"
    health_degraded = calculate_network_health(db)["health_score"]
    db.close()

    # Resolve alert
    patch_res = client.patch(f"/api/alerts/{alert_id}", json={"status": "RESOLVED"}, headers=headers)
    assert patch_res.status_code == 200

    db = SessionLocal()
    dev_after = db.query(Device).filter(Device.ip_address == "192.168.1.10").first()
    assert dev_after.risk_score == 0.0  # Fully recovered!
    assert dev_after.risk_score < high_risk
    assert dev_after.status == "ONLINE"  # Status recovered
    health_recovered = calculate_network_health(db)["health_score"]
    assert health_recovered == 100.0
    assert health_recovered > health_degraded
    db.close()

def test_acceptance_check_6_deleting_or_taking_offline_updates_graph_and_health_penalty():
    admin_headers = get_admin_headers()
    analyst_headers = get_analyst_headers()

    db = SessionLocal()
    init_health = calculate_network_health(db)["health_score"]
    assert init_health == 100.0
    dev = db.query(Device).filter(Device.device_name == "PC-02").first()
    dev_id = dev.id
    db.close()

    # Take offline
    patch_res = client.patch(f"/api/devices/{dev_id}", json={"status": "OFFLINE"}, headers=analyst_headers)
    assert patch_res.status_code == 200

    db = SessionLocal()
    health_offline = calculate_network_health(db)
    assert health_offline["penalties"]["offline_devices"] > 0
    assert health_offline["health_score"] < 100.0
    assert digital_twin.graph.nodes["PC-02"]["status"] == "OFFLINE"
    db.close()

    # Restore
    client.patch(f"/api/devices/{dev_id}", json={"status": "ONLINE"}, headers=analyst_headers)
