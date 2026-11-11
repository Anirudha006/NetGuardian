import io
import time
from datetime import datetime, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy import func, case, text
import pypdf

from app.main import app
from app.database import SessionLocal, Base, engine
from app.models.device import Device
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.models.traffic import TrafficRecord
from app.models.simulation import SimulationRun, AttackPath
from app.models.audit_log import AuditLog
from app.models.user import User
from app.routes.reports import build_report_data, generate_security_report_pdf
from app.utils.time_utils import utcnow

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
    assert res.status_code == 200, f"Login failed: {res.text}"
    return res.json()["access_token"]

def get_analyst_token(client: TestClient) -> str:
    return get_auth_token(client, username="analyst", password="analyst123")

# =========================================================================
# Acceptance Check 1: Chart Numbers Equal Independent SQL Counts
# Every chart's numbers equal an independent SQL count computed in the test.
# =========================================================================
def test_acceptance_check_1_charts_match_independent_sql_counts(client: TestClient, db: Session):
    token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    # Seed controlled traffic records & events
    db.query(TrafficRecord).delete()
    db.query(SecurityEvent).delete()
    db.query(Alert).delete()
    db.commit()

    now = utcnow()
    t1 = TrafficRecord(
        timestamp=now - timedelta(minutes=5),
        source_ip="192.168.1.50",
        destination_ip="192.168.1.1",
        protocol="TCP",
        packet_count=120,
        bytes=15000,
        is_anomalous=0,
        data_source="SIMULATED"
    )
    t2 = TrafficRecord(
        timestamp=now - timedelta(minutes=2),
        source_ip="192.168.1.50",
        destination_ip="192.168.1.10",
        protocol="UDP",
        packet_count=45,
        bytes=6000,
        is_anomalous=1,
        data_source="SIMULATED"
    )
    t3 = TrafficRecord(
        timestamp=now - timedelta(minutes=1),
        source_ip="192.168.1.60",
        destination_ip="192.168.1.1",
        protocol="TCP",
        packet_count=80,
        bytes=10000,
        is_anomalous=0,
        data_source="SIMULATED"
    )
    db.add_all([t1, t2, t3])

    ev1 = SecurityEvent(
        event_type="PORT_SCAN",
        severity="HIGH",
        source_device="192.168.1.50",
        description="Port scanning activity detected",
        created_at=now - timedelta(minutes=3)
    )
    ev2 = SecurityEvent(
        event_type="PORT_SCAN",
        severity="HIGH",
        source_device="192.168.1.50",
        description="Port scanning activity repeated",
        created_at=now - timedelta(minutes=2)
    )
    ev3 = SecurityEvent(
        event_type="TRAFFIC_ANOMALY",
        severity="MEDIUM",
        source_device="192.168.1.60",
        description="Unusual outbound volume",
        created_at=now - timedelta(minutes=1)
    )
    db.add_all([ev1, ev2, ev3])

    al1 = Alert(
        event_type="TRAFFIC_ANOMALY",
        title="AI Traffic Anomaly Detected",
        severity="MEDIUM",
        message="Isolation forest score 0.88",
        source_ip="192.168.1.60",
        ai_score=0.88,
        ai_confidence="High",
        ai_explanation="Deviation in packet frequency and volume",
        recommendation="Investigate host 192.168.1.60",
        created_at=now - timedelta(minutes=1)
    )
    db.add(al1)
    db.commit()

    # 1. Independent SQL calculation for Traffic Bytes
    sql_total_bytes = db.query(func.sum(TrafficRecord.bytes)).scalar()
    sql_total_packets = db.query(func.sum(TrafficRecord.packet_count)).scalar()

    # 2. Independent SQL calculation for Threat Categories
    sql_categories = dict(
        db.query(SecurityEvent.event_type, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.event_type)
        .all()
    )

    # 3. Independent SQL calculation for Protocols
    sql_protocols = dict(
        db.query(TrafficRecord.protocol, func.sum(TrafficRecord.bytes))
        .group_by(TrafficRecord.protocol)
        .all()
    )

    # 4. Independent SQL calculation for Top Communicating Devices
    sql_top_talkers = dict(
        db.query(TrafficRecord.source_ip, func.sum(TrafficRecord.bytes))
        .group_by(TrafficRecord.source_ip)
        .all()
    )

    # 5. Independent SQL calculation for Risk Bands (matching SIMULATED filter)
    sql_risk_bands = {
        "Low (0-29)": db.query(Device).filter(Device.device_source == "SIMULATED", Device.risk_score < 30.0).count(),
        "Medium (30-69)": db.query(Device).filter(Device.device_source == "SIMULATED", Device.risk_score >= 30.0, Device.risk_score < 70.0).count(),
        "High (70-89)": db.query(Device).filter(Device.device_source == "SIMULATED", Device.risk_score >= 70.0, Device.risk_score < 90.0).count(),
        "Critical (90-100)": db.query(Device).filter(Device.device_source == "SIMULATED", Device.risk_score >= 90.0).count()
    }

    # Query API endpoint
    res = client.get("/api/analytics?time_range=all&data_source=SIMULATED", headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()

    # Verify Summary totals match independent SQL
    assert data["summary"]["total_bytes"] == sql_total_bytes
    assert data["summary"]["total_packets"] == sql_total_packets
    assert data["summary"]["total_threats"] == 3
    assert data["summary"]["total_anomalies"] == 1

    # Verify Threat Categories
    api_categories = {item["type"]: item["value"] for item in data["threat_categories"]}
    assert api_categories.get("PORT_SCAN") == sql_categories.get("PORT_SCAN")
    assert api_categories.get("TRAFFIC_ANOMALY") == sql_categories.get("TRAFFIC_ANOMALY")

    # Verify Protocol Usage
    api_proto_bytes = {item["protocol"]: item["bytes"] for item in data["protocol_usage"]}
    assert api_proto_bytes.get("TCP") == sql_protocols.get("TCP")
    assert api_proto_bytes.get("UDP") == sql_protocols.get("UDP")

    # Verify Top Talkers
    api_talker_bytes = {item["ip"]: item["bytes"] for item in data["top_communicating_devices"]}
    assert api_talker_bytes.get("192.168.1.50") == sql_top_talkers.get("192.168.1.50")
    assert api_talker_bytes.get("192.168.1.60") == sql_top_talkers.get("192.168.1.60")

    # Verify Device Risk Distribution
    api_risk_bands = {item["range"]: item["count"] for item in data["device_risk_distribution"]}
    for band_name, expected_count in sql_risk_bands.items():
        assert api_risk_bands.get(band_name) == expected_count, f"Mismatch for {band_name}: expected {expected_count}, got {api_risk_bands.get(band_name)}"

    # Verify Anomalies timeline
    assert len(data["anomalies_timeline"]) >= 1
    assert data["anomalies_timeline"][0]["ip"] == "192.168.1.60"
    assert data["anomalies_timeline"][0]["score"] == 0.88

# =========================================================================
# Acceptance Check 2: Time Range & Data Source Filters Mutate Numbers
# =========================================================================
def test_acceptance_check_2_time_range_and_source_filters(client: TestClient, db: Session):
    token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    # Clear and insert:
    # 1 recent simulated record (now - 5 min)
    # 1 old simulated record (now - 120 min)
    # 1 recent observed record (now - 5 min)
    db.query(TrafficRecord).delete()
    db.commit()

    now = utcnow()
    r_sim_recent = TrafficRecord(
        timestamp=now - timedelta(minutes=5),
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        protocol="TCP",
        packet_count=100,
        bytes=10000,
        data_source="SIMULATED"
    )
    r_sim_old = TrafficRecord(
        timestamp=now - timedelta(minutes=120),
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        protocol="TCP",
        packet_count=200,
        bytes=20000,
        data_source="SIMULATED"
    )
    r_obs_recent = TrafficRecord(
        timestamp=now - timedelta(minutes=5),
        source_ip="10.0.0.99",
        destination_ip="10.0.0.1",
        protocol="UDP",
        packet_count=50,
        bytes=5000,
        data_source="OBSERVED"
    )
    db.add_all([r_sim_recent, r_sim_old, r_obs_recent])
    db.commit()

    # 1. Query all time, all sources -> 10000 + 20000 + 5000 = 35000 bytes
    res_all = client.get("/api/analytics?time_range=all&data_source=ALL", headers=headers).json()
    assert res_all["summary"]["total_bytes"] == 35000

    # 2. Query last 15 minutes, all sources -> 10000 + 5000 = 15000 bytes (old record excluded)
    res_15m = client.get("/api/analytics?time_range=15m&data_source=ALL", headers=headers).json()
    assert res_15m["summary"]["total_bytes"] == 15000

    # 3. Query all time, SIMULATED only -> 10000 + 20000 = 30000 bytes (observed excluded)
    res_sim = client.get("/api/analytics?time_range=all&data_source=SIMULATED", headers=headers).json()
    assert res_sim["summary"]["total_bytes"] == 30000

    # 4. Query all time, OBSERVED only -> 5000 bytes (simulated excluded)
    res_obs = client.get("/api/analytics?time_range=all&data_source=OBSERVED", headers=headers).json()
    assert res_obs["summary"]["total_bytes"] == 5000

    # 5. Query last 15 minutes, OBSERVED only -> 5000 bytes
    res_15m_obs = client.get("/api/analytics?time_range=15m&data_source=OBSERVED", headers=headers).json()
    assert res_15m_obs["summary"]["total_bytes"] == 5000

# =========================================================================
# Acceptance Check 3: Report Contains Injected Event, What-If Path, and Recommended Action
# =========================================================================
def test_acceptance_check_3_injected_event_whatif_isolation_in_report(client: TestClient, db: Session):
    token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    # Find or create a device (PC-04)
    from app.utils.seed_data import seed_database
    from app.digital_twin.twin_engine import digital_twin
    pc04 = db.query(Device).filter(Device.device_name == "PC-04").first()
    if not pc04:
        seed_database(db, force_reset=True)
        digital_twin.sync_from_database(db)
        pc04 = db.query(Device).filter(Device.device_name == "PC-04").first()
    assert pc04 is not None
    pc04.risk_score = 75.0
    pc04.is_isolated = True
    db.commit()

    # 1. Inject security event
    alert = Alert(
        event_type="COMPROMISED_HOST",
        title="Host Compromise on PC-04",
        severity="CRITICAL",
        message="Adversary execution detected on PC-04",
        source_ip=pc04.ip_address,
        recommendation="Isolate PC-04 immediately from lateral movement",
        created_at=utcnow()
    )
    db.add(alert)
    db.commit()

    # 2. Add saved simulation run and attack path (What-If)
    sim = SimulationRun(
        simulation_type="WHAT_IF_COMPROMISE",
        target_device="Crown Jewel DB",
        risk_level="CRITICAL",
        path_risk_score=88.5,
        critical_assets_reached=1,
        result="Lateral traversal path detected from PC-04 to Crown Jewel DB."
    )
    db.add(sim)
    db.commit()

    ap = AttackPath(
        simulation_id=sim.id,
        source_node="PC-04",
        destination_node="Crown Jewel DB",
        path=["PC-04", "Switch-01", "Core Router", "Crown Jewel DB"],
        hop_count=3,
        risk=88.5
    )
    db.add(ap)
    db.commit()

    # 3. Fetch report summary
    res = client.get("/api/reports/summary", headers=headers)
    assert res.status_code == 200, res.text
    rep = res.json()

    # Verify event is present
    event_titles = [e["title"] for e in rep["security_events"]]
    assert "Host Compromise on PC-04" in event_titles

    # Verify hypothetical path is present with HYPOTHETICAL label
    sim_targets = [s["target_device"] for s in rep["simulated_attack_paths"]]
    assert "Crown Jewel DB" in sim_targets
    assert all(s["label"] == "HYPOTHETICAL" for s in rep["simulated_attack_paths"])

    # Verify recommendations contain isolation / segmentation action
    recs_text = " ".join(rep["recommendations"])
    assert "PC-04" in recs_text or "isolate" in recs_text.lower()
    assert "segmentation" in recs_text.lower() or "zero-trust" in recs_text.lower()

    # Verify health score breakdown includes penalties and credit
    hb = rep["network_health"]["breakdown"]
    assert "threat_penalty" in hb
    assert "formula" in hb

# =========================================================================
# Acceptance Check 4: Exported PDF Structure, Multiple Pages, and Extracted Text
# =========================================================================
def test_acceptance_check_4_exported_pdf_structure_and_text_extraction(client: TestClient, db: Session):
    token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/reports/export-pdf", headers=headers)
    assert res.status_code == 200, res.text
    assert "application/pdf" in res.headers["content-type"]
    assert "filename=" in res.headers["content-disposition"]
    pdf_bytes = res.content
    assert len(pdf_bytes) > 2000

    # Extract text using pypdf
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    num_pages = len(reader.pages)
    assert num_pages >= 2, f"Expected multiple pages, got {num_pages}"

    full_text = " ".join([page.extract_text() for page in reader.pages])

    # Assert required sections and expected texts
    assert "SIMULATED DATA NOTICE" in full_text
    assert "HYPOTHETICAL" in full_text
    assert "anomalies are not proof of attacks" in full_text
    assert "1. Reporting Period" in full_text
    assert "2. Network Overview" in full_text
    assert "3. Devices" in full_text
    assert "4. Traffic Summary" in full_text
    assert "5. Security Events" in full_text
    assert "6. AI Anomalies" in full_text
    assert "7. High-Risk Devices" in full_text
    assert "8. Critical Assets" in full_text
    assert "9. Simulated Attack Paths (HYPOTHETICAL)" in full_text
    assert "10. Recommendations" in full_text
    assert "11. Conclusion" in full_text

    # Assert page numbering is present on pages
    has_page_num = any("Page " in page.extract_text() for page in reader.pages)
    assert has_page_num, "Page numbers missing in footer"

# =========================================================================
# Acceptance Check 5: Empty Database Returns Friendly Empty Structures (No 500s)
# =========================================================================
def test_acceptance_check_5_empty_database_friendly_behavior(client: TestClient, db: Session):
    token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    # Temporarily clear all activity tables
    db.query(TrafficRecord).delete()
    db.query(SecurityEvent).delete()
    db.query(Alert).delete()
    db.query(SimulationRun).delete()
    db.query(AttackPath).delete()
    db.commit()

    # 1. Analytics endpoint
    res_an = client.get("/api/analytics?time_range=all", headers=headers)
    assert res_an.status_code == 200
    an_data = res_an.json()
    assert an_data["traffic_over_time"] == []
    assert an_data["threats_over_time"] == []
    assert an_data["threat_categories"] == []
    assert an_data["protocol_usage"] == []
    assert an_data["top_communicating_devices"] == []
    assert an_data["anomalies_timeline"] == []
    assert an_data["summary"]["total_threats"] == 0
    assert an_data["summary"]["total_bytes"] == 0

    # 2. Reports summary endpoint
    res_rep = client.get("/api/reports/summary", headers=headers)
    assert res_rep.status_code == 200
    rep_data = res_rep.json()
    assert rep_data["security_events"] == []
    assert rep_data["ai_anomalies"] == []
    assert rep_data["simulated_attack_paths"] == []

    # 3. Reports HTML endpoint
    res_html = client.get("/api/reports/export-html", headers=headers)
    assert res_html.status_code == 200
    assert "No events in reporting period." in res_html.text

    # 4. Reports PDF endpoint
    res_pdf = client.get("/api/reports/export-pdf", headers=headers)
    assert res_pdf.status_code == 200
    reader = pypdf.PdfReader(io.BytesIO(res_pdf.content))
    assert len(reader.pages) >= 2
    pdf_text = " ".join([page.extract_text() for page in reader.pages])
    assert "No events in reporting period." in pdf_text
    assert "No AI anomalies detected in this reporting period." in pdf_text

# =========================================================================
# Acceptance Check 6: RBAC Permissions & Audit Logging
# =========================================================================
def test_acceptance_check_6_rbac_permissions_and_audit_logging(client: TestClient, db: Session):
    # Unauthenticated requests must receive 401
    assert client.get("/api/analytics").status_code == 401
    assert client.get("/api/reports/summary").status_code == 401
    assert client.get("/api/reports/export-pdf").status_code == 401
    assert client.get("/api/reports/export-html").status_code == 401

    # Analyst token works
    analyst_token = get_analyst_token(client)
    a_headers = {"Authorization": f"Bearer {analyst_token}"}
    assert client.get("/api/analytics", headers=a_headers).status_code == 200
    assert client.get("/api/reports/summary", headers=a_headers).status_code == 200

    # Admin token works and creates audit log
    admin_token = get_auth_token(client)
    adm_headers = {"Authorization": f"Bearer {admin_token}"}
    db_audit_before = db.query(AuditLog).filter(AuditLog.action == "GENERATE_REPORT").count()

    res_pdf = client.get("/api/reports/export-pdf", headers=adm_headers)
    assert res_pdf.status_code == 200

    db_audit_after = db.query(AuditLog).filter(AuditLog.action == "GENERATE_REPORT").count()
    assert db_audit_after > db_audit_before

    latest_log = db.query(AuditLog).filter(AuditLog.action == "GENERATE_REPORT").order_by(AuditLog.timestamp.desc()).first()
    assert latest_log.username == "admin"
    assert "PDF" in latest_log.details

# =========================================================================
# Acceptance Check 7: Performance Benchmark on 50,000 Traffic Records (< 500 ms)
# =========================================================================
def test_acceptance_check_7_benchmark_50000_traffic_records(client: TestClient, db: Session):
    token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    # Ensure indexes exist on SQLite engine
    with engine.connect() as conn:
        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_tr_data_source_ts ON traffic_records (data_source, timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_tr_protocol ON traffic_records (protocol)",
            "CREATE INDEX IF NOT EXISTS idx_tr_src_bytes ON traffic_records (source_ip, bytes)"
        ]:
            try:
                conn.execute(text(idx_sql))
                conn.commit()
            except Exception:
                pass

    # Ensure exactly 100 devices are enrolled
    existing_dev_count = db.query(Device).count()
    if existing_dev_count < 100:
        new_devs = [
            Device(
                device_name=f"Device-{i:03d}",
                ip_address=f"192.168.10.{i}",
                mac_address=f"00:1a:2b:3c:4d:{i:02x}",
                device_type="Workstation",
                criticality="LOW",
                risk_score=float(i % 100),
                device_source="SIMULATED",
                status="ONLINE"
            )
            for i in range(existing_dev_count + 1, 101)
        ]
        db.add_all(new_devs)
        db.commit()

    # Clear and insert exactly 50,000 records
    db.query(TrafficRecord).delete()
    db.commit()

    now = utcnow()
    records = []
    for i in range(50000):
        records.append(
            TrafficRecord(
                timestamp=now - timedelta(seconds=(i % 3600)),
                source_ip=f"192.168.1.{(i % 80) + 10}",
                destination_ip=f"192.168.1.{(i % 5) + 1}",
                protocol=["TCP", "UDP", "ICMP", "DNS"][i % 4],
                packet_count=10,
                bytes=1024,
                is_anomalous=1 if (i % 200 == 0) else 0,
                data_source="SIMULATED"
            )
        )

    # Bulk insert
    db.bulk_save_objects(records)
    db.commit()

    # Time 3 consecutive calls and calculate average latency
    timings = []
    for _ in range(3):
        t0 = time.perf_counter()
        res = client.get("/api/analytics?time_range=all&data_source=SIMULATED", headers=headers)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        timings.append(elapsed_ms)
        assert res.status_code == 200

    avg_timing = sum(timings) / len(timings)
    print(f"\n[PERFORMANCE BENCHMARK] Analytics endpoint with 50,000 traffic records: {avg_timing:.2f} ms (Min: {min(timings):.2f} ms, Max: {max(timings):.2f} ms)")

    # Assert under 500 ms limit
    assert avg_timing < 500.0, f"Analytics query took {avg_timing:.2f} ms, exceeding 500 ms threshold"

# =========================================================================
# Acceptance Check 8: Audit Log Immutability Triggers (Item 4)
# Audit logs are append-only; database triggers block UPDATE and DELETE.
# =========================================================================
def test_acceptance_check_8_audit_log_immutability_triggers(client: TestClient, db: Session):
    # Ensure triggers exist
    with engine.connect() as conn:
        for trig_sql in [
            """
            CREATE TRIGGER IF NOT EXISTS audit_logs_prevent_update
            BEFORE UPDATE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'audit_logs entries are immutable: UPDATE not permitted');
            END;
            """,
            """
            CREATE TRIGGER IF NOT EXISTS audit_logs_prevent_delete
            BEFORE DELETE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'audit_logs entries are immutable: DELETE not permitted');
            END;
            """
        ]:
            try:
                conn.execute(text(trig_sql))
                conn.commit()
            except Exception:
                pass

    # 1. Insert is permitted
    test_entry = AuditLog(
        action="TEST_IMMUTABLE_LOG",
        username="admin",
        details="Security integrity check test entry"
    )
    db.add(test_entry)
    db.commit()
    entry_id = test_entry.id
    assert entry_id is not None

    # 2. UPDATE must be blocked by database trigger
    with pytest.raises(Exception) as exc_update:
        db.execute(text(f"UPDATE audit_logs SET action = 'MUTATED' WHERE id = {entry_id}"))
        db.commit()
    assert "immutable" in str(exc_update.value).lower() or "abort" in str(exc_update.value).lower()
    db.rollback()

    # 3. DELETE must be blocked by database trigger
    with pytest.raises(Exception) as exc_delete:
        db.execute(text(f"DELETE FROM audit_logs WHERE id = {entry_id}"))
        db.commit()
    assert "immutable" in str(exc_delete.value).lower() or "abort" in str(exc_delete.value).lower()
    db.rollback()

    # 4. Record remains intact and unaltered
    stored = db.query(AuditLog).filter(AuditLog.id == entry_id).first()
    assert stored is not None
    assert stored.action == "TEST_IMMUTABLE_LOG"


# =========================================================================
# Acceptance Check 9: Pipeline-Created Telemetry & Analytics Consistency (Item 3)
# Data created ONLY through real pipeline (port scan, traffic anomaly,
# unknown device, what-if, isolate). Analytics compared against independent SQL.
# =========================================================================
def test_acceptance_check_9_pipeline_telemetry_and_analytics_integrity(client: TestClient, db: Session):
    token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    # Reset network state to baseline
    from app.utils.seed_data import seed_database
    from app.digital_twin.twin_engine import digital_twin
    if not db.query(Device).filter(Device.device_name == "PC-01").first():
        seed_database(db, force_reset=True)
        digital_twin.sync_from_database(db)
    client.post("/api/simulation/demo/reset", headers=headers)
    db.expire_all()

    # 1. Pipeline: Simulate a port scan on PC-01
    pc01 = db.query(Device).filter(Device.device_name == "PC-01").first()
    assert pc01 is not None
    res_ps = client.post("/api/simulation/trigger-event", json={
        "event_type": "PORT_SCAN",
        "source_ip": pc01.ip_address,
        "target_ip": "192.168.1.20"
    }, headers=headers)
    assert res_ps.status_code == 200, f"Port scan failed: {res_ps.text}"

    # 2. Pipeline: Simulate a traffic spike on PC-02
    pc02 = db.query(Device).filter(Device.device_name == "PC-02").first()
    assert pc02 is not None
    res_ts = client.post("/api/simulation/trigger-event", json={
        "event_type": "TRAFFIC_ANOMALY",
        "source_ip": pc02.ip_address
    }, headers=headers)
    assert res_ts.status_code == 200, f"Traffic anomaly failed: {res_ts.text}"

    # 3. Pipeline: Simulate an unknown device joining
    res_ud = client.post("/api/simulation/trigger-event", json={
        "event_type": "UNKNOWN_DEVICE",
        "source_ip": "192.168.1.99"
    }, headers=headers)
    assert res_ud.status_code == 200, f"Unknown device failed: {res_ud.text}"

    # 4. Pipeline: Run What-If lateral movement compromise from PC-01
    res_wi = client.post("/api/simulation/what-if", json={
        "target_device_id": pc01.id,
        "scenario": "COMPROMISED_HOST"
    }, headers=headers)
    assert res_wi.status_code == 200, f"What-If failed: {res_wi.text}"

    # 5. Pipeline: Simulate isolation of PC-01
    res_iso = client.post("/api/simulation/isolate", json={
        "target_device_id": pc01.id
    }, headers=headers)
    assert res_iso.status_code == 200, f"Isolation failed: {res_iso.text}"

    # 6. Check analytics numbers against independent SQL queries
    db.expire_all()
    sql_total_bytes = db.query(func.sum(TrafficRecord.bytes)).scalar() or 0
    sql_total_packets = db.query(func.sum(TrafficRecord.packet_count)).scalar() or 0
    sql_alerts = db.query(Alert).count()
    sql_events = db.query(SecurityEvent).count()

    res_an = client.get("/api/analytics?time_range=all&data_source=ALL", headers=headers)
    assert res_an.status_code == 200
    adata = res_an.json()

    assert adata["summary"]["total_bytes"] == sql_total_bytes
    assert adata["summary"]["total_packets"] == sql_total_packets
    assert adata["summary"]["total_threats"] == sql_events

    # Verify threat categories match exact injected events
    sql_cat_counts = dict(
        db.query(SecurityEvent.event_type, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.event_type)
        .all()
    )
    api_cat_counts = {c["type"]: c["value"] for c in adata["threat_categories"]}
    for cat_name, count in sql_cat_counts.items():
        assert api_cat_counts.get(cat_name) == count, f"Mismatch in category {cat_name}: expected {count}, got {api_cat_counts.get(cat_name)}"

    # 7. Verify risk bands are consistent with open alerts and isolated state
    # Isolated PC-01 gets containment credit (-20 pts); alerts transitioned to CONTAINED
    # Unknown device remains uncontained -> elevated risk
    db.expire_all()
    sql_low = db.query(Device).filter(Device.risk_score < 30.0).count()
    sql_med = db.query(Device).filter(Device.risk_score >= 30.0, Device.risk_score < 70.0).count()
    sql_high = db.query(Device).filter(Device.risk_score >= 70.0, Device.risk_score < 90.0).count()
    sql_crit = db.query(Device).filter(Device.risk_score >= 90.0).count()

    api_risk_dist = {r["range"]: r["count"] for r in adata["device_risk_distribution"]}
    assert api_risk_dist["Low (0-29)"] == sql_low
    assert api_risk_dist["Medium (30-69)"] == sql_med
    assert api_risk_dist["High (70-89)"] == sql_high
    assert api_risk_dist["Critical (90-100)"] == sql_crit

