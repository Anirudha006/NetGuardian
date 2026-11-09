import time
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, engine, SessionLocal
from app.utils.seed_data import seed_database
from app.digital_twin.twin_engine import digital_twin
from app.simulation.traffic_generator import traffic_generator
from app.models.device import Device
from app.models.connection import NetworkConnection
from app.utils.time_utils import utcnow
from sqlalchemy import text

# Initialize test database
Base.metadata.create_all(bind=engine)
with engine.connect() as conn:
    try:
        conn.execute(text("ALTER TABLE devices ADD COLUMN trust_level VARCHAR(20) DEFAULT 'MEDIUM'"))
        conn.commit()
    except Exception:
        pass

_db = SessionLocal()
# Force re-seed to ensure Phase 2 required documentation-only IPs are loaded
seed_database(_db, force_reset=True)
digital_twin.sync_from_database(_db)
_db.close()

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

def test_seeded_network_documentation_ips_and_levels():
    """Task 1, 2, 3: Verify network is seeded with exact specification names, documentation IPs, and distinct trust/criticality levels."""
    db = SessionLocal()
    devices = db.query(Device).all()
    dev_map = {d.device_name: d for d in devices}
    db.close()

    # Exact Spec Names & IPs:
    # Router, Switch, PC-01, PC-02, PC-03, PC-04, Phone-01, Printer, Server, Database, IoT-Camera, Internet
    assert "Internet" in dev_map
    assert dev_map["Internet"].ip_address == "203.0.113.1"
    assert dev_map["Internet"].trust_level == "UNTRUSTED"

    assert "Router" in dev_map
    assert dev_map["Router"].ip_address == "192.168.1.1"
    assert dev_map["Router"].criticality == "HIGH"
    assert dev_map["Router"].trust_level == "HIGH"

    assert "Switch" in dev_map
    assert dev_map["Switch"].ip_address == "192.168.1.2"
    assert dev_map["Switch"].criticality == "HIGH"
    assert dev_map["Switch"].trust_level == "HIGH"

    assert "PC-01" in dev_map
    assert dev_map["PC-01"].ip_address == "192.168.1.10"
    assert dev_map["PC-01"].criticality == "MEDIUM"
    assert dev_map["PC-01"].trust_level == "MEDIUM"

    assert "PC-02" in dev_map
    assert dev_map["PC-02"].ip_address == "192.168.1.11"
    assert dev_map["PC-02"].criticality == "MEDIUM"
    assert dev_map["PC-02"].trust_level == "MEDIUM"

    assert "PC-03" in dev_map
    assert dev_map["PC-03"].ip_address == "192.168.1.12"
    assert dev_map["PC-03"].criticality == "MEDIUM"
    assert dev_map["PC-03"].trust_level == "MEDIUM"

    assert "PC-04" in dev_map
    assert dev_map["PC-04"].ip_address == "192.168.1.13"
    assert dev_map["PC-04"].criticality == "MEDIUM"
    assert dev_map["PC-04"].trust_level == "MEDIUM"

    assert "Phone-01" in dev_map
    assert dev_map["Phone-01"].ip_address == "192.168.1.14"
    assert dev_map["Phone-01"].criticality == "LOW"
    assert dev_map["Phone-01"].trust_level == "LOW"

    assert "Printer" in dev_map
    assert dev_map["Printer"].ip_address == "192.168.1.30"
    assert dev_map["Printer"].criticality == "LOW"
    assert dev_map["Printer"].trust_level == "MEDIUM"

    assert "Server" in dev_map
    assert dev_map["Server"].ip_address == "192.168.1.20"
    assert dev_map["Server"].criticality == "HIGH"
    assert dev_map["Server"].trust_level == "HIGH"

    assert "Database" in dev_map
    assert dev_map["Database"].ip_address == "192.168.1.21"
    assert dev_map["Database"].criticality == "CRITICAL"
    assert dev_map["Database"].trust_level == "HIGH"

    assert "IoT-Camera" in dev_map
    assert dev_map["IoT-Camera"].ip_address == "192.168.1.40"
    assert dev_map["IoT-Camera"].criticality == "LOW"
    assert dev_map["IoT-Camera"].trust_level == "LOW"

    # Topology: Server-Database connection exists, but Database is NOT directly linked to Switch
    db = SessionLocal()
    server_id = dev_map["Server"].id
    db_id = dev_map["Database"].id
    switch_id = dev_map["Switch"].id

    s_db_conn = db.query(NetworkConnection).filter(
        NetworkConnection.source_device_id == server_id,
        NetworkConnection.destination_device_id == db_id
    ).first()
    assert s_db_conn is not None

    sw_db_conn = db.query(NetworkConnection).filter(
        (NetworkConnection.source_device_id == switch_id) & (NetworkConnection.destination_device_id == db_id)
    ).first()
    assert sw_db_conn is None, "Database must only link to Server, not directly to Switch"
    db.close()

def test_deterministic_traffic_same_seed_and_different_seeds():
    """Acceptance Check 1: The same seed gives the same traffic; different seeds differ."""
    db = SessionLocal()

    # Run batch with seed 777
    traffic_generator.set_seed(777)
    batch_a = [
        (r.source_ip, r.destination_ip, r.protocol, r.destination_port, r.packet_count, r.bytes)
        for r in traffic_generator.generate_tick(db, count=6, scenario="NORMAL", seed=777)
    ]

    # Re-run batch with same seed 777
    traffic_generator.set_seed(777)
    batch_b = [
        (r.source_ip, r.destination_ip, r.protocol, r.destination_port, r.packet_count, r.bytes)
        for r in traffic_generator.generate_tick(db, count=6, scenario="NORMAL", seed=777)
    ]

    assert batch_a == batch_b, "Identical seed must produce identical synthetic traffic flows"

    # Run batch with different seed 888
    traffic_generator.set_seed(888)
    batch_c = [
        (r.source_ip, r.destination_ip, r.protocol, r.destination_port, r.packet_count, r.bytes)
        for r in traffic_generator.generate_tick(db, count=6, scenario="NORMAL", seed=888)
    ]
    db.close()

    assert batch_a != batch_c, "Different seeds must produce different traffic flows"

def test_normal_traffic_values_vary():
    """Acceptance Check 2: Normal traffic values vary naturally, never identical."""
    db = SessionLocal()
    records = traffic_generator.generate_tick(db, count=15, scenario="NORMAL", seed=123)
    byte_values = [r.bytes for r in records]
    durations = [r.duration for r in records]
    ports = [r.destination_port for r in records]
    db.close()

    assert len(records) >= 10

    # Check natural variance
    assert len(set(byte_values)) > 1, "Byte counts must vary naturally"
    assert len(set(durations)) > 1, "Durations must vary naturally"
    assert len(set(ports)) > 1, "Destination service ports must cover multiple protocols"

    # Verify standard services appear
    standard_ports = {443, 53, 9100, 5432, 554, 80}
    assert any(p in standard_ports for p in ports), "Standard services must be exercised"

def test_add_device_validation_and_rejections():
    """Acceptance Check 3: Add-device works and appears on map; invalid IP, MAC, duplicates, and non-admin rejected."""
    admin_headers = get_admin_headers()
    analyst_headers = get_analyst_headers()

    # 1. Analyst cannot add device (403 Forbidden)
    res_analyst = client.post("/api/devices", json={
        "device_name": "Analyst-Device",
        "ip_address": "192.168.1.70",
        "mac_address": "00:1A:2B:3C:4D:70",
        "device_type": "Workstation"
    }, headers=analyst_headers)
    assert res_analyst.status_code == 403

    # 2. Invalid IP address rejected (400)
    res_bad_ip = client.post("/api/devices", json={
        "device_name": "Bad-IP-Device",
        "ip_address": "999.999.999.999",
        "mac_address": "00:1A:2B:3C:4D:71",
        "device_type": "Workstation"
    }, headers=admin_headers)
    assert res_bad_ip.status_code == 400
    assert "Invalid IP address" in res_bad_ip.json()["detail"]

    # 3. Invalid MAC address rejected (400)
    res_bad_mac = client.post("/api/devices", json={
        "device_name": "Bad-MAC-Device",
        "ip_address": "192.168.1.72",
        "mac_address": "not-a-mac",
        "device_type": "Workstation"
    }, headers=admin_headers)
    assert res_bad_mac.status_code == 400
    assert "Invalid MAC address" in res_bad_mac.json()["detail"]

    # 4. Duplicate name rejected (400)
    res_dup_name = client.post("/api/devices", json={
        "device_name": "PC-01",
        "ip_address": "192.168.1.73",
        "mac_address": "00:1A:2B:3C:4D:73",
        "device_type": "Workstation"
    }, headers=admin_headers)
    assert res_dup_name.status_code == 400
    assert "already exists" in res_dup_name.json()["detail"]

    # 5. Duplicate IP rejected (400)
    res_dup_ip = client.post("/api/devices", json={
        "device_name": "Dup-IP-Device",
        "ip_address": "192.168.1.10",
        "mac_address": "00:1A:2B:3C:4D:74",
        "device_type": "Workstation"
    }, headers=admin_headers)
    assert res_dup_ip.status_code == 400
    assert "already exists" in res_dup_ip.json()["detail"]

    # 6. Valid device addition succeeds
    test_device_name = "Sec-Audit-Workstation"
    test_ip = "192.168.1.75"
    test_mac = "00:1A:2B:3C:4D:75"
    res_valid = client.post("/api/devices", json={
        "device_name": test_device_name,
        "ip_address": test_ip,
        "mac_address": test_mac,
        "device_type": "Workstation",
        "os_type": "Debian Linux",
        "criticality": "MEDIUM",
        "trust_level": "HIGH"
    }, headers=admin_headers)
    assert res_valid.status_code == 200
    new_dev = res_valid.json()
    assert new_dev["device_name"] == test_device_name

    # Verify device is attached to Switch and present in Digital Twin graph
    topo = client.get("/api/digital-twin/topology").json()
    topo_nodes = [n["name"] for n in topo["nodes"]]
    assert test_device_name in topo_nodes

    topo_edges = [(e["source"], e["target"]) for e in topo["edges"]]
    assert any(
        (test_device_name, sw) in topo_edges or (sw, test_device_name) in topo_edges
        for sw in ["Switch", "Core-Switch-01"]
    )

def test_baseline_learning():
    """Task 7: Warm-up ticks of normal traffic produce a per-device baseline."""
    headers = get_analyst_headers()
    res = client.post("/api/traffic/baseline/learn?warm_up_ticks=4&seed=55", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["baseline_status"] == "LEARNED"
    assert data["total_profiled_devices"] > 0

    dev_base = data["device_baselines"]
    # Check that at least one Lab PC or Server has average bytes and peers computed
    some_ip = next(iter(dev_base))
    profile = dev_base[some_ip]
    assert "avg_bytes_per_tick" in profile
    assert "usual_peers" in profile
    assert profile["warm_up_ticks"] == 4

def test_100_devices_performance():
    """Acceptance Check 5: 100 devices still render and synchronize smoothly (report load time)."""
    db = SessionLocal()
    try:
        # Create 85 mock devices to reach 100+ devices
        existing_count = db.query(Device).count()
        needed = max(0, 100 - existing_count)
        switch = db.query(Device).filter(Device.device_name.in_(["Switch", "Core-Switch-01"])).first()

        for i in range(needed):
            ip_suffix = 100 + i
            d = Device(
                device_name=f"Scale-Host-{i:03d}",
                ip_address=f"10.0.1.{ip_suffix}",
                mac_address=f"AA:BB:CC:DD:{i//256:02X}:{i%256:02X}",
                device_type="Workstation",
                os_type="Linux",
                criticality="LOW",
                trust_level="MEDIUM",
                status="ONLINE",
                risk_score=10.0,
                trust_score=90.0
            )
            db.add(d)
            db.flush()
            if switch:
                conn = NetworkConnection(
                    source_device_id=d.id,
                    destination_device_id=switch.id,
                    protocol="ETHERNET",
                    source_port=0,
                    destination_port=0,
                    packet_count=5,
                    bytes_transferred=320
                )
                db.add(conn)
        db.commit()

        # Measure synchronization and topology generation time
        t0 = time.perf_counter()
        digital_twin.sync_from_database(db)
        topo_data = digital_twin.get_topology()
        elapsed_ms = (time.perf_counter() - t0) * 1000

        print(f"\n[Performance Benchmark] 100-Device Topology Graph Generation: {elapsed_ms:.2f} ms")
        assert topo_data["total_nodes"] >= 100
        assert elapsed_ms < 500.0, f"Topology generation took {elapsed_ms}ms (must be < 500ms)"

        # Measure API retrieval time
        t1 = time.perf_counter()
        resp = client.get("/api/digital-twin/topology")
        api_elapsed_ms = (time.perf_counter() - t1) * 1000
        assert resp.status_code == 200
        print(f"[Performance Benchmark] 100-Device HTTP Topology Response: {api_elapsed_ms:.2f} ms")
        assert api_elapsed_ms < 500.0
    finally:
        # Clean up mock scaled devices
        db.query(NetworkConnection).filter(NetworkConnection.bytes_transferred == 320).delete()
        db.query(Device).filter(Device.device_name.like("Scale-Host-%")).delete()
        db.commit()
        digital_twin.sync_from_database(db)
        db.close()

def test_rate_limit_ip_does_not_trust_x_forwarded_for_by_default():
    """Item 1: Verify rate limit does NOT trust X-Forwarded-For header by default.
    Changing X-Forwarded-For on each attempt does NOT bypass the limit."""
    from app.routes.auth import clear_all_failed_attempts
    from app.config import settings
    clear_all_failed_attempts()

    # Ensure TRUSTED_PROXIES is empty by default
    orig_trusted = settings.TRUSTED_PROXIES
    settings.TRUSTED_PROXIES = ""

    target_user = "spoof_attempt_user"
    # Connecting client address: 198.51.100.1
    spoof_client = TestClient(app, client=("198.51.100.1", 50000))

    try:
        # 5 failed attempts with constantly shifting X-Forwarded-For headers
        for i in range(5):
            fake_ip = f"203.0.113.{100 + i}"
            r = spoof_client.post(
                "/api/auth/login",
                json={"username": target_user, "password": "wrong_password"},
                headers={"X-Forwarded-For": fake_ip}
            )
            assert r.status_code == 401

        # 6th attempt with yet another new X-Forwarded-For must STILL be blocked (429)
        # because the server keys on real client.host (198.51.100.1) and rejects spoofing!
        r6 = spoof_client.post(
            "/api/auth/login",
            json={"username": target_user, "password": "wrong_password"},
            headers={"X-Forwarded-For": "10.99.99.99"}
        )
        assert r6.status_code == 429, "Spoofed X-Forwarded-For must NOT bypass login rate limit"
        assert "Too many failed login attempts" in r6.json()["detail"]
    finally:
        settings.TRUSTED_PROXIES = orig_trusted
        clear_all_failed_attempts()

def test_rate_limit_different_real_client_not_locked_out():
    """Item 1: Verify a different real client IP is not locked out when another IP triggers rate limiting."""
    from app.routes.auth import clear_all_failed_attempts
    clear_all_failed_attempts()

    target_user = "shared_target_user"
    client_a = TestClient(app, client=("192.168.1.100", 50001))
    client_b = TestClient(app, client=("192.168.1.200", 50002))

    try:
        # Client A fails 5 times -> locked out on 6th
        for _ in range(5):
            r = client_a.post("/api/auth/login", json={"username": target_user, "password": "bad"})
            assert r.status_code == 401
        assert client_a.post("/api/auth/login", json={"username": target_user, "password": "bad"}).status_code == 429

        # Client B (different real connection address) attempts login for the same user
        # Should NOT be locked out (returns 401, not 429)
        r_b = client_b.post("/api/auth/login", json={"username": target_user, "password": "bad"})
        assert r_b.status_code == 401, "Different real client IP must have its own isolated rate-limit bucket"
    finally:
        clear_all_failed_attempts()

def test_rate_limit_trusted_proxy_honors_x_forwarded_for():
    """Item 1: Verify X-Forwarded-For IS read when connecting address is in TRUSTED_PROXIES."""
    from app.routes.auth import clear_all_failed_attempts
    from app.config import settings
    clear_all_failed_attempts()

    orig_trusted = settings.TRUSTED_PROXIES
    settings.TRUSTED_PROXIES = "192.168.1.99"
    proxy_client = TestClient(app, client=("192.168.1.99", 50000))

    try:
        target_user = "proxy_user"
        # 5 failed attempts behind trusted proxy for upstream IP 10.10.10.10
        for _ in range(5):
            r = proxy_client.post(
                "/api/auth/login",
                json={"username": target_user, "password": "bad"},
                headers={"X-Forwarded-For": "10.10.10.10"}
            )
            assert r.status_code == 401

        # 6th attempt from 10.10.10.10 is rate-limited
        r6 = proxy_client.post(
            "/api/auth/login",
            json={"username": target_user, "password": "bad"},
            headers={"X-Forwarded-For": "10.10.10.10"}
        )
        assert r6.status_code == 429

        # But a different upstream client (10.10.10.20) through the same trusted proxy is NOT locked out
        r_other = proxy_client.post(
            "/api/auth/login",
            json={"username": target_user, "password": "bad"},
            headers={"X-Forwarded-For": "10.10.10.20"}
        )
        assert r_other.status_code == 401
    finally:
        settings.TRUSTED_PROXIES = orig_trusted
        clear_all_failed_attempts()

def test_traffic_records_50000_cap_and_fast_queries():
    """Item 5: Raise traffic_records cap to 50,000, make configurable, and confirm queries stay fast."""
    from app.models.traffic import TrafficRecord
    from app.config import settings
    from datetime import datetime

    assert settings.MAX_TRAFFIC_RECORDS == 50000
    assert traffic_generator.max_records_stored == 50000

    db = SessionLocal()
    try:
        # Check starting count
        initial_count = db.query(TrafficRecord).count()

        # Seed 50,000 rows in bulk using bulk_insert_mappings for instant generation
        total_to_insert = 50000
        now = utcnow()
        batch_size = 10000

        print(f"\n[Traffic Cap Benchmark] Inserting {total_to_insert} synthetic records in batches of {batch_size}...")
        t_insert_start = time.perf_counter()
        for b in range(0, total_to_insert, batch_size):
            records_batch = [
                {
                    "timestamp": now,
                    "source_ip": f"192.168.1.{10 + (i % 5)}",
                    "destination_ip": "192.168.1.20" if i % 2 == 0 else "192.168.1.21",
                    "protocol": "TCP" if i % 3 != 0 else "UDP",
                    "source_port": 32000 + (i % 20000),
                    "destination_port": 443 if i % 2 == 0 else 5432,
                    "packet_count": 6 + (i % 10),
                    "bytes": 1024 + (i % 5000),
                    "duration": 0.05,
                    "is_anomalous": 1 if i % 50 == 0 else 0
                }
                for i in range(b, b + batch_size)
            ]
            db.bulk_insert_mappings(TrafficRecord, records_batch)
            db.commit()
        t_insert_elapsed = time.perf_counter() - t_insert_start
        print(f"[Traffic Cap Benchmark] Bulk inserted 50,000 rows in {t_insert_elapsed:.2f}s")

        total_rows = db.query(TrafficRecord).count()
        assert total_rows >= 50000

        # Query 1: Recent 50 records (REST endpoint /api/traffic?limit=50)
        t0 = time.perf_counter()
        res_recent = client.get("/api/traffic?limit=50")
        t_recent_ms = (time.perf_counter() - t0) * 1000
        assert res_recent.status_code == 200
        assert len(res_recent.json()) == 50
        print(f"[Traffic Cap Benchmark] /api/traffic?limit=50 against 50,000 rows: {t_recent_ms:.2f} ms")
        assert t_recent_ms < 100.0, f"Query took {t_recent_ms:.2f}ms (must be < 100ms)"

        # Query 2: Anomalies filter (REST endpoint /api/traffic?anomalies_only=true)
        t1 = time.perf_counter()
        res_anom = client.get("/api/traffic?limit=50&anomalies_only=true")
        t_anom_ms = (time.perf_counter() - t1) * 1000
        assert res_anom.status_code == 200
        print(f"[Traffic Cap Benchmark] /api/traffic (anomalies_only) against 50,000 rows: {t_anom_ms:.2f} ms")
        assert t_anom_ms < 100.0

        # Query 3: Traffic stats aggregation (/api/traffic/stats)
        t2 = time.perf_counter()
        res_stats = client.get("/api/traffic/stats")
        t_stats_ms = (time.perf_counter() - t2) * 1000
        assert res_stats.status_code == 200
        stats = res_stats.json()
        assert stats["total_packets"] > 0
        assert stats["anomalous_records"] > 0
        print(f"[Traffic Cap Benchmark] /api/traffic/stats aggregation over 50,000 rows: {t_stats_ms:.2f} ms")
        assert t_stats_ms < 100.0, f"Stats aggregation took {t_stats_ms:.2f}ms (must be fast < 100ms)"
    finally:
        # Clean up benchmark rows
        db.query(TrafficRecord).delete()
        db.commit()
        db.close()
