import os
import sys
import time
import httpx
import numpy as np
from datetime import timedelta
from playwright.sync_api import sync_playwright

# Point SQLAlchemy at backend/netguardian.db matching the running backend server
sys.path.insert(0, os.path.abspath("backend"))
os.environ["DATABASE_URL"] = "sqlite:///./backend/netguardian.db"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.device import Device
from app.models.connection import NetworkConnection
from app.models.traffic import TrafficRecord
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.utils.time_utils import utcnow

BACKEND_URL = "http://127.0.0.1:8000"
FRONTEND_URL = "http://localhost:5175"

def run_benchmark():
    db_path = os.path.abspath("backend/netguardian.db")
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    now = utcnow()

    print("=== Phase 9 Task 8: Performance Benchmark (100 Devices, 50,000 Traffic Records) ===")

    # 1. Seed 100 devices & topology connections
    print("Seeding 100 devices and network connections...")
    db.query(NetworkConnection).delete()
    db.query(TrafficRecord).delete()
    db.query(Alert).delete()
    db.query(SecurityEvent).delete()
    db.query(Device).delete()
    db.commit()

    devices = []
    # Core nodes
    core_gw = Device(device_name="Gateway-Router", ip_address="192.168.1.1", mac_address="00:10:00:00:00:01", device_type="Router", criticality="HIGH", trust_level="HIGH", status="ONLINE", risk_score=0.0, device_source="SIMULATED")
    core_sw = Device(device_name="Core-Switch", ip_address="192.168.1.2", mac_address="00:10:00:00:00:02", device_type="Switch", criticality="HIGH", trust_level="HIGH", status="ONLINE", risk_score=0.0, device_source="SIMULATED")
    core_srv = Device(device_name="Server", ip_address="192.168.1.20", mac_address="00:10:00:00:00:20", device_type="Server", criticality="CRITICAL", trust_level="HIGH", status="ONLINE", risk_score=0.0, device_source="SIMULATED")
    core_db = Device(device_name="Database", ip_address="192.168.1.21", mac_address="00:10:00:00:00:21", device_type="Database", criticality="CRITICAL", trust_level="HIGH", status="ONLINE", risk_score=0.0, device_source="SIMULATED")
    devices.extend([core_gw, core_sw, core_srv, core_db])

    for i in range(5, 101):
        devices.append(Device(
            device_name=f"Host-{i:03d}",
            ip_address=f"192.168.1.{30 + i}",
            mac_address=f"00:1a:2b:3c:4d:{i:02x}",
            device_type="Workstation" if i <= 75 else "IoT",
            criticality="MEDIUM" if i <= 20 else "LOW",
            trust_level="MEDIUM" if i <= 50 else "LOW",
            risk_score=float((i * 7) % 65),
            status="SUSPICIOUS" if i % 25 == 0 else "ONLINE",
            device_source="SIMULATED"
        ))
    db.add_all(devices)
    db.commit()

    # Create hierarchical connections
    db_devs = db.query(Device).all()
    gw = next(d for d in db_devs if d.device_name == "Gateway-Router")
    sw = next(d for d in db_devs if d.device_name == "Core-Switch")
    srv = next(d for d in db_devs if d.device_name == "Server")
    dbd = next(d for d in db_devs if d.device_name == "Database")

    conns = [
        NetworkConnection(source_device_id=gw.id, destination_device_id=sw.id, protocol="TCP", source_port=443, destination_port=443, packet_count=500, bytes_transferred=64000),
        NetworkConnection(source_device_id=sw.id, destination_device_id=srv.id, protocol="TCP", source_port=80, destination_port=443, packet_count=1200, bytes_transferred=256000),
        NetworkConnection(source_device_id=srv.id, destination_device_id=dbd.id, protocol="TCP", source_port=5000, destination_port=5432, packet_count=2400, bytes_transferred=512000),
    ]
    for d in db_devs:
        if d.id not in (gw.id, sw.id, srv.id, dbd.id):
            conns.append(NetworkConnection(
                source_device_id=d.id,
                destination_device_id=sw.id,
                protocol="TCP",
                source_port=50000 + (d.id % 100),
                destination_port=443,
                packet_count=50,
                bytes_transferred=4096
            ))
    db.add_all(conns)
    db.commit()

    # 2. Seed 50,000 traffic records
    print("Seeding 50,000 traffic records...")
    records = [
        TrafficRecord(
            timestamp=now - timedelta(seconds=(i % 3600)),
            source_ip=f"192.168.1.{35 + (i % 90)}",
            destination_ip="192.168.1.20",
            protocol=["TCP", "UDP", "ICMP", "DNS"][i % 4],
            packet_count=12,
            bytes=1536,
            is_anomalous=1 if (i % 250 == 0) else 0,
            data_source="SIMULATED"
        )
        for i in range(50000)
    ]
    db.bulk_save_objects(records)
    db.commit()

    # 3. Seed 10 alerts & security events
    for i in range(10):
        db.add(Alert(
            title=f"Scale Audit Alert #{i}",
            rule_name="PORT_SCAN",
            severity="HIGH" if i < 4 else "MEDIUM",
            message=f"Port scan sweep observed on scale host #{i}",
            recommendation="Inspect and isolate if unauthorized.",
            status="NEW",
            source_ip=f"192.168.1.{10 + i}",
            created_at=now - timedelta(minutes=i)
        ))
        db.add(SecurityEvent(
            event_type="PORT_SCAN",
            severity="HIGH" if i < 4 else "MEDIUM",
            source_device=f"192.168.1.{10 + i}",
            description=f"Scale audit event #{i}",
            created_at=now - timedelta(minutes=i)
        ))
    db.commit()
    db.close()

    # 4. Login & trigger twin sync on live backend
    with httpx.Client(timeout=30.0) as client:
        login_res = client.post(f"{BACKEND_URL}/api/auth/login", json={"username": "admin", "password": "admin123"})
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        sync_res = client.post(f"{BACKEND_URL}/api/digital-twin/sync", headers=headers)
        assert sync_res.status_code == 200
        print(f"Digital Twin Sync: {sync_res.json()['nodes_count']} nodes, {sync_res.json()['edges_count']} edges")

        # 5. API Latency Benchmarks (15 runs each)
        endpoints = [
            ("Dashboard (/api/dashboard)", "/api/dashboard"),
            ("Devices (/api/devices)", "/api/devices"),
            ("Digital Twin Topology (/api/digital-twin/topology)", "/api/digital-twin/topology"),
            ("Alerts (/api/alerts)", "/api/alerts"),
            ("Analytics (/api/analytics)", "/api/analytics?time_range=all&data_source=ALL"),
            ("Reports Summary (/api/reports/summary)", "/api/reports/summary?time_range=all&data_source=ALL"),
        ]

        print("\n--- API LATENCY BENCHMARKS (100 Devices, 50,000 Traffic Records, 15 iterations) ---")
        for label, path in endpoints:
            # Warmup
            client.get(f"{BACKEND_URL}{path}", headers=headers)
            times = []
            for _ in range(15):
                t0 = time.perf_counter()
                resp = client.get(f"{BACKEND_URL}{path}", headers=headers)
                assert resp.status_code == 200, f"Failed {path}: {resp.status_code}"
                times.append((time.perf_counter() - t0) * 1000.0)
            print(f"{label:<52} | min: {np.min(times):6.1f}ms | median: {np.median(times):6.1f}ms | p95: {np.percentile(times, 95):6.1f}ms | max: {np.max(times):6.1f}ms")

    # 6. Browser Page Load & Topology Render Timings (Playwright)
    print("\n--- BROWSER PAGE LOAD & TOPOLOGY RENDER TIMINGS (100 Nodes, 50k Records) ---")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 950})
        page = context.new_page()
        page.route("**/*fonts.g*", lambda route: route.abort())
        page.add_init_script("localStorage.setItem('ng_onboarded', 'true');")

        # Measure Login -> Dashboard load
        page.goto(f"{FRONTEND_URL}/")
        page.wait_for_selector('input[type="text"]', timeout=10000)
        page.fill('input[type="text"]', 'admin')
        page.fill('input[type="password"]', 'admin123')
        t_start = time.perf_counter()
        page.click('button[type="submit"]')
        page.wait_for_selector('text=NETWORK HEALTH SCORE', timeout=15000)
        t_dash = (time.perf_counter() - t_start) * 1000.0
        print(f"Dashboard Page (Initial Login + Render):            {t_dash:7.1f} ms")

        # Measure Network Inventory (100 devices table)
        t_start = time.perf_counter()
        page.click('button.ng-navitem:has-text("Network")')
        page.wait_for_selector('h1:has-text("Network Operations")', timeout=15000)
        page.wait_for_selector('text=Host-005', timeout=15000)
        t_net = (time.perf_counter() - t_start) * 1000.0
        print(f"Network Inventory Page (100 Devices Render):        {t_net:7.1f} ms")

        # Measure Digital Twin Topology Map Render Time (100 nodes SVG/DOM)
        t_start = time.perf_counter()
        page.click('button.ng-navitem:has-text("Digital Twin")')
        page.wait_for_selector('[data-testid="topology-node"]', timeout=15000)
        page.wait_for_function("document.querySelectorAll('[data-testid=\"topology-node\"]').length >= 90", timeout=15000)
        t_twin = (time.perf_counter() - t_start) * 1000.0
        node_el_count = page.evaluate("document.querySelectorAll('[data-testid=\"topology-node\"]').length")
        print(f"Digital Twin Topology Map (100 Nodes Render):       {t_twin:7.1f} ms (Rendered {node_el_count} nodes)")

        # Measure Analytics Page (7 Charts over 50k records)
        t_start = time.perf_counter()
        page.click('button.ng-navitem:has-text("Analytics")')
        page.wait_for_selector('text=Protocol Usage', timeout=15000)
        t_an = (time.perf_counter() - t_start) * 1000.0
        print(f"Analytics Page (50,000 Records Aggregation Render): {t_an:7.1f} ms")

        # Measure Reports Page
        t_start = time.perf_counter()
        page.click('button.ng-navitem:has-text("Reports")')
        page.wait_for_selector('text=11. Conclusion', timeout=15000)
        t_rep = (time.perf_counter() - t_start) * 1000.0
        print(f"Reports Page (Full Security Report Render):         {t_rep:7.1f} ms")

        browser.close()

    # 7. Restore clean baseline state using seed_database(force_reset=True) & sync twin
    from app.utils.seed_data import seed_database
    db_restore = SessionLocal()
    seed_database(db_restore, force_reset=True)
    db_restore.close()

    with httpx.Client(timeout=15.0) as client:
        login_res = client.post(f"{BACKEND_URL}/api/auth/login", json={"username": "admin", "password": "admin123"})
        token = login_res.json()["access_token"]
        client.post(f"{BACKEND_URL}/api/digital-twin/sync", headers={"Authorization": f"Bearer {token}"})
        print("\nBaseline seeded database cleanly restored.")

if __name__ == "__main__":
    run_benchmark()
