import time
import sys
import numpy as np
from datetime import timedelta

# Ensure backend directory is in path
sys.path.insert(0, 'backend')

from app.main import app
from fastapi.testclient import TestClient
from app.database import SessionLocal, engine
from app.models.device import Device
from app.models.traffic import TrafficRecord
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.utils.time_utils import utcnow
from sqlalchemy import text

client = TestClient(app)
db = SessionLocal()
now = utcnow()

# 1. Ensure indexes exist
with engine.connect() as conn:
    for sql in [
        "CREATE INDEX IF NOT EXISTS idx_tr_data_source_ts ON traffic_records (data_source, timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_tr_protocol ON traffic_records (protocol)",
        "CREATE INDEX IF NOT EXISTS idx_tr_src_bytes ON traffic_records (source_ip, bytes)"
    ]:
        try:
            conn.execute(text(sql))
            conn.commit()
        except Exception:
            pass

print("Ensuring 100 devices...")
db.query(Device).delete()
devs = [
    Device(
        device_name=f"Dev-{i:03d}",
        ip_address=f"192.168.1.{i}",
        mac_address=f"00:1a:2b:3c:4d:{i:02x}",
        device_type="Workstation",
        criticality="CRITICAL" if i == 1 else "HIGH" if i <= 5 else "MEDIUM" if i <= 20 else "LOW",
        risk_score=float(i % 80),
        status="ONLINE",
        device_source="SIMULATED"
    )
    for i in range(1, 101)
]
db.add_all(devs)
db.commit()

print("Seeding 50,000 traffic records...")
db.query(TrafficRecord).delete()
db.commit()

records = [
    TrafficRecord(
        timestamp=now - timedelta(seconds=(i % 3600)),
        source_ip=f"192.168.1.{(i % 80) + 1}",
        destination_ip="192.168.1.254",
        protocol=["TCP", "UDP", "ICMP", "DNS"][i % 4],
        packet_count=10,
        bytes=1024,
        is_anomalous=1 if (i % 200 == 0) else 0,
        data_source="SIMULATED"
    )
    for i in range(50000)
]
db.bulk_save_objects(records)
db.commit()

print("Adding alerts & security events...")
db.query(Alert).delete()
db.query(SecurityEvent).delete()
for i in range(10):
    db.add(Alert(
        title=f"Port Scan Detection #{i}",
        rule_name="PORT_SCAN",
        severity="HIGH",
        message=f"Suspicious port scan observed from host #{i}",
        recommendation="Investigate source host and block scanning port.",
        status="NEW",
        source_ip="192.168.1.10",
        created_at=now - timedelta(minutes=i)
    ))
    db.add(SecurityEvent(
        event_type="PORT_SCAN",
        severity="HIGH",
        source_device="192.168.1.10",
        description=f"Port scan security event #{i}",
        created_at=now - timedelta(minutes=i)
    ))
db.commit()

token_res = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
assert token_res.status_code == 200
access_token = token_res.json()["access_token"]
headers = {"Authorization": f"Bearer {access_token}"}

endpoints = [
    ("Analytics Telemetry (/api/analytics)", "/api/analytics?time_range=all&data_source=ALL"),
    ("Report Summary (/api/reports/summary)", "/api/reports/summary?time_range=all&data_source=ALL"),
    ("Report HTML Export (/api/reports/export-html)", "/api/reports/export-html?time_range=all&data_source=ALL"),
    ("Report PDF Export (/api/reports/export-pdf)", "/api/reports/export-pdf?time_range=all&data_source=ALL"),
]

print("\n" + "=" * 70)
print("RUNNING 30 ITERATIONS PER ENDPOINT (50,000 RECORDS + 100 DEVICES)")
print("=" * 70)

results = {}
for name, url in endpoints:
    timings = []
    # Warmup
    client.get(url, headers=headers)
    for _ in range(30):
        t0 = time.perf_counter()
        r = client.get(url, headers=headers)
        assert r.status_code == 200, f"Error {r.status_code}: {r.text}"
        elapsed = (time.perf_counter() - t0) * 1000
        timings.append(elapsed)
    
    med = float(np.median(timings))
    p95 = float(np.percentile(timings, 95))
    mx = float(np.max(timings))
    mn = float(np.min(timings))
    results[name] = {"min": mn, "median": med, "p95": p95, "max": mx}
    print(f"\n{name}:")
    print(f"  Min:    {mn:.2f} ms")
    print(f"  Median: {med:.2f} ms")
    print(f"  P95:    {p95:.2f} ms")
    print(f"  Max:    {mx:.2f} ms")
    print(f"  Under 500ms SLA: {'PASS' if mx < 500.0 else 'FAIL'}")

db.close()
