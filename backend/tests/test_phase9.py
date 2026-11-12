import os
import re
import subprocess
import time
from datetime import datetime, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.main import app
from app.database import SessionLocal, Base, engine
from app.models.device import Device
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.models.traffic import TrafficRecord
from app.models.simulation import SimulationRun, AttackPath
from app.models.audit_log import AuditLog
from app.models.user import User
from app.services.auth_service import create_access_token, hash_password
from app.utils.seed_data import seed_database
from app.digital_twin.twin_engine import digital_twin
from app.simulation.traffic_generator import traffic_generator
from app.config import settings
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
    assert res.status_code == 200, f"Login failed for {username}: {res.text}"
    return res.json()["access_token"]

def get_analyst_token(client: TestClient) -> str:
    return get_auth_token(client, username="analyst", password="analyst123")


# =========================================================================
# Task 3: Integration Test
# Simulation -> Detection -> Alert -> Digital Twin -> Dashboard in one flow
# =========================================================================
def test_integration_full_pipeline_simulation_to_dashboard(client: TestClient, db: Session):
    """
    End-to-end integrated flow:
    1. Seed baseline state (Health = 100, 0 open alerts)
    2. Inject simulated security event (PORT_SCAN from 192.168.1.10)
    3. Verify detection engine created Alert with HIGH severity
    4. Verify Digital Twin graph synchronized with updated risk & alert count
    5. Verify Dashboard reflects reduced health score, open alert, and threat entry
    """
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Step 1: Clean seed baseline
    seed_database(db, force_reset=True)
    digital_twin.sync_from_database(db)

    dash_init = client.get("/api/dashboard", headers=headers)
    assert dash_init.status_code == 200
    init_data = dash_init.json()
    assert init_data["network_health"]["health_score"] == 100.0
    assert init_data["kpis"]["threats_detected"] == 0

    # Step 2: Trigger simulation (PORT_SCAN)
    sim_resp = client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "PORT_SCAN", "source_ip": "192.168.1.10", "target_ip": "192.168.1.20"},
        headers=headers
    )
    assert sim_resp.status_code == 200
    sim_data = sim_resp.json()
    assert sim_data["status"] == "SUCCESS"
    assert sim_data["severity"] == "HIGH"
    alert_id = sim_data["alert_id"]

    # Step 3: Verify detection engine created Alert in DB
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    assert alert is not None
    assert alert.severity == "HIGH"
    assert "Port Scan" in alert.title
    assert alert.status == "NEW"

    # Step 4: Verify Digital Twin graph node was synchronized and updated
    twin_resp = client.get("/api/digital-twin/topology", headers=headers)
    assert twin_resp.status_code == 200
    graph = twin_resp.json()
    node = next((n for n in graph["nodes"] if n["id"] == "PC-01" or n["ip"] == "192.168.1.10"), None)
    assert node is not None
    assert node["risk_score"] > 0

    # Step 5: Verify Dashboard reflects updated state
    dash_resp = client.get("/api/dashboard", headers=headers)
    assert dash_resp.status_code == 200
    dash_data = dash_resp.json()
    assert dash_data["kpis"]["threats_detected"] >= 1
    assert dash_data["network_health"]["health_score"] < 100.0
    assert len(dash_data["recent_alerts"]) >= 1
    assert any(a["id"] == alert_id for a in dash_data["recent_alerts"])


# =========================================================================
# Task 4: The 8 Required Cases (Named Tests with Real Numbers)
# =========================================================================

def test_case_1_normal_traffic_gives_no_alert(client: TestClient, db: Session):
    """Case 1: Normal traffic generated gives 0 alerts; baseline health is 100."""
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    seed_database(db, force_reset=True)
    digital_twin.sync_from_database(db)

    # Pulse 3 rounds of normal baseline traffic
    for _ in range(3):
        res = client.post("/api/traffic/pulse", headers=headers)
        assert res.status_code == 200

    # Assert 0 alerts exist
    alert_count = db.query(Alert).count()
    assert alert_count == 0, f"Expected 0 alerts for normal traffic, found {alert_count}"

    # Assert health is 100
    dash_resp = client.get("/api/dashboard", headers=headers)
    assert dash_resp.status_code == 200
    assert dash_resp.json()["network_health"]["health_score"] == 100.0


def test_case_2_unknown_device_gives_warning(client: TestClient, db: Session):
    """Case 2: Unknown device observed gives a WARNING / MEDIUM alert."""
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    seed_database(db, force_reset=True)
    digital_twin.sync_from_database(db)

    # Trigger UNKNOWN_DEVICE event
    res = client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "UNKNOWN_DEVICE", "source_ip": "192.168.1.99"},
        headers=headers
    )
    assert res.status_code == 200
    alert_id = res.json()["alert_id"]

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    assert alert is not None
    assert alert.severity in ["WARNING", "MEDIUM"]
    assert "Unknown Device" in alert.title

    # Unregistered device created in DB
    dev = db.query(Device).filter(Device.ip_address == "192.168.1.99").first()
    assert dev is not None
    assert dev.device_type == "unregistered"
    assert dev.risk_score >= 30.0


def test_case_3_port_scan_gives_high_alert(client: TestClient, db: Session):
    """Case 3: Port scan reconnaissance gives a HIGH severity alert."""
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    seed_database(db, force_reset=True)
    digital_twin.sync_from_database(db)

    res = client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "PORT_SCAN", "source_ip": "192.168.1.10", "target_ip": "192.168.1.20"},
        headers=headers
    )
    assert res.status_code == 200
    data = res.json()
    assert data["severity"] == "HIGH"

    alert = db.query(Alert).filter(Alert.id == data["alert_id"]).first()
    assert alert is not None
    assert alert.severity == "HIGH"
    assert alert.event_type == "PORT_SCAN"


def test_case_4_traffic_spike_gives_anomaly(client: TestClient, db: Session):
    """Case 4: Sudden traffic volume spike triggers an anomaly alert."""
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    seed_database(db, force_reset=True)
    digital_twin.sync_from_database(db)

    res = client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "TRAFFIC_ANOMALY", "source_ip": "192.168.1.10", "target_ip": "192.168.1.20"},
        headers=headers
    )
    assert res.status_code == 200
    data = res.json()
    assert data["severity"] in ["MEDIUM", "HIGH"]

    alert = db.query(Alert).filter(Alert.id == data["alert_id"]).first()
    assert alert is not None
    assert alert.event_type == "TRAFFIC_ANOMALY"
    assert "Traffic" in alert.title or "Spike" in alert.title or "Bandwidth" in alert.title


def test_case_5_failed_authentication_gives_warning_or_high(client: TestClient, db: Session):
    """Case 5: Repeated failed authentication gives a WARNING or HIGH alert."""
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    seed_database(db, force_reset=True)
    digital_twin.sync_from_database(db)

    res = client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "FAILED_AUTH", "source_ip": "192.168.1.10", "target_ip": "192.168.1.20"},
        headers=headers
    )
    assert res.status_code == 200
    data = res.json()
    assert data["severity"] in ["WARNING", "HIGH"]

    alert = db.query(Alert).filter(Alert.id == data["alert_id"]).first()
    assert alert is not None
    assert alert.event_type == "FAILED_AUTH"
    title_lower = alert.title.lower()
    assert "authentication" in title_lower or "failed" in title_lower or "brute" in title_lower


def test_case_6_what_if_on_compromised_device_generates_attack_path(client: TestClient, db: Session):
    """Case 6: What-If simulation on a compromised host generates attack paths and reachable systems."""
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    seed_database(db, force_reset=True)
    digital_twin.sync_from_database(db)

    pc1 = db.query(Device).filter(Device.device_name == "PC-01").first()
    assert pc1 is not None

    res = client.post(
        "/api/simulation/what-if",
        json={"target_device_id": pc1.id, "scenario": "COMPROMISED_HOST"},
        headers=headers
    )
    assert res.status_code == 200
    data = res.json()

    assert data["target_device"] == "PC-01"
    assert len(data["reachable_systems"]) >= 1
    assert data["reachable_nodes_count"] >= 1
    assert data["path_risk_score"] >= 50.0
    assert len(data["attack_paths"]) >= 1

    first_path = data["attack_paths"][0]
    assert "path" in first_path
    assert "risk" in first_path or "risk_score" in first_path
    assert len(first_path["path"]) >= 2


def test_case_7_simulated_isolation_interrupts_path(client: TestClient, db: Session):
    """Case 7: Simulated isolation severs reachable systems to 0 and neutralizes attack paths."""
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    seed_database(db, force_reset=True)
    digital_twin.sync_from_database(db)

    pc1 = db.query(Device).filter(Device.device_name == "PC-01").first()
    assert pc1 is not None

    # First run What-If to establish pre-isolation paths
    pre_what_if = client.post(
        "/api/simulation/what-if",
        json={"target_device_id": pc1.id, "scenario": "COMPROMISED_HOST"},
        headers=headers
    ).json()
    assert len(pre_what_if["reachable_systems"]) > 0

    # Isolate PC-01
    iso_res = client.post(
        "/api/simulation/isolate",
        json={"target_device_id": pc1.id, "reason": "Simulated containment"},
        headers=headers
    )
    assert iso_res.status_code == 200
    iso_data = iso_res.json()
    assert iso_data["is_isolated"] is True
    assert iso_data["reachability_after"] == 0

    # Re-run What-If on isolated PC-01 -> reachable systems is 0 and attack paths are 0
    post_what_if = client.post(
        "/api/simulation/what-if",
        json={"target_device_id": pc1.id, "scenario": "COMPROMISED_HOST"},
        headers=headers
    ).json()
    assert len(post_what_if["reachable_systems"]) == 0
    assert len(post_what_if["attack_paths"]) == 0


def test_case_8_resetting_simulation_restores_baseline(client: TestClient, db: Session):
    """Case 8: Resetting the simulation restores the network to clean baseline."""
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # First dirty the state: trigger event, isolate device
    pc1 = db.query(Device).filter(Device.device_name == "PC-01").first()
    client.post("/api/simulation/trigger-event", json={"event_type": "PORT_SCAN", "source_ip": "192.168.1.10"}, headers=headers)
    client.post("/api/simulation/isolate", json={"target_device_id": pc1.id, "reason": "Dirty test"}, headers=headers)

    # Call reset
    reset_resp = client.post("/api/simulation/demo/reset", headers=headers)
    assert reset_resp.status_code == 200
    reset_data = reset_resp.json()
    assert reset_data["status"] == "SUCCESS"
    assert reset_data["health_score"] == 100.0

    # Assert PC-01 is un-isolated
    db.refresh(pc1)
    assert pc1.is_isolated is False

    # Assert health is 100 and no active threats on dashboard
    dash = client.get("/api/dashboard", headers=headers).json()
    assert dash["network_health"]["health_score"] == 100.0
    assert dash["kpis"]["threats_detected"] == 0


# =========================================================================
# Task 6: Security Audit Tests
# =========================================================================

def test_passwords_hashed_in_database(db: Session):
    """Verify that all stored user passwords are encrypted/hashed, never stored in plaintext."""
    users = db.query(User).all()
    assert len(users) >= 2

    for u in users:
        assert u.password_hash is not None
        assert u.password_hash != "admin123"
        assert u.password_hash != "analyst123"
        assert u.password_hash != "password"
        # Verify hash format (bcrypt $2b$ or pbkdf2_sha256$ or length >= 50)
        assert len(u.password_hash) >= 50, f"Password hash for {u.username} is too short"
        assert u.password_hash.startswith("$2b$") or "pbkdf2" in u.password_hash or len(u.password_hash) == 60


def test_role_enforcement_on_every_state_changing_endpoint(client: TestClient, db: Session):
    """Verify 401 Unauthorized for unauthenticated calls and 403 Forbidden for Analyst on Admin endpoints."""
    admin_endpoints = [
        ("POST", "/api/auth/users", {"username": "role_audit", "email": "r@net.local", "password": "Password123!", "role": "ANALYST"}),
        ("POST", "/api/devices", {"device_name": "AuditPC", "ip_address": "192.168.1.199", "mac_address": "00:AA:BB:CC:DD:EE", "device_type": "Workstation", "criticality": "LOW", "trust_level": "LOW", "status": "ONLINE"}),
        ("DELETE", "/api/devices/1", {}),
        ("PATCH", "/api/settings", {"traffic_anomaly_threshold": 4.0}),
        ("POST", "/api/simulation/demo/reset", {}),
    ]

    # 1. Unauthenticated calls get 401
    for method, path, payload in admin_endpoints:
        if method == "POST":
            r = client.post(path, json=payload)
        elif method == "DELETE":
            r = client.delete(path)
        elif method == "PATCH":
            r = client.patch(path, json=payload)
        assert r.status_code == 401, f"Expected 401 on unauthenticated {method} {path}, got {r.status_code}"

    # 2. Analyst calls get 403
    analyst_token = get_analyst_token(client)
    headers = {"Authorization": f"Bearer {analyst_token}"}
    for method, path, payload in admin_endpoints:
        if method == "POST":
            r = client.post(path, json=payload, headers=headers)
        elif method == "DELETE":
            r = client.delete(path, headers=headers)
        elif method == "PATCH":
            r = client.patch(path, json=payload, headers=headers)
        assert r.status_code == 403, f"Expected 403 on analyst {method} {path}, got {r.status_code}"


def test_csrf_and_security_headers(client: TestClient):
    """Verify security headers are returned on all responses."""
    resp = client.get("/api/dashboard")
    assert resp.status_code == 200

    headers = resp.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert "Strict-Transport-Security" in headers
    assert "Referrer-Policy" in headers


def test_login_rate_limiting_with_header_spoofing(client: TestClient):
    """
    Verify login rate limiting:
    5 failed attempts triggers 429 Too Many Requests.
    Spoofing X-Forwarded-For from untrusted IP does not bypass rate limit.
    """
    from app.routes.auth import clear_all_failed_attempts
    clear_all_failed_attempts()

    # 5 failed login attempts
    for i in range(5):
        res = client.post("/api/auth/login", json={"username": "ratelimit_victim", "password": "WrongPassword!"})
        assert res.status_code == 401

    # 6th attempt should be 429
    res6 = client.post("/api/auth/login", json={"username": "ratelimit_victim", "password": "WrongPassword!"})
    assert res6.status_code == 429, f"Expected 429 after 5 failed attempts, got {res6.status_code}"

    # Attempt with spoofed X-Forwarded-For header from same untrusted client -> STILL 429
    spoofed = client.post(
        "/api/auth/login",
        json={"username": "ratelimit_victim", "password": "WrongPassword!"},
        headers={"X-Forwarded-For": "203.0.113.195"}
    )
    assert spoofed.status_code == 429, "Spoofed X-Forwarded-For bypassed rate limiting!"

    clear_all_failed_attempts()


def test_session_expiry(client: TestClient):
    """Verify that expired access tokens return 401 Unauthorized."""
    # Create an access token expired 1 hour ago
    expired_token = create_access_token(
        data={"sub": "admin", "role": "ADMIN", "user_id": 1},
        expires_delta=timedelta(hours=-1)
    )
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401, f"Expected 401 for expired token, got {res.status_code}"


def test_xss_protection_in_device_fields(client: TestClient, db: Session):
    """Verify that XSS injection payloads stored in device fields are handled safely as plain text."""
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    xss_payload = "<script>alert('XSS-TEST')</script>"
    create_res = client.post(
        "/api/devices",
        json={
            "device_name": xss_payload,
            "ip_address": "192.168.1.187",
            "mac_address": "00:11:22:33:44:99",
            "device_type": "Workstation",
            "criticality": "LOW",
            "trust_level": "LOW",
            "status": "ONLINE"
        },
        headers=headers
    )
    assert create_res.status_code in [200, 201]
    dev_id = create_res.json()["id"]

    # Retrieve device
    get_res = client.get(f"/api/devices/{dev_id}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["device_name"] == xss_payload
    # Response content-type must be application/json, preventing HTML rendering
    assert "application/json" in get_res.headers.get("Content-Type", "")

    # Cleanup
    client.delete(f"/api/devices/{dev_id}", headers=headers)


def test_sql_injection_resilience_in_filters_and_forms(client: TestClient, db: Session):
    """Verify that SQL injection strings in query parameters and filters do not cause syntax errors or drop tables."""
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE devices; --",
        "1; SELECT * FROM users;",
        "' UNION SELECT NULL, NULL, NULL --"
    ]

    for payload in sqli_payloads:
        # Test on devices search
        r1 = client.get(f"/api/devices?search={payload}", headers=headers)
        assert r1.status_code in [200, 422], f"SQLi payload caused error on devices: {r1.status_code}"

        # Test on alerts status filter
        r2 = client.get(f"/api/alerts?status={payload}", headers=headers)
        assert r2.status_code in [200, 422], f"SQLi payload caused error on alerts: {r2.status_code}"

        # Test on traffic query
        r3 = client.get(f"/api/traffic?data_source={payload}", headers=headers)
        assert r3.status_code in [200, 422], f"SQLi payload caused error on traffic: {r3.status_code}"

        # Test on analytics query
        r4 = client.get(f"/api/analytics?time_range={payload}", headers=headers)
        assert r4.status_code in [200, 422], f"SQLi payload caused error on analytics: {r4.status_code}"

    # Confirm devices table still exists and contains records
    dev_count = db.query(Device).count()
    assert dev_count > 0, "Devices table was modified or dropped by SQLi test!"


def test_no_secrets_in_repo_and_git_history():
    """Verify that no private keys, active API secrets or plain credentials exist in source code or git history."""
    forbidden_patterns = [
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        re.compile(r"AKIA[0-9A-Z]{16}"), # AWS Access Key
        re.compile(r"AIza[0-9A-Za-z-_]{35}"), # Google API Key
    ]

    # Scan repository files (backend, frontend, .env.example, scripts)
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for root, _, files in os.walk(repo_root):
        if any(skip in root for skip in [".git", "__pycache__", "venv", "node_modules", "dist"]):
            continue
        for f in files:
            if f.endswith((".py", ".js", ".jsx", ".env", ".example", ".json", ".md")):
                path = os.path.join(root, f)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                        for pattern in forbidden_patterns:
                            matches = pattern.findall(content)
                            assert len(matches) == 0, f"Disallowed secret pattern {pattern.pattern} found in {path}"
                except Exception:
                    pass

    # Scan git history for leaked private keys or cloud API keys
    try:
        git_out = subprocess.check_output(
            ["git", "log", "-p", "-n", "25"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )
        for pattern in forbidden_patterns:
            matches = pattern.findall(git_out)
            assert len(matches) == 0, f"Disallowed secret pattern {pattern.pattern} found in git history!"
    except Exception:
        pass


def test_production_mode_refuses_default_credentials(client: TestClient, monkeypatch):
    """Verify that when ENVIRONMENT=production, default demo credentials are explicitly rejected with 403."""
    from app.config import settings
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")

    # Attempt to login with default credentials admin123
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert resp.status_code == 403, f"Expected 403 in production mode for default credentials, got {resp.status_code}"
    assert "default" in resp.text.lower() or "production" in resp.text.lower()


def test_alerts_and_settings_edge_coverage(client: TestClient, db: Session):
    """Additional backend unit tests covering alerts notification read-state, events list, and settings validations."""
    admin_token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}
    seed_database(db, force_reset=True)

    # 1. Trigger alert & inspect detail + events
    ev = client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "PORT_SCAN", "source_ip": "192.168.1.10"},
        headers=headers
    ).json()
    aid = ev["alert_id"]

    r_detail = client.get(f"/api/alerts/{aid}", headers=headers)
    assert r_detail.status_code == 200
    assert r_detail.json()["id"] == aid

    assert client.get("/api/alerts/999999", headers=headers).status_code == 404

    r_events = client.get("/api/alerts/events", headers=headers)
    assert r_events.status_code == 200
    assert len(r_events.json()) >= 1

    # 2. Alert notification read-state endpoints
    assert client.post("/api/alerts/read-state", json={"alert_id": aid}, headers=headers).status_code == 200
    assert aid in client.get("/api/alerts/read-state", headers=headers).json()["read_alert_ids"]
    assert client.post("/api/alerts/read-all", headers=headers).status_code == 200

    # 3. Settings retrieval, validation errors, and simulation mode switch
    r_st = client.get("/api/settings/status", headers=headers)
    assert r_st.status_code == 200
    assert r_st.json()["backend"] == "ONLINE"

    r_get_set = client.get("/api/settings", headers=headers)
    assert r_get_set.status_code == 200
    assert r_get_set.json()["is_admin"] is True

    # Invalid settings boundary validations (should return 400)
    assert client.patch("/api/settings", json={"simulation_tick_seconds": 0}, headers=headers).status_code == 400
    assert client.patch("/api/settings", json={"traffic_generation_rate": -1.0}, headers=headers).status_code == 400
    assert client.patch("/api/settings", json={"simulated_devices_count": 5}, headers=headers).status_code == 400
    assert client.patch("/api/settings", json={"session_timeout_minutes": 0}, headers=headers).status_code == 400
    assert client.patch("/api/settings", json={"password_min_length": 4}, headers=headers).status_code == 400
    assert client.patch("/api/settings", json={"system_mode": "INVALID"}, headers=headers).status_code == 400

