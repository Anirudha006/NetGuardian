import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.utils.seed_data import seed_database
from app.config import settings

@pytest.fixture(autouse=True)
def setup_db():
    db = SessionLocal()
    seed_database(db, force_reset=True)
    db.close()
    yield

# All state-changing endpoints that require authentication
STATE_CHANGING_ENDPOINTS = [
    ("POST", "/api/auth/logout", {}),
    ("POST", "/api/auth/users", {"username": "newanalyst", "email": "a@net.local", "password": "Password123!", "role": "ANALYST"}),
    ("POST", "/api/devices", {"device_name": "AuditPC", "ip_address": "192.168.1.188", "mac_address": "00:11:22:33:44:55", "device_type": "Workstation", "criticality": "LOW", "trust_level": "LOW", "status": "ONLINE"}),
    ("PATCH", "/api/devices/1", {"status": "OFFLINE"}),
    ("DELETE", "/api/devices/1", {}),
    ("POST", "/api/traffic/pulse", {}),
    ("POST", "/api/traffic/baseline/learn", {}),
    ("PATCH", "/api/alerts/1", {"status": "RESOLVED"}),
    ("POST", "/api/alerts/read-state", {"alert_id": 1}),
    ("POST", "/api/alerts/read-all", {}),
    ("POST", "/api/digital-twin/sync", {}),
    ("POST", "/api/simulation/what-if", {"target_device_id": 1, "scenario": "COMPROMISED_HOST"}),
    ("POST", "/api/simulation/isolate", {"target_device_id": 1, "reason": "Audit"}),
    ("POST", "/api/simulation/restore/1", {}),
    ("POST", "/api/simulation/trigger-event", {"event_type": "PORT_SCAN", "source_ip": "192.168.1.10"}),
    ("POST", "/api/simulation/demo/step", {"step_number": 1}),
    ("POST", "/api/simulation/demo/reset", {}),
    ("PATCH", "/api/settings", {"traffic_anomaly_threshold": 3.5}),
]

ADMIN_ONLY_ENDPOINTS = [
    ("POST", "/api/auth/users", {"username": "audituser", "email": "u@test.local", "password": "Password123!", "role": "ANALYST"}),
    ("POST", "/api/devices", {"device_name": "AdminOnlyPC", "ip_address": "192.168.1.189", "mac_address": "AA:BB:CC:DD:EE:FF", "device_type": "Workstation", "criticality": "LOW", "trust_level": "LOW", "status": "ONLINE"}),
    ("DELETE", "/api/devices/1", {}),
    ("PATCH", "/api/settings", {"traffic_anomaly_threshold": 4.0}),
]

def test_unauthenticated_state_changing_endpoints_return_401():
    """Verify that every state-changing endpoint returns 401 Unauthorized when called without login."""
    client = TestClient(app)
    for method, path, payload in STATE_CHANGING_ENDPOINTS:
        if method == "POST":
            resp = client.post(path, json=payload)
        elif method == "PATCH":
            resp = client.patch(path, json=payload)
        elif method == "DELETE":
            resp = client.delete(path)
        else:
            continue
        assert resp.status_code == 401, f"Expected 401 on {method} {path}, got {resp.status_code}: {resp.text}"

def test_analyst_forbidden_on_admin_only_endpoints_returns_403():
    """Verify that an analyst user gets 403 Forbidden on all admin-only endpoints."""
    client = TestClient(app)
    # Login as analyst via Bearer token
    login_resp = client.post("/api/auth/login", json={"username": "analyst", "password": settings.DEMO_ANALYST_PASSWORD})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    for method, path, payload in ADMIN_ONLY_ENDPOINTS:
        if method == "POST":
            resp = client.post(path, json=payload, headers=headers)
        elif method == "PATCH":
            resp = client.patch(path, json=payload, headers=headers)
        elif method == "DELETE":
            resp = client.delete(path, headers=headers)
        else:
            continue
        assert resp.status_code == 403, f"Expected 403 for analyst on {method} {path}, got {resp.status_code}: {resp.text}"

def test_csrf_protection_on_cookie_authenticated_requests():
    """Verify that state-changing cookie requests lacking valid X-CSRF-Token return 403 Forbidden."""
    client = TestClient(app)
    # Login sets cookies in client.cookies automatically
    login_resp = client.post("/api/auth/login", json={"username": "admin", "password": settings.DEMO_ADMIN_PASSWORD})
    assert login_resp.status_code == 200
    csrf_token = login_resp.json()["csrf_token"]
    assert "ng_session" in client.cookies
    assert "ng_csrf" in client.cookies

    # 1. Calling state-changing endpoint without X-CSRF-Token header -> 403
    resp_no_csrf = client.patch("/api/settings", json={"traffic_anomaly_threshold": 4.5})
    assert resp_no_csrf.status_code == 403
    assert "CSRF" in resp_no_csrf.text or "csrf" in resp_no_csrf.text

    # 2. Calling with mismatched X-CSRF-Token header -> 403
    resp_bad_csrf = client.patch("/api/settings", json={"traffic_anomaly_threshold": 4.5}, headers={"X-CSRF-Token": "invalid_csrf_token"})
    assert resp_bad_csrf.status_code == 403

    # 3. Calling with matching X-CSRF-Token header -> 200 OK
    resp_good = client.patch("/api/settings", json={"traffic_anomaly_threshold": 4.5}, headers={"X-CSRF-Token": csrf_token})
    assert resp_good.status_code == 200

def test_trigger_event_requires_json_body_rejects_query_parameters():
    """
    Task 2: POST /api/simulation/trigger-event must accept a JSON body only, not query parameters.
    Passing query parameters with no JSON body must return 422 Unprocessable Entity.
    """
    client = TestClient(app)
    login_resp = client.post("/api/auth/login", json={"username": "admin", "password": settings.DEMO_ADMIN_PASSWORD})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Calling with query parameters only (no JSON body) must return 422
    query_resp = client.post("/api/simulation/trigger-event?event_type=PORT_SCAN&source_ip=192.168.1.10", headers=headers)
    assert query_resp.status_code == 422, f"Expected 422 for query params without JSON body, got {query_resp.status_code}"

    # Calling with valid JSON body must succeed with 200 OK
    json_resp = client.post(
        "/api/simulation/trigger-event",
        json={"event_type": "PORT_SCAN", "source_ip": "192.168.1.10"},
        headers=headers
    )
    assert json_resp.status_code == 200
    data = json_resp.json()
    assert data["status"] == "SUCCESS"
    assert data["severity"] == "HIGH"
