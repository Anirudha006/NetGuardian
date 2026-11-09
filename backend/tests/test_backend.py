from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, engine, SessionLocal
from app.utils.seed_data import seed_database
from app.digital_twin.twin_engine import digital_twin
from app.ml.model import ai_detector
from app.services.auth_service import hash_password, verify_password
from app.utils.time_utils import utcnow

# Initialize tables and seed data for testing
Base.metadata.create_all(bind=engine)
from sqlalchemy import text
with engine.connect() as conn:
    try:
        conn.execute(text("ALTER TABLE devices ADD COLUMN trust_level VARCHAR(20) DEFAULT 'MEDIUM'"))
        conn.commit()
    except Exception:
        pass
_db = SessionLocal()
seed_database(_db)
digital_twin.sync_from_database(_db)
_db.close()

client = TestClient(app)

def test_password_hashing():
    pwd = "SecretPassword123!"
    hashed = hash_password(pwd)
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword", hashed) is False

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["project"] == "NetGuardian"
    assert data["status"] == "ONLINE"

def test_login_admin():
    response = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["role"] == "ADMIN"

def test_login_wrong_password_friendly_error():
    response = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert response.status_code == 401
    data = response.json()
    assert "Incorrect username or password" in data["detail"]

def test_login_rate_limiting_6th_attempt():
    test_user = "rate_limit_test_user"
    # Create attempts 1 to 5 with wrong password -> should return 401
    for _ in range(5):
        res = client.post("/api/auth/login", json={"username": test_user, "password": "badpassword"})
        assert res.status_code == 401
    
    # 6th attempt -> should return 429 Too Many Requests
    res6 = client.post("/api/auth/login", json={"username": test_user, "password": "badpassword"})
    assert res6.status_code == 429
    assert "Too many failed login attempts" in res6.json()["detail"]

def test_analyst_cannot_open_admin_endpoints_403():
    # Login as analyst
    login_res = client.post("/api/auth/login", json={"username": "analyst", "password": "analyst123"})
    assert login_res.status_code == 200
    analyst_token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # Attempt to access admin-only endpoint: GET /api/auth/users
    admin_users_res = client.get("/api/auth/users", headers=headers)
    assert admin_users_res.status_code == 403
    assert "Administrative privileges required" in admin_users_res.json()["detail"]

    # Attempt to modify settings: PATCH /api/settings
    settings_patch_res = client.patch("/api/settings", json={"port_scan_threshold": 30}, headers=headers)
    assert settings_patch_res.status_code == 403

def test_passwords_not_plain_text_in_db():
    from app.models.user import User
    db = SessionLocal()
    users = db.query(User).all()
    assert len(users) >= 2
    for u in users:
        # Check that hash contains salt delimiter $ and is not raw password
        assert "$" in u.password_hash
        assert u.password_hash != "admin123"
        assert u.password_hash != "analyst123"
        assert len(u.password_hash) > 40
    db.close()

def test_user_logout():
    login_res = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    token = login_res.json()["access_token"]
    logout_res = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == 200
    assert "Successfully logged out" in logout_res.json()["message"]

def test_dashboard_summary():
    response = client.get("/api/dashboard")
    assert response.status_code == 200
    data = response.json()
    assert "kpis" in data
    assert data["kpis"]["total_devices"] >= 10
    assert "network_health" in data
    assert data["network_health"]["health_score"] >= 0

def test_devices_list():
    response = client.get("/api/devices")
    assert response.status_code == 200
    devices = response.json()
    assert len(devices) >= 10
    names = [d["device_name"] for d in devices]
    assert any(n in names for n in ["Router", "Gateway-Router"])
    assert any(n in names for n in ["Database", "Crown-Jewel-DB"])

def test_device_risk_breakdown():
    # Fetch Database ID
    devs = client.get("/api/devices").json()
    db_dev = next(d for d in devs if d["device_name"] in ["Database", "Crown-Jewel-DB"])
    response = client.get(f"/api/devices/{db_dev['id']}/risk-breakdown")
    assert response.status_code == 200
    data = response.json()
    # Pre-Phase 6 Rule 1: With NO events, baseline risk score must be 0.0 (no baseline criticality risk)
    assert data["risk_score"] == 0.0
    assert "formula" in data
    assert data["trust_score"] >= 80.0

def test_ai_detector():
    info = ai_detector.get_model_info()
    assert info["status"] == "READY"
    assert info["features_count"] == 8

    # Test normal traffic prediction
    normal_traffic = {
        "packet_count": 5,
        "bytes": 2400,
        "connection_count": 1,
        "duration": 0.5,
        "unique_dst_ports": 1,
        "unique_dst_ips": 1,
        "failed_connections": 0,
        "traffic_rate": 4800.0
    }
    result_normal = ai_detector.predict(normal_traffic)
    assert "is_anomalous" in result_normal
    assert "anomaly_score" in result_normal
    assert "explanation" in result_normal

    # Test extreme anomaly traffic prediction
    extreme_traffic = {
        "packet_count": 8000,
        "bytes": 15000000,
        "connection_count": 80,
        "duration": 1.0,
        "unique_dst_ports": 45,
        "unique_dst_ips": 20,
        "failed_connections": 35,
        "traffic_rate": 15000000.0
    }
    result_extreme = ai_detector.predict(extreme_traffic)
    assert result_extreme["is_anomalous"] is True
    assert result_extreme["anomaly_score"] >= 0.60
    assert len(result_extreme["explanation"]["reasons"]) > 0

def test_digital_twin_topology():
    response = client.get("/api/digital-twin/topology")
    assert response.status_code == 200
    topo = response.json()
    assert topo["total_nodes"] >= 10
    assert topo["total_edges"] >= 9
    assert topo["state"] == "SYNCHRONIZED"

def get_auth_headers():
    res = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert res.status_code == 200
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_what_if_compromise_and_isolation():
    headers = get_auth_headers()
    devs = client.get("/api/devices").json()
    pc_dev = next(d for d in devs if d["device_name"] in ["PC-01", "Lab-PC-01"])

    # Run What-If simulation
    sim_res = client.post("/api/simulation/what-if", json={
        "target_device_id": pc_dev["id"],
        "scenario": "WHAT_IF_COMPROMISE"
    }, headers=headers)
    assert sim_res.status_code == 200
    sim_data = sim_res.json()
    assert sim_data["reachable_nodes_count"] > 0
    assert len(sim_data["attack_paths"]) > 0

    # Verify that Server or Database is reached
    reached_nodes = sim_data["reachable_nodes"]
    assert any(n in reached_nodes for n in ["Server", "App-Server", "Database", "Crown-Jewel-DB"])

    # Execute simulated isolation
    iso_res = client.post("/api/simulation/isolate", json={
        "target_device_id": pc_dev["id"],
        "reason": "Test simulated isolation"
    }, headers=headers)
    assert iso_res.status_code == 200
    iso_data = iso_res.json()
    assert iso_data["is_isolated"] is True
    assert iso_data["reachability_after"] == 0
    assert iso_data["edges_severed"] > 0

    # Restore node
    restore_res = client.post(f"/api/simulation/restore/{pc_dev['id']}", headers=headers)
    assert restore_res.status_code == 200
    assert restore_res.json()["is_isolated"] is False

def test_demo_step_and_reset():
    headers = get_auth_headers()
    # Step 1
    s1 = client.post("/api/simulation/demo/step", json={"step_number": 1}, headers=headers)
    assert s1.status_code == 200
    assert s1.json()["step_number"] == 1

    # Step 3 (Rogue device introduced)
    s3 = client.post("/api/simulation/demo/step", json={"step_number": 3}, headers=headers)
    assert s3.status_code == 200
    assert s3.json()["affected_device"] == "Rogue-Laptop-99"

    # Reset demo
    reset_res = client.post("/api/simulation/demo/reset", headers=headers)
    assert reset_res.status_code == 200
    assert reset_res.json()["current_step"] == 0

def test_login_rate_limit_casing_and_spaces_bypass_prevented():
    """Requirement 7: Verify login rate-limiting cannot be bypassed by casing or whitespace tricks."""
    variations = [
        "bypass_test_target",
        "  bypass_test_target",
        "BYPASS_TEST_TARGET  ",
        "  ByPass_Test_Target  ",
        "Bypass_Test_Target"
    ]
    # First 5 attempts with different casing/whitespace all count against the same normalized bucket
    for idx, var in enumerate(variations):
        res = client.post("/api/auth/login", json={"username": var, "password": "wrongpassword123"})
        assert res.status_code == 401, f"Attempt {idx+1} for '{var}' should fail with 401"

    # 6th attempt with another casing variant must be blocked by rate limiter (429)
    res_blocked = client.post("/api/auth/login", json={"username": "  BYPASS_TEST_TARGET", "password": "wrongpassword123"})
    assert res_blocked.status_code == 429
    assert "Too many failed login attempts" in res_blocked.json()["detail"]

def test_pbkdf2_iterations_and_rehash_upgrade():
    """Requirement 2: Verify PBKDF2 iterations are >= 600,000 and legacy hashes rehash on login."""
    from app.services.auth_service import PBKDF2_ITERATIONS, hash_password, needs_rehash
    import hashlib
    assert PBKDF2_ITERATIONS >= 600000

    new_hash = hash_password("TestSecretPass123!")
    assert f"pbkdf2_sha256${PBKDF2_ITERATIONS}$" in new_hash
    assert needs_rehash(new_hash) is False

    # Simulate legacy 100k hash format: salt$hex
    salt = "legacysalt123456"
    legacy_key = hashlib.pbkdf2_hmac("sha256", "LegacyPassword123!".encode("utf-8"), salt.encode("utf-8"), 100000)
    legacy_hash = f"{salt}${legacy_key.hex()}"
    assert needs_rehash(legacy_hash) is True

    # Register or seed a user with this legacy hash in DB
    from app.models.user import User
    from datetime import datetime
    db = SessionLocal()
    legacy_user = db.query(User).filter(User.username == "legacy_test_user").first()
    if not legacy_user:
        legacy_user = User(
            username="legacy_test_user",
            email="legacy@netguardian.local",
            password_hash=legacy_hash,
            role="ANALYST",
            created_at=utcnow()
        )
        db.add(legacy_user)
        db.commit()
    else:
        legacy_user.password_hash = legacy_hash
        db.commit()
    db.close()

    # Log in as legacy user -> backend should verify password and dynamically rehash in DB
    login_res = client.post("/api/auth/login", json={"username": "legacy_test_user", "password": "LegacyPassword123!"})
    assert login_res.status_code == 200

    # Query DB to confirm hash has been upgraded
    db = SessionLocal()
    updated_user = db.query(User).filter(User.username == "legacy_test_user").first()
    assert updated_user.password_hash.startswith("pbkdf2_sha256$600000$")
    assert needs_rehash(updated_user.password_hash) is False
    db.close()

def test_session_timeout_configurable_via_settings():
    """Requirement 4: Verify session timeout is configurable from Settings page (admin only)."""
    # Login as admin
    login_res = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Set session timeout to 180 minutes
    update_res = client.patch("/api/settings", json={"session_timeout_minutes": 180}, headers=headers)
    assert update_res.status_code == 200

    # Verify retrieval
    get_res = client.get("/api/settings")
    assert get_res.status_code == 200
    assert str(get_res.json()["settings"]["session_timeout_minutes"]) == "180"

    # Reset back to default
    client.patch("/api/settings", json={"session_timeout_minutes": 1440}, headers=headers)

def test_production_mode_startup_refusal():
    """Requirement 3: Verify backend refuses to start in production if demo passwords or default keys are used."""
    import pytest
    from app.config import settings

    orig_env = settings.ENVIRONMENT
    orig_key = settings.SECRET_KEY
    try:
        settings.ENVIRONMENT = "production"
        # Test default secret key rejection
        with pytest.raises(RuntimeError) as exc_info:
            from app.main import lifespan
            import asyncio
            async def run_lifespan():
                async with lifespan(app):
                    pass
            asyncio.run(run_lifespan())
        assert "Production mode startup refused" in str(exc_info.value)
    finally:
        settings.ENVIRONMENT = orig_env
        settings.SECRET_KEY = orig_key

def test_cookie_auth_and_csrf_validation():
    """Requirement 1: Verify HttpOnly session cookie auth and strict CSRF protection."""
    # Use an isolated test client
    cookie_client = TestClient(app)
    login_res = cookie_client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert login_res.status_code == 200
    assert "ng_session" in cookie_client.cookies
    assert "ng_csrf" in cookie_client.cookies
    csrf_token = cookie_client.cookies["ng_csrf"]

    # 1. State-changing request without CSRF header should fail with 403 Forbidden
    res_no_csrf = cookie_client.patch("/api/settings", json={"session_timeout_minutes": 180})
    assert res_no_csrf.status_code == 403
    assert "CSRF token validation failed" in res_no_csrf.json()["detail"]

    # 2. State-changing request with mismatched CSRF header should fail with 403 Forbidden
    res_bad_csrf = cookie_client.patch(
        "/api/settings",
        json={"session_timeout_minutes": 180},
        headers={"X-CSRF-Token": "invalid-token-123"}
    )
    assert res_bad_csrf.status_code == 403

    # 3. State-changing request with valid CSRF header should succeed with 200 OK
    res_ok = cookie_client.patch(
        "/api/settings",
        json={"session_timeout_minutes": 180},
        headers={"X-CSRF-Token": csrf_token}
    )
    assert res_ok.status_code == 200

    # 4. Logout should clear cookies
    logout_res = cookie_client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_token})
    assert logout_res.status_code == 200
    # Cookie should be deleted or expired
    assert cookie_client.cookies.get("ng_session") is None


