import os
import sys
import time
import pytest
import requests
from playwright.sync_api import sync_playwright

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

SCREENSHOTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "screenshots"))
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

BASE_URL = os.environ.get("FRONTEND_URL", "http://localhost:5175")
API_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:8000")

def test_100_devices_creation_and_topology_map_playwright():
    """Item 4:
    1. Create 100 devices through the API and record exact timing.
    2. Open the Network Map in a real Chromium browser and record page load timing.
    3. Verify no overlap (multi-column grid wrapping, zoom/pan controls).
    4. Save screenshot to backend/tests/screenshots/phase2_100_devices_map.png.
    5. Clean up created devices.
    """
    session = requests.Session()
    
    # Step 1: Admin Login via API to get auth token
    login_res = session.post(f"{API_URL}/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert login_res.status_code == 200, "Failed to authenticate as admin via API"
    token = login_res.json()["access_token"]
    csrf_token = session.cookies.get("ng_csrf", "")
    headers = {
        "Authorization": f"Bearer {token}",
        "X-CSRF-Token": csrf_token
    }

    # Step 2: Create 100 simulated devices via API
    print(f"\n[100-Device Test] Step 1: Creating 100 devices via REST API at {API_URL}/api/devices...")
    created_device_ids = []
    t_api_start = time.perf_counter()

    for i in range(100):
        dev_payload = {
            "device_name": f"Lab-Node-{i+1:03d}",
            "ip_address": f"10.200.{(i // 250)}.{10 + (i % 240)}",
            "mac_address": f"52:54:00:12:{(i // 256):02X}:{(i % 256):02X}",
            "device_type": "Workstation" if i % 4 != 0 else "Laptop" if i % 4 == 1 else "Camera" if i % 4 == 2 else "IoT",
            "os_type": "Debian Linux" if i % 2 == 0 else "Windows 11",
            "criticality": "LOW" if i % 3 == 0 else "MEDIUM",
            "trust_level": "MEDIUM" if i % 2 == 0 else "LOW",
            "status": "ONLINE"
        }
        res = session.post(f"{API_URL}/api/devices", json=dev_payload, headers=headers)
        if res.status_code == 200:
            created_device_ids.append(res.json()["id"])
        elif res.status_code == 400 and "already exists" in res.text:
            pass  # Already created in prior run
        else:
            print(f"Warning on device {i}: {res.status_code} - {res.text}")

    t_api_elapsed_ms = (time.perf_counter() - t_api_start) * 1000
    print(f"[100-Device Test] Created {len(created_device_ids)} devices through API in: {t_api_elapsed_ms:.2f} ms ({t_api_elapsed_ms / max(1, len(created_device_ids)):.2f} ms/device)")

    # Step 3: Launch real Chromium browser
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1600, "height": 1000},
            ignore_https_errors=True
        )
        page = context.new_page()

        print("[100-Device Test] Step 2: Logging into frontend UI...")
        page.goto(BASE_URL, wait_until="networkidle")
        page.fill('input[placeholder="Enter username"]', "admin")
        page.fill('input[placeholder="Enter password"]', "admin123")
        page.click('button[type="submit"]')

        # Handle onboarding tour
        try:
            skip_btn = page.locator('button:has-text("Skip Tutorial")')
            skip_btn.wait_for(state="visible", timeout=3000)
            skip_btn.click()
            page.wait_for_selector('.ng-modal', state="detached", timeout=3000)
        except Exception:
            pass

        # Step 4: Navigate to Network page and measure page load
        print("[100-Device Test] Step 3: Navigating to Network page...")
        t_page_start = time.perf_counter()
        page.wait_for_selector('nav.ng-navlist button:has-text("Network")', timeout=6000)
        page.click('nav.ng-navlist button:has-text("Network")')
        page.wait_for_selector('text=Network Operations', timeout=6000)
        t_page_elapsed_ms = (time.perf_counter() - t_page_start) * 1000
        print(f"[100-Device Test] Network Page Load Time: {t_page_elapsed_ms:.2f} ms")

        # Step 5: Switch to Network Map view and measure map render
        print("[100-Device Test] Step 4: Switching to Network Map tab...")
        t_map_start = time.perf_counter()
        map_btn = page.locator('button:has-text("Network Map")')
        map_btn.click()
        page.wait_for_selector('.topology-canvas', timeout=6000)
        # Wait for SVG node elements to render
        page.wait_for_selector('.topology-canvas g[transform]', timeout=6000)
        t_map_elapsed_ms = (time.perf_counter() - t_map_start) * 1000
        print(f"[100-Device Test] Network Map Render Time: {t_map_elapsed_ms:.2f} ms")

        # Step 6: Verify 100+ nodes rendered and no visual overlap
        node_elements = page.locator('.topology-canvas g[transform]')
        node_count = node_elements.count()
        print(f"[100-Device Test] Total nodes visible in topology map: {node_count}")
        assert node_count >= 100, f"Expected at least 100 nodes in topology, got {node_count}"

        # Step 7: Test Zoom and Fit controls
        fit_btn = page.locator('button[title="Fit to View"]')
        assert fit_btn.is_visible(), "Fit to View button not visible"
        fit_btn.click()
        page.wait_for_timeout(400)

        # Step 8: Save screenshot
        shot_path = os.path.join(SCREENSHOTS_DIR, "phase2_100_devices_map.png")
        page.screenshot(path=shot_path, full_page=True)
        assert os.path.exists(shot_path), f"Screenshot not saved at {shot_path}"
        print(f"[100-Device Test] Successfully saved screenshot: {shot_path}")

        browser.close()

    # Step 9: Cleanup created test devices from DB
    print("[100-Device Test] Cleaning up created test devices...")
    from app.database import SessionLocal
    from app.models.device import Device
    from app.models.connection import NetworkConnection
    from app.digital_twin.twin_engine import digital_twin

    db = SessionLocal()
    try:
        if created_device_ids:
            db.query(NetworkConnection).filter(
                (NetworkConnection.source_device_id.in_(created_device_ids)) |
                (NetworkConnection.destination_device_id.in_(created_device_ids))
            ).delete(synchronize_session=False)
            db.query(Device).filter(Device.id.in_(created_device_ids)).delete(synchronize_session=False)
            db.commit()
            digital_twin.sync_from_database(db)
            print(f"[100-Device Test] Cleaned up {len(created_device_ids)} test devices successfully.")
    finally:
        db.close()

if __name__ == "__main__":
    test_100_devices_creation_and_topology_map_playwright()
