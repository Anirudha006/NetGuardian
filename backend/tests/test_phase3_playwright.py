import os
import time
import pytest
from playwright.sync_api import sync_playwright

SCREENSHOT_DIR = os.path.join(os.path.dirname(__file__), "screenshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5175")

SCENARIOS = [
    {
        "id": "UNKNOWN_DEVICE",
        "title_option": "1. Unknown Device Joins",
        "alert_title": "Unknown Device Detected",
        "expected_severity": "MEDIUM",
        "screenshot_name": "phase3_sim_01_unknown_device.png"
    },
    {
        "id": "PORT_SCAN",
        "title_option": "2. Port Scan Reconnaissance",
        "alert_title": "Port Scanning Activity Detected",
        "expected_severity": "HIGH",
        "screenshot_name": "phase3_sim_02_port_scan.png"
    },
    {
        "id": "TRAFFIC_ANOMALY",
        "title_option": "3. Traffic Volume Anomaly Spike",
        "alert_title": "Traffic Volume Anomaly Spike",
        "expected_severity": "MEDIUM",
        "screenshot_name": "phase3_sim_03_traffic_anomaly.png"
    },
    {
        "id": "FAILED_AUTH",
        "title_option": "4. Repeated Failed Authentication",
        "alert_title": "Possible Brute-Force Pattern",
        "expected_severity": "HIGH",
        "screenshot_name": "phase3_sim_04_failed_auth.png"
    },
    {
        "id": "SUSPICIOUS_OUTBOUND",
        "title_option": "5. Suspicious Outbound Connection",
        "alert_title": "Suspicious Outbound Connection",
        "expected_severity": "HIGH",
        "screenshot_name": "phase3_sim_05_suspicious_outbound.png"
    },
    {
        "id": "COMPROMISED_HOST",
        "title_option": "6. Compromised Device Scenario",
        "alert_title": "Host Compromise Scenario Simulated",
        "expected_severity": "CRITICAL",
        "screenshot_name": "phase3_sim_06_compromised_device.png"
    }
]

def test_all_six_simulated_events_and_unknown_device():
    """
    Tasks 3 & 5:
    1. Log in via UI as admin.
    2. Dismiss onboarding / skip tutorial.
    3. Navigate to Threats page.
    4. Trigger ALL 6 simulated events from the UI modal.
    5. Verify each appears on the Threats page with the correct severity badge.
    6. Save an evidentiary screenshot for each.
    7. Navigate to Network inventory and verify Unknown-Host-99 appears as unregistered.
    8. Navigate to Digital Twin topology and verify Unknown-Host-99 is connected.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1400, "height": 900})
        page = context.new_page()

        # 1. Open Landing / Login Page with clean cookie session
        context.clear_cookies()
        page.goto(FRONTEND_URL, wait_until="networkidle")
        page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
        page.reload(wait_until="networkidle")
        time.sleep(1)

        # Step 2: Login as admin
        page.wait_for_selector('input[placeholder="Enter username"]', timeout=8000)
        page.fill('input[placeholder="Enter username"]', "admin")
        page.fill('input[placeholder="Enter password"]', "admin123")
        page.click('button[type="submit"]')

        # Handle onboarding modal if it appears
        try:
            skip_btn = page.locator('button:has-text("Skip Tutorial")')
            skip_btn.wait_for(state="visible", timeout=4000)
            skip_btn.click()
            page.wait_for_selector('.ng-modal', state="detached", timeout=4000)
        except Exception:
            pass

        # Step 3: Wait for navbar and navigate to Threats Page
        page.wait_for_selector('nav.ng-navlist', timeout=10000)
        page.click('nav.ng-navlist button:has-text("Threats")')
        page.wait_for_selector('h1:has-text("Threats")', timeout=8000)
        time.sleep(1)

        # 3. Trigger ALL 6 Simulated Events from UI Modal
        for idx, sc in enumerate(SCENARIOS, 1):
            # Open simulation modal
            sim_btn = page.locator('button:has-text("Simulate Security Event")').first
            assert sim_btn.is_visible()
            sim_btn.click()
            time.sleep(0.8)

            modal = page.locator('.modal-content')
            assert modal.is_visible()

            # Select scenario card
            option = page.locator(f'text={sc["title_option"]}').first
            assert option.is_visible(), f"Option '{sc['title_option']}' not visible in modal"
            option.click()
            time.sleep(0.4)

            # Click Execute Simulation
            exec_btn = page.locator('.modal-content button:has-text("Execute Simulation")')
            assert exec_btn.is_visible()
            exec_btn.click()
            time.sleep(1.8)

            # Verify alert row is in table with correct title and severity badge
            alert_row = page.locator(f'tr:has-text("{sc["alert_title"]}")').first
            assert alert_row.is_visible(), f"Alert row with title '{sc['alert_title']}' not found in table"

            sev_badge = alert_row.locator(f'.badge:has-text("{sc["expected_severity"]}")').first
            assert sev_badge.is_visible(), f"Expected severity badge '{sc['expected_severity']}' not found for '{sc['alert_title']}'"

            # Save evidentiary screenshot
            sc_path = os.path.join(SCREENSHOT_DIR, sc["screenshot_name"])
            page.screenshot(path=sc_path)
            assert os.path.exists(sc_path)

        # 4. Verify Alert Details View (for the last event or any event)
        alert_row = page.locator('tr:has-text("Host Compromise")').first
        details_btn = alert_row.locator('button:has-text("View Details")').first
        if details_btn.is_visible():
            details_btn.click()
        else:
            alert_row.click()
        time.sleep(1)

        details_modal = page.locator('.modal-content')
        assert details_modal.is_visible()
        # Verify defensive recommendation
        assert page.locator('text=Recommended Defensive Action').is_visible()
        screenshot_details = os.path.join(SCREENSHOT_DIR, "phase3_alert_details_modal.png")
        page.screenshot(path=screenshot_details)

        # Close details modal
        close_btn = page.locator('.modal-content button.btn-ghost').first
        if close_btn.is_visible():
            close_btn.click()
        else:
            page.locator('.modal-backdrop').click(position={"x": 5, "y": 5})
        time.sleep(1)

        # 5. Task 5: Check Network Inventory for Unknown-Host-99
        page.wait_for_selector('nav.ng-navlist button:has-text("Network")', timeout=8000)
        page.click('nav.ng-navlist button:has-text("Network")')
        time.sleep(1.5)

        # Confirm Unknown-Host-99 is in table and marked as UNTRUSTED
        unknown_device_row = page.locator('tr:has-text("Unknown-Host-99")').first
        assert unknown_device_row.is_visible(), "Unknown-Host-99 must appear in Network Inventory"
        assert unknown_device_row.locator('text=192.168.1.99').is_visible()
        assert unknown_device_row.locator('text=UNTRUSTED').is_visible()

        sc_inventory = os.path.join(SCREENSHOT_DIR, "phase3_unknown_device_inventory.png")
        page.screenshot(path=sc_inventory)
        assert os.path.exists(sc_inventory)

        # 6. Task 5: Check Digital Twin Topology Graph for Unknown-Host-99
        page.wait_for_selector('nav.ng-navlist button:has-text("Digital Twin")', timeout=8000)
        page.click('nav.ng-navlist button:has-text("Digital Twin")')
        time.sleep(2)

        # Verify Unknown-Host-99 is listed in the nodes or on canvas
        assert page.locator('text=Unknown-Host-99').first.is_visible() or page.locator('text=192.168.1.99').first.is_visible(), "Unknown-Host-99 must appear in Digital Twin"

        sc_topology = os.path.join(SCREENSHOT_DIR, "phase3_unknown_device_topology.png")
        page.screenshot(path=sc_topology)
        assert os.path.exists(sc_topology)

        browser.close()
