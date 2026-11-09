import os
import time
import pytest
from playwright.sync_api import sync_playwright

SCREENSHOT_DIR = os.path.join(os.path.dirname(__file__), "screenshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5175")

def test_phase5_digital_twin_lifecycle_and_recovery():
    """
    Phase 5 Acceptance Check 7:
    Open Digital Twin page, inject a port scan, confirm the node turns suspicious / warning,
    then resolve the alert in the UI and confirm the node and health recover.
    Save before and after screenshots.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1400, "height": 900})
        page = context.new_page()

        # Step 1: Open landing page and log in
        context.clear_cookies()
        page.goto(FRONTEND_URL, wait_until="networkidle")
        page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
        page.reload(wait_until="networkidle")
        time.sleep(1)

        page.wait_for_selector('input[placeholder="Enter username"]', timeout=8000)
        page.fill('input[placeholder="Enter username"]', "admin")
        page.fill('input[placeholder="Enter password"]', "admin123")
        page.click('button[type="submit"]')

        # Dismiss onboarding tutorial if visible
        try:
            skip_btn = page.locator('button:has-text("Skip Tutorial")')
            skip_btn.wait_for(state="visible", timeout=4000)
            skip_btn.click()
            page.wait_for_selector('.ng-modal', state="detached", timeout=4000)
        except Exception:
            pass

        # Step 2: Navigate to Digital Twin page
        page.wait_for_selector('nav.ng-navlist', timeout=10000)
        page.click('nav.ng-navlist button:has-text("Digital Twin")')
        page.wait_for_selector('h1:has-text("Digital Twin")', timeout=8000)
        page.wait_for_selector('text=MODE: SIMULATION', timeout=5000)
        page.wait_for_selector('[data-testid="twin-sync-badge"]', timeout=5000)
        time.sleep(1)

        # Evidentiary Screenshot 1: Digital Twin Initial State (Synchronized)
        snap1_path = os.path.join(SCREENSHOT_DIR, "phase5_01_digital_twin_synchronized.png")
        page.screenshot(path=snap1_path, full_page=True)
        print(f"Saved initial synchronized twin screenshot: {snap1_path}")

        # Step 3: Trigger simulated Port Scan Reconnaissance from Threats page
        page.click('nav.ng-navlist button:has-text("Threats")')
        page.wait_for_selector('h1:has-text("Threats")', timeout=8000)
        time.sleep(0.8)

        sim_btn = page.locator('button:has-text("Simulate Security Event")').first
        assert sim_btn.is_visible()
        sim_btn.click()
        time.sleep(0.8)

        # Select Port Scan Reconnaissance option
        port_scan_opt = page.locator('text=2. Port Scan Reconnaissance').first
        assert port_scan_opt.is_visible()
        port_scan_opt.click()
        time.sleep(0.4)

        # Execute simulation
        page.click('.modal-content button:has-text("Execute Simulation")')
        time.sleep(1.5)

        # Step 4: Return to Digital Twin page
        page.click('nav.ng-navlist button:has-text("Digital Twin")')
        page.wait_for_selector('h1:has-text("Digital Twin")', timeout=8000)
        time.sleep(1.5)

        # Step 5: Verify PC-01 node displays text label badge '⚠️ SUSPICIOUS' and warning/critical styling
        suspicious_badge = page.locator('text=⚠️ SUSPICIOUS').first
        suspicious_badge.wait_for(state="visible", timeout=6000)
        assert suspicious_badge.is_visible(), "Suspicious text label badge not visible on map"

        # Click PC-01 node to inspect factor breakdown in drawer
        pc01_node = page.locator('[data-node-name="PC-01"]').first
        if pc01_node.is_visible():
            pc01_node.click()
        else:
            page.locator('text=PC-01').first.click()
        time.sleep(1)

        # Evidentiary Screenshot 2 (BEFORE RESOLVE): Node turned warning/critical with text label & factor list
        snap2_path = os.path.join(SCREENSHOT_DIR, "phase5_before_resolve_suspicious.png")
        page.screenshot(path=snap2_path, full_page=True)
        print(f"Saved BEFORE resolve screenshot: {snap2_path}")

        # Close the device drawer so overlay doesn't block navigation
        close_drawer_btn = page.locator('[data-testid="close-drawer"]')
        if close_drawer_btn.is_visible():
            close_drawer_btn.click()
        else:
            page.keyboard.press("Escape")
        time.sleep(0.5)

        # Step 6: Navigate to Threats page to resolve the alert in the UI
        page.click('nav.ng-navlist button:has-text("Threats")')
        page.wait_for_selector('h1:has-text("Threats")', timeout=8000)
        time.sleep(1)

        # Click the top alert row (Port Scan Reconnaissance)
        alert_row = page.locator('table tbody tr').first
        assert alert_row.is_visible(), "No alert rows found on Threats page"
        alert_row.click()
        time.sleep(1)

        # Confirm modal is open
        page.wait_for_selector('.modal-content h2:has-text("Port Scan")', timeout=5000)

        # Click the "Resolved" button in the status mutation controls
        resolved_btn = page.locator('.modal-content button:has-text("Resolved")').first
        assert resolved_btn.is_visible(), "Resolved button not found in alert modal"
        resolved_btn.click()
        time.sleep(1.5)

        # Close the modal
        close_btn = page.locator('.modal-content button.btn-ghost').first
        if close_btn.is_visible():
            close_btn.click()
        else:
            page.keyboard.press("Escape")
        time.sleep(0.8)

        # Step 7: Return to Digital Twin page to confirm recovery
        page.click('nav.ng-navlist button:has-text("Digital Twin")')
        page.wait_for_selector('h1:has-text("Digital Twin")', timeout=8000)
        time.sleep(2)

        # Verify '⚠️ SUSPICIOUS' text label badge is no longer visible
        assert page.locator('text=⚠️ SUSPICIOUS').count() == 0, "Suspicious badge should be gone after alert resolution"

        # Click PC-01 node to confirm its risk score returned to 0
        pc01_recovered_node = page.locator('[data-node-name="PC-01"]').first
        if pc01_recovered_node.is_visible():
            pc01_recovered_node.click()
            time.sleep(1)
            total_risk_label = page.locator('[data-testid="drawer-total-risk"]')
            if total_risk_label.is_visible():
                assert "0" in total_risk_label.text_content(), f"Risk should be 0, got {total_risk_label.text_content()}"

        # Evidentiary Screenshot 3 (AFTER RESOLVE): Node, risk, and health recovered
        snap3_path = os.path.join(SCREENSHOT_DIR, "phase5_after_resolve_recovered.png")
        page.screenshot(path=snap3_path, full_page=True)
        print(f"Saved AFTER resolve recovered screenshot: {snap3_path}")

        browser.close()
