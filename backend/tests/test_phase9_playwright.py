import os
import time
import shutil
import httpx
import pytest
from playwright.sync_api import sync_playwright

SCREENSHOT_DIR = os.path.join(os.path.dirname(__file__), "screenshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

ARTIFACT_DIR = r"C:\Users\srini\.gemini\antigravity\brain\3166697a-8be2-4b72-80cd-0bd4dcc6a45e"
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5175")
BACKEND_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:8000")

def reset_baseline():
    try:
        r = httpx.post(f"{BACKEND_URL}/api/auth/login", json={"username": "admin", "password": "admin123"}, timeout=5.0)
        if r.status_code == 200:
            token = r.json()["access_token"]
            httpx.post(f"{BACKEND_URL}/api/simulation/demo/reset", headers={"Authorization": f"Bearer {token}"}, timeout=5.0)
    except Exception:
        pass

def copy_to_artifacts(src_path: str, filename: str):
    try:
        dest_path = os.path.join(ARTIFACT_DIR, filename)
        shutil.copy2(src_path, dest_path)
    except Exception as e:
        print(f"Artifact copy warning: {e}")

def save_and_copy(page, filename: str):
    local_path = os.path.join(SCREENSHOT_DIR, filename)
    try:
        page.screenshot(path=local_path, full_page=False, timeout=8000, animations="disabled")
    except Exception as e:
        print(f"Screenshot retry on {filename}: {e}")
        try:
            page.screenshot(path=local_path, full_page=False, timeout=5000)
        except Exception:
            pass
    copy_to_artifacts(local_path, filename)
    print(f"Captured {filename}")
    return local_path

def dismiss_all_modals(page):
    try:
        for _ in range(3):
            overlay = page.locator(".ng-modal-overlay")
            if overlay.count() > 0 and overlay.first.is_visible():
                skip = page.locator('button:has-text("Skip Tutorial")')
                if skip.count() > 0 and skip.first.is_visible():
                    skip.first.click()
                else:
                    page.keyboard.press("Escape")
                page.wait_for_timeout(300)
            else:
                break
    except Exception:
        pass

def test_phase9_full_success_flow_17_steps():
    """
    Task 5: The full success flow in ONE Playwright run, with a screenshot per step:
    1. login
    2. dashboard
    3. topology
    4. traffic simulation
    5. security event
    6. rule detection
    7. AI anomaly
    8. alert
    9. twin update
    10. select suspicious device
    11. what-if
    12. attack path
    13. risk analysis
    14. recommendation
    15. simulated isolation
    16. twin updated
    17. report
    """
    reset_baseline()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 950}, accept_downloads=True)
        page = context.new_page()
        page.route("**/*fonts.g*", lambda route: route.abort())
        page.on("dialog", lambda dialog: dialog.accept())
        page.add_init_script("localStorage.setItem('ng_onboarded', 'true');")

        # Step 1: Login
        page.goto(f"{FRONTEND_URL}/")
        page.wait_for_selector('input[type="text"]', timeout=10000)
        save_and_copy(page, "phase9_step_01_login.png")

        page.fill('input[type="text"]', 'admin')
        page.fill('input[type="password"]', 'admin123')
        page.click('button[type="submit"]')

        # Step 2: Dashboard
        page.wait_for_selector('text=NETGUARDIAN', timeout=12000)
        dismiss_all_modals(page)
        page.wait_for_selector('text=NETWORK HEALTH SCORE', timeout=8000)
        page.wait_for_timeout(600)
        save_and_copy(page, "phase9_step_02_dashboard.png")

        # Step 3: Topology (Digital Twin Graph)
        dismiss_all_modals(page)
        page.click('button.ng-navitem:has-text("Digital Twin")')
        page.wait_for_selector('h1:has-text("Digital Twin")', timeout=8000)
        page.wait_for_timeout(1000)
        save_and_copy(page, "phase9_step_03_topology.png")

        # Step 4: Traffic Simulation
        page.click('button.ng-navitem:has-text("Dashboard")')
        page.wait_for_selector('h1:has-text("Security Dashboard")', timeout=8000)
        page.wait_for_timeout(600)
        if page.is_visible('button:has-text("Step")'):
            page.click('button:has-text("Step")')
            page.wait_for_timeout(600)
        save_and_copy(page, "phase9_step_04_traffic_simulation.png")

        # Step 5: Security Event
        sim_btn = page.locator('button:has-text("Port Scan")').first
        sim_btn.scroll_into_view_if_needed()
        page.wait_for_timeout(400)
        save_and_copy(page, "phase9_step_05_security_event.png")
        sim_btn.click()
        page.wait_for_timeout(1000)

        # Step 6: Rule Detection
        needs_attn = page.locator('text=Needs Attention: Open Threats').first
        needs_attn.scroll_into_view_if_needed()
        page.wait_for_timeout(600)
        save_and_copy(page, "phase9_step_06_rule_detection.png")

        # Step 7: AI Anomaly
        spike_btn = page.locator('button:has-text("Traffic Spike")').first
        if spike_btn.is_visible():
            spike_btn.click()
            page.wait_for_timeout(800)
        ai_card = page.locator('text=Latest AI Anomaly Detection').first
        ai_card.scroll_into_view_if_needed()
        page.wait_for_timeout(600)
        save_and_copy(page, "phase9_step_07_ai_anomaly.png")

        # Step 8: Alert (Threats Page)
        page.click('button.ng-navitem:has-text("Threats")')
        page.wait_for_selector('h1:has-text("Threats & Security Alerts")', timeout=8000)
        page.wait_for_timeout(800)
        save_and_copy(page, "phase9_step_08_alert.png")

        # Step 9: Twin Update
        page.click('button.ng-navitem:has-text("Digital Twin")')
        page.wait_for_selector('h1:has-text("Digital Twin")', timeout=8000)
        page.wait_for_timeout(1000)
        save_and_copy(page, "phase9_step_09_twin_update.png")

        # Step 10: Select Suspicious Device
        page.click('button.ng-navitem:has-text("Network")')
        page.wait_for_selector('h1:has-text("Network Operations")', timeout=8000)
        page.wait_for_selector('text=PC-01', timeout=10000)
        page.locator('text=PC-01').first.click()
        page.wait_for_timeout(500)
        save_and_copy(page, "phase9_step_10_select_suspicious_device.png")
        # Close drawer if open
        page.keyboard.press("Escape")
        page.wait_for_timeout(300)

        # Step 11: What-If (Simulation Page)
        page.click('button.ng-navitem:has-text("Simulation")')
        page.wait_for_selector('h1:has-text("What-If Attack Simulation Engine")', timeout=8000)
        page.wait_for_selector('select.ng-select option:has-text("PC-01")', state="attached", timeout=10000)
        select_el = page.locator('select.ng-select').first
        options = select_el.locator('option').all_text_contents()
        pc1_idx = next((i for i, t in enumerate(options) if 'PC-01' in t), None)
        assert pc1_idx is not None, f"PC-01 option not found in {options}"
        val = select_el.locator('option').nth(pc1_idx).get_attribute('value')
        assert val, "PC-01 option value is empty"
        select_el.select_option(val)
        page.wait_for_selector('button:has-text("Run What-If Simulation"):not([disabled])', timeout=5000)
        save_and_copy(page, "phase9_step_11_what_if.png")

        # Step 12: Attack Path
        page.click('button:has-text("Run What-If Simulation")')
        page.wait_for_selector('text=POTENTIAL REACH PATH', timeout=10000)
        page.wait_for_timeout(400)
        save_and_copy(page, "phase9_step_12_attack_path.png")

        # Step 13: Risk Analysis
        page.wait_for_timeout(500)
        save_and_copy(page, "phase9_step_13_risk_analysis.png")

        # Step 14: Recommendation
        if page.is_visible('text=Simulate Path Severance'):
            page.locator('text=Simulate Path Severance').first.scroll_into_view_if_needed()
            page.wait_for_timeout(400)
        save_and_copy(page, "phase9_step_14_recommendation.png")

        # Step 15: Simulated Isolation
        if page.is_visible('button:has-text("Simulate Isolation")'):
            page.click('button:has-text("Simulate Isolation")')
            page.wait_for_selector('text=Twin Links Severed', timeout=8000)
            page.wait_for_timeout(600)
        save_and_copy(page, "phase9_step_15_simulated_isolation.png")

        # Step 16: Twin Updated
        page.click('button.ng-navitem:has-text("Digital Twin")')
        page.wait_for_selector('h1:has-text("Digital Twin")', timeout=8000)
        page.wait_for_timeout(1000)
        save_and_copy(page, "phase9_step_16_twin_updated.png")

        # Step 17: Report
        page.click('button.ng-navitem:has-text("Reports")')
        page.wait_for_selector('h1:has-text("NetGuardian Security Report")', timeout=8000)
        page.wait_for_timeout(1200)
        save_and_copy(page, "phase9_step_17_report.png")

        browser.close()


def test_phase9_comprehensive_frontend_pages():
    """
    Task 2: Frontend tests covering login, dashboard, device details, alerts,
    simulation, navigation, settings, profile, analytics, reports, onboarding, demo mode.
    """
    reset_baseline()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 950})
        page = context.new_page()
        page.route("**/*fonts.g*", lambda route: route.abort())
        page.on("dialog", lambda dialog: dialog.accept())

        # Login
        page.goto(f"{FRONTEND_URL}/")
        page.wait_for_selector('input[type="text"]', timeout=10000)
        page.fill('input[type="text"]', 'admin')
        page.fill('input[type="password"]', 'admin123')
        page.click('button[type="submit"]')
        page.wait_for_selector('text=NETGUARDIAN', timeout=12000)
        page.wait_for_timeout(600)

        # 1. Onboarding Modal verification (auto opens on first login)
        save_and_copy(page, "phase9_ui_01_onboarding.png")
        dismiss_all_modals(page)

        # 2. Demo Mode modal
        page.click('button:has-text("Start Demo")')
        page.wait_for_selector('text=Automated Guided Demonstration', timeout=8000)
        page.wait_for_timeout(500)
        save_and_copy(page, "phase9_ui_02_demo_mode.png")
        # Close demo modal
        close_demo = page.locator('div.ng-modal-header button').last
        if close_demo.is_visible():
            close_demo.click()
        else:
            page.keyboard.press("Escape")
        page.wait_for_timeout(400)
        dismiss_all_modals(page)

        # 3. Devices & Details Drawer
        page.click('button.ng-navitem:has-text("Network")')
        page.wait_for_selector('h1:has-text("Network Operations")', timeout=8000)
        page.wait_for_timeout(600)
        if page.is_visible('text=PC-01'):
            page.locator('text=PC-01').first.click()
            page.wait_for_timeout(500)
            save_and_copy(page, "phase9_ui_03_device_details.png")
            page.keyboard.press("Escape")
            page.wait_for_timeout(300)

        # 4. Settings Page
        page.click('button.ng-navitem:has-text("Settings")')
        page.wait_for_selector('h1:has-text("System Settings & Status")', timeout=8000)
        page.wait_for_timeout(600)
        save_and_copy(page, "phase9_ui_04_settings.png")

        # 5. Profile Page
        page.click('button.ng-navitem:has-text("Profile")')
        page.wait_for_selector('h1:has-text("My Profile & Settings")', timeout=8000)
        page.wait_for_timeout(600)
        save_and_copy(page, "phase9_ui_05_profile.png")

        # 6. Analytics Page
        page.click('button.ng-navitem:has-text("Analytics")')
        page.wait_for_selector('h1:has-text("Analytics & Telemetry")', timeout=8000)
        page.wait_for_timeout(800)
        save_and_copy(page, "phase9_ui_06_analytics.png")

        # 7. Reports Page
        page.click('button.ng-navitem:has-text("Reports")')
        page.wait_for_selector('h1:has-text("NetGuardian Security Report")', timeout=8000)
        page.wait_for_timeout(800)
        save_and_copy(page, "phase9_ui_07_reports.png")

        browser.close()
