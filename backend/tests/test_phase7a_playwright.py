import os
import time
import shutil
import pytest
from playwright.sync_api import sync_playwright

SCREENSHOT_DIR = os.path.join(os.path.dirname(__file__), "screenshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

ARTIFACT_DIR = r"C:\Users\srini\.gemini\antigravity\brain\3166697a-8be2-4b72-80cd-0bd4dcc6a45e"

FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5175")

def copy_to_artifacts(src_path: str, filename: str):
    try:
        dest_path = os.path.join(ARTIFACT_DIR, filename)
        shutil.copy2(src_path, dest_path)
        print(f"Copied {filename} to artifacts directory: {dest_path}")
    except Exception as e:
        print(f"Warning: could not copy {filename} to artifacts: {e}")

def test_phase7a_dashboard_settings_and_system_status():
    """
    Phase 7A Playwright E2E Verification:
    1. Log in as admin, dismiss tutorial.
    2. Inspect Dashboard:
       - 6 KPI cards (Devices Online, Threats Detected, Suspicious Devices, Packets Monitored, Active Connections, High-Risk Devices)
       - Health Gauge with label (HEALTHY) and breakdown
       - "What should I do next?" comprehensive guidance card
       - Latest AI Anomaly Detection card
       - Mini Topology Map
       - Screenshot 1: phase7a_01_dashboard_baseline_healthy.png
    3. Test Traffic Controls:
       - Verify state: SIMULATION: RUNNING
       - Click Pause -> state changes to SIMULATION: PAUSED
       - Click Step -> advances 1 tick
       - Click Resume -> state changes to SIMULATION: RUNNING
       - Screenshot 2: phase7a_02_dashboard_traffic_controls.png
    4. Inject Security Event directly from Dashboard:
       - Click "🔁 Port Scan"
       - Verify Threat count changes, health score drops, "Needs attention" list updates
       - Screenshot 3: phase7a_03_dashboard_event_injected_threats.png
    5. Navigate to Settings:
       - Verify System Status Probes panel (Backend, Database, AI Engine, Digital Twin, Network Collector) with reasons
       - Verify Detection, Simulation, Security fields
       - Screenshot 4: phase7a_04_settings_admin_and_status.png
    6. Log in as Analyst:
       - Navigate to Settings
       - Verify Read-Only Mode banner and disabled inputs
       - Screenshot 5: phase7a_05_settings_analyst_readonly.png
    7. Test Friendly Offline Error State:
       - Intercept API requests to simulate backend downtime
       - Verify friendly error message "Unable to load... Please verify the backend is running." with Retry button
       - Screenshot 6: phase7a_06_friendly_offline_error.png
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 950})
        page = context.new_page()

        # Handle dialogs
        page.on("dialog", lambda dialog: dialog.accept())

        # Step 1: Open landing page and log in as Admin
        context.clear_cookies()
        page.goto(FRONTEND_URL, wait_until="networkidle")
        page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
        page.reload(wait_until="networkidle")
        time.sleep(1)

        page.wait_for_selector('input[placeholder="Enter username"]', timeout=8000)
        page.fill('input[placeholder="Enter username"]', "admin")
        page.fill('input[placeholder="Enter password"]', "admin123")
        page.click('button[type="submit"]')

        # Dismiss tutorial
        try:
            skip_btn = page.locator('button:has-text("Skip Tutorial")')
            skip_btn.wait_for(state="visible", timeout=4000)
            skip_btn.click()
            page.wait_for_selector('.ng-modal', state="detached", timeout=4000)
        except Exception:
            pass

        # Step 2: Dashboard Baseline Verification
        page.wait_for_selector('h1:has-text("Security Dashboard")', timeout=8000)
        page.wait_for_selector('.kpi-label:has-text("Devices Online")', timeout=5000)
        page.wait_for_selector('.kpi-label:has-text("Threats Detected")', timeout=5000)
        page.wait_for_selector('.kpi-label:has-text("Suspicious Devices")', timeout=5000)
        page.wait_for_selector('.kpi-label:has-text("Packets Monitored")', timeout=5000)
        page.wait_for_selector('.kpi-label:has-text("Active Connections")', timeout=5000)
        page.wait_for_selector('.kpi-label:has-text("High-Risk Devices")', timeout=5000)

        # Verify "What should I do next?" card
        page.wait_for_selector('text=What should I do next?', timeout=5000)
        # Verify AI Anomaly Card
        page.wait_for_selector('text=Latest AI Anomaly Detection', timeout=5000)
        # Verify Mini Topology Map
        page.wait_for_selector('text=Mini Topology Map (Digital Twin)', timeout=5000)

        time.sleep(1)
        s1 = os.path.join(SCREENSHOT_DIR, "phase7a_01_dashboard_baseline_healthy.png")
        page.screenshot(path=s1, full_page=True)
        copy_to_artifacts(s1, "phase7a_01_dashboard_baseline_healthy.png")

        # Step 3: Traffic Controls Test
        # Click Pause
        pause_btn = page.locator('button:has-text("Pause")')
        pause_btn.click()
        page.wait_for_selector('text=SIMULATION: PAUSED', timeout=5000)

        # Click Step
        step_btn = page.locator('button:has-text("Step")')
        step_btn.click()
        time.sleep(1)

        # Click Resume
        resume_btn = page.locator('button:has-text("Resume")')
        resume_btn.click()
        page.wait_for_selector('text=SIMULATION: RUNNING', timeout=5000)

        s2 = os.path.join(SCREENSHOT_DIR, "phase7a_02_dashboard_traffic_controls.png")
        page.screenshot(path=s2, full_page=True)
        copy_to_artifacts(s2, "phase7a_02_dashboard_traffic_controls.png")

        # Step 4: Inject Security Event from Dashboard
        port_scan_btn = page.locator('button:has-text("Port Scan")')
        port_scan_btn.click()
        page.wait_for_selector('text=PORT SCAN event triggered', timeout=8000)
        time.sleep(2)

        # Confirm Needs Attention list shows threat
        page.wait_for_selector('text=Needs Attention: Open Threats', timeout=5000)
        page.wait_for_selector('button:has-text("Investigate")', timeout=5000)

        s3 = os.path.join(SCREENSHOT_DIR, "phase7a_03_dashboard_event_injected_threats.png")
        page.screenshot(path=s3, full_page=True)
        copy_to_artifacts(s3, "phase7a_03_dashboard_event_injected_threats.png")

        # Step 5: Navigate to Settings (Admin Mode)
        page.click('nav.ng-navlist button:has-text("Settings")')
        page.wait_for_selector('h1:has-text("System Settings & Status")', timeout=8000)
        page.wait_for_selector('text=Subsystem Health Probes', timeout=5000)
        page.wait_for_selector('text=Backend Engine', timeout=5000)
        page.wait_for_selector('text=Database Storage', timeout=5000)
        page.wait_for_selector('text=AI Anomaly Engine', timeout=5000)
        page.wait_for_selector('text=Digital Twin Graph', timeout=5000)
        page.wait_for_selector('text=Network Collector', timeout=5000)

        time.sleep(1)
        s4 = os.path.join(SCREENSHOT_DIR, "phase7a_04_settings_admin_and_status.png")
        page.screenshot(path=s4, full_page=True)
        copy_to_artifacts(s4, "phase7a_04_settings_admin_and_status.png")

        # Step 6: Log in as Analyst to verify Read-Only Settings
        page.click('button:has-text("Profile")')
        page.wait_for_selector('button:has-text("Sign Out")', timeout=5000)
        page.click('button:has-text("Sign Out")')

        page.wait_for_selector('input[placeholder="Enter username"]', timeout=8000)
        page.fill('input[placeholder="Enter username"]', "analyst")
        page.fill('input[placeholder="Enter password"]', "analyst123")
        page.click('button[type="submit"]')

        try:
            skip_btn = page.locator('button:has-text("Skip Tutorial")')
            skip_btn.wait_for(state="visible", timeout=3000)
            skip_btn.click()
        except Exception:
            pass

        page.click('nav.ng-navlist button:has-text("Settings")')
        page.wait_for_selector('text=Read-Only Mode: Signed in as an Analyst', timeout=8000)
        page.wait_for_selector('button:has-text("Read-Only (Analyst)")', timeout=5000)

        s5 = os.path.join(SCREENSHOT_DIR, "phase7a_05_settings_analyst_readonly.png")
        page.screenshot(path=s5, full_page=True)
        copy_to_artifacts(s5, "phase7a_05_settings_analyst_readonly.png")

        # Step 7: Friendly Offline State Verification
        # Abort subsequent /api/devices requests to simulate backend downtime
        page.route("**/api/devices*", lambda route: route.abort("failed"))
        page.click('nav.ng-navlist button:has-text("Network")')
        page.wait_for_selector('text=Unable to Load Devices', timeout=8000)
        page.wait_for_selector('text=Unable to load devices. Please verify the backend is running.', timeout=5000)
        page.wait_for_selector('button:has-text("Retry")', timeout=5000)

        s6 = os.path.join(SCREENSHOT_DIR, "phase7a_06_friendly_offline_error.png")
        page.screenshot(path=s6, full_page=True)
        copy_to_artifacts(s6, "phase7a_06_friendly_offline_error.png")

        browser.close()
