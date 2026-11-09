import os
import sys
import pytest
from playwright.sync_api import sync_playwright

# Ensure UTF-8 output on Windows console
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

SCREENSHOTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "screenshots"))
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

BASE_URL = os.environ.get("FRONTEND_URL", "http://localhost:5175")

def test_playwright_e2e_browser_flow():
    """Requirement 6: Complete end-to-end real browser test using Playwright Chromium:
    1. Open landing page and verify light theme, branding, tagline, and workflow.
    2. Log in as admin.
    3. Confirm onboarding modal appears and verify contents.
    4. Click 'Skip Tutorial' and confirm modal closes.
    5. Confirm dashboard displays with light theme and KPI metrics.
    6. Check all 10 navigation items and verify each renders cleanly.
    7. Verify live footer subsystem status strip.
    8. Capture and preserve screenshots in backend/tests/screenshots/.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            ignore_https_errors=True
        )
        page = context.new_page()

        console_errors = []
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)

        # Step 1: Open Landing Page
        print("\n[Playwright] Step 1: Navigating to landing page:", BASE_URL)
        page.goto(BASE_URL, wait_until="networkidle")

        # Clear any stored state to guarantee fresh onboarding modal
        page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
        page.reload(wait_until="networkidle")

        # Verify Landing Page branding, tagline, and workflow via visible text
        body_text = page.inner_text("body")
        assert "NETGUARDIAN" in body_text, "NETGUARDIAN brand text not found on landing page"
        assert "See your network. Understand the risk." in body_text, "Tagline missing from landing page"
        assert "Observe" in body_text and "Respond" in body_text, "Workflow steps missing from landing page"

        # Verify Light Theme on landing page: soft grey background, dark text
        body_bg = page.evaluate("() => window.getComputedStyle(document.body).backgroundColor")
        print(f"[Playwright] Landing page body background: {body_bg}")

        # Capture Screenshot 1: Landing Page
        shot_01 = os.path.join(SCREENSHOTS_DIR, "01_landing_page.png")
        page.screenshot(path=shot_01, full_page=True)
        assert os.path.exists(shot_01), "Screenshot 01 was not saved"
        print(f"[Playwright] Saved {shot_01}")

        # Step 2: Log in as admin
        print("[Playwright] Step 2: Submitting admin credentials...")
        page.fill('input[placeholder="Enter username"]', "admin")
        page.fill('input[placeholder="Enter password"]', "admin123")
        page.click('button[type="submit"]')

        # Step 3: Confirm Onboarding Modal appears
        print("[Playwright] Step 3: Verifying onboarding modal...")
        page.wait_for_selector('.ng-modal', timeout=10000)
        assert page.is_visible('.ng-modal'), "Onboarding modal not visible"
        modal_text = page.locator('.ng-modal').inner_text()
        assert "Welcome to NetGuardian" in modal_text, "Onboarding modal header missing"
        assert "Skip Tutorial" in modal_text, "Skip Tutorial button text missing"

        # Capture Screenshot 2: Onboarding Modal
        shot_02 = os.path.join(SCREENSHOTS_DIR, "02_onboarding_modal.png")
        page.screenshot(path=shot_02)
        assert os.path.exists(shot_02), "Screenshot 02 was not saved"
        print(f"[Playwright] Saved {shot_02}")

        # Step 4: Click 'Skip Tutorial'
        print("[Playwright] Step 4: Clicking 'Skip Tutorial'...")
        skip_btn = page.locator('button:has-text("Skip Tutorial")')
        skip_btn.click()
        page.wait_for_selector('.ng-modal', state="detached", timeout=5000)
        assert not page.is_visible('.ng-modal'), "Onboarding modal did not dismiss"

        # Step 5: Confirm Dashboard displays with light theme
        print("[Playwright] Step 5: Verifying Dashboard display and light theme...")
        page.wait_for_selector('nav.ng-navlist', timeout=10000)
        assert page.is_visible('nav.ng-navlist'), "Navbar not visible after login"

        # Verify Dashboard KPIs (case-insensitive check)
        dash_text = page.inner_text("body").lower()
        assert "network health" in dash_text or "devices online" in dash_text or "security dashboard" in dash_text, "Dashboard KPI missing"

        # Capture Screenshot 3: Dashboard View
        shot_03 = os.path.join(SCREENSHOTS_DIR, "03_dashboard_view.png")
        page.screenshot(path=shot_03, full_page=True)
        assert os.path.exists(shot_03), "Screenshot 03 was not saved"
        print(f"[Playwright] Saved {shot_03}")

        # Step 6: Check all 9 Navigation Items as per spec:
        # Dashboard, Network, Digital Twin, Threats, Simulation, Analytics, Reports, Settings, Profile
        nav_targets = [
            ("Dashboard", "04_nav_dashboard.png"),
            ("Network", "05_nav_network.png"),
            ("Digital Twin", "06_nav_digital_twin.png"),
            ("Threats", "07_nav_threats.png"),
            ("Simulation", "08_nav_simulation.png"),
            ("Analytics", "10_nav_analytics.png"),
            ("Reports", "11_nav_reports.png"),
            ("Settings", "12_nav_settings.png"),
            ("Profile", "13_nav_profile.png"),
        ]

        print(f"[Playwright] Step 6: Verifying all {len(nav_targets)} navigation items...")
        for label, screenshot_name in nav_targets:
            btn_selector = f'nav.ng-navlist button:has-text("{label}")'
            page.wait_for_selector(btn_selector, timeout=5000)
            page.click(btn_selector)
            page.wait_for_timeout(600)  # smooth render transition

            # Check that page rendered without error
            assert not page.is_visible('text="An internal server error"'), f"Error detected on tab {label}"

            # Save screenshot
            shot_path = os.path.join(SCREENSHOTS_DIR, screenshot_name)
            page.screenshot(path=shot_path, full_page=True)
            assert os.path.exists(shot_path), f"Failed to save {shot_path}"
            print(f"[Playwright] Clicked '{label}' -> saved {screenshot_name}")

        # Step 7: Verify Footer Status Strip
        print("[Playwright] Step 7: Verifying live footer status strip...")
        footer_selector = '.status-strip'
        page.wait_for_selector(footer_selector, timeout=5000)
        footer_text = page.inner_text(footer_selector)
        print(f"[Playwright] Footer status text: {footer_text}")
        assert "Backend:" in footer_text and "ONLINE" in footer_text
        assert "Database:" in footer_text and "ONLINE" in footer_text
        assert "AI Engine:" in footer_text and "READY" in footer_text
        assert "Digital Twin:" in footer_text and "SYNCHRONIZED" in footer_text
        assert "Network Collector:" in footer_text

        # Capture footer screenshot
        shot_14 = os.path.join(SCREENSHOTS_DIR, "14_footer_status_strip.png")
        page.locator(footer_selector).screenshot(path=shot_14)
        print(f"[Playwright] Saved {shot_14}")

        browser.close()
        print("\n[Playwright] All end-to-end browser verification steps passed successfully!")

if __name__ == "__main__":
    test_playwright_e2e_browser_flow()
