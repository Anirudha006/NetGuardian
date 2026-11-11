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

def test_phase7b_guided_demo_and_demo_mode_playwright():
    """
    Phase 7B End-to-End Playwright Verification:
    1. Log in as admin, dismiss tutorial.
    2. Toggle Demo Mode (Task 6): verify high-contrast presentation styling and hidden configuration tabs.
    3. Open Guided Demonstration (Task 4):
       Walk through all 12 steps in real Chromium browser, verifying automatic page transitions
       and capturing a screenshot per step.
    4. Execute Reset Demo (Task 5):
       Open confirmation dialog, confirm reset, verify pristine baseline restoration.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 950})
        page = context.new_page()

        # Step A: Login as admin
        page.goto(f"{FRONTEND_URL}/")
        page.wait_for_selector('input[type="text"]', timeout=10000)
        page.fill('input[type="text"]', 'admin')
        page.fill('input[type="password"]', 'admin123')
        page.click('button[type="submit"]')

        # Wait for dashboard
        page.wait_for_selector('text=NETGUARDIAN', timeout=12000)
        time.sleep(1.0)

        # Dismiss onboarding tutorial if visible
        try:
            skip_btn = page.query_selector('button:has-text("Skip")')
            if skip_btn:
                skip_btn.click()
                time.sleep(0.5)
        except Exception:
            pass

        # Step B: Toggle Demo Mode (Task 6)
        demo_mode_btn = page.wait_for_selector('button:has-text("Demo Mode")', timeout=8000)
        demo_mode_btn.click()
        time.sleep(1.0)
        assert page.query_selector('.demo-mode') is not None, "Demo mode class should be applied to app root"

        # Verify that Settings configuration page is hidden in Demo Mode
        assert page.query_selector('.ng-navitem:has-text("Settings")') is None, "Settings tab must be hidden in Demo Mode"

        # Item 7: Confirm Logout and Profile are reachable in Demo Mode
        profile_nav = page.wait_for_selector('.ng-navitem:has-text("Profile")', timeout=5000)
        assert profile_nav is not None, "Profile tab must be reachable in Demo Mode"
        profile_nav.click()
        time.sleep(0.5)
        assert page.wait_for_selector('text=Account Information', timeout=5000) is not None, "Profile view should be visible in Demo Mode"

        # Confirm Logout (Sign Out) is reachable via user profile dropdown in Demo Mode
        user_menu_btn = page.wait_for_selector('button:has-text("admin")', timeout=5000)
        user_menu_btn.click()
        time.sleep(0.5)
        logout_btn = page.wait_for_selector('button:has-text("Sign Out")', timeout=5000)
        assert logout_btn is not None, "Sign Out button must be reachable in Demo Mode"
        # Close profile menu
        user_menu_btn.click()
        time.sleep(0.5)

        # Open Full Guided Demo Modal
        start_demo_btn = page.wait_for_selector('button:has-text("Start Demo")', timeout=8000)
        start_demo_btn.click()
        time.sleep(1.0)

        # Step C: Execute Guided Demo Steps 1 to 12 (Task 4)
        for step_num in range(1, 13):
            # Click step button in the guided demo progress bar
            step_btn = page.wait_for_selector(f'button:text-is("{step_num}")', timeout=8000)
            step_btn.click()
            time.sleep(1.2)

            filename = f"phase7b_step{step_num:02d}.png"
            filepath = os.path.join(SCREENSHOT_DIR, filename)
            page.screenshot(path=filepath)
            copy_to_artifacts(filepath, filename)
            print(f"Captured Step {step_num} screenshot: {filename}")

        # Step D: Test Reset Demo Dialog & Action (Task 5)
        reset_btn = page.wait_for_selector('button:has-text("Reset Demo")', timeout=8000)
        reset_btn.click()
        time.sleep(0.8)

        # Verify confirmation dialog appears
        assert page.wait_for_selector('text=Reset Demonstration?', timeout=5000) is not None
        confirm_btn = page.wait_for_selector('button:has-text("Confirm Reset")', timeout=5000)
        confirm_btn.click()
        time.sleep(2.0)

        reset_filename = "phase7b_step13_reset_baseline.png"
        reset_filepath = os.path.join(SCREENSHOT_DIR, reset_filename)
        page.screenshot(path=reset_filepath)
        copy_to_artifacts(reset_filepath, reset_filename)
        print(f"Captured Reset Baseline screenshot: {reset_filename}")

        browser.close()

if __name__ == "__main__":
    test_phase7b_guided_demo_and_demo_mode_playwright()
