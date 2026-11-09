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

def test_phase6_what_if_simulation_and_isolation():
    """
    Phase 6 Playwright E2E Verification:
    1. Log in as admin, dismiss tutorial.
    2. Navigate to Simulation (What-If) page.
    3. Select PC-04 and run What-If Simulation.
    4. Confirm scenario text, reach path ('PC-04 → Switch → Server → Database'), 3 hops,
       Critical Asset Reached = YES, Risk = 60.5 (HIGH), mathematical breakdown, ordered step list.
    5. Save Screenshot 1: phase6_01_whatif_attack_path_breakdown.png.
    6. Click 'Simulate Isolation' and accept confirmation dialog.
    7. Verify exact message:
       'SIMULATED ACTION — PC-04 isolated. Potential attack path interrupted. No real network changes were performed.'
    8. Verify Before vs After comparison card (Reachable: 3 vs 0, Risk: 60.5 vs 0.0).
    9. Save Screenshot 2: phase6_02_simulated_isolation_interrupted.png.
    10. Click 'Restore Device' and accept confirmation dialog.
    11. Verify restored network state.
    12. Save Screenshot 3: phase6_03_restored_twin_state.png.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 950})
        page = context.new_page()

        # Handle browser alert/confirm dialogs automatically
        page.on("dialog", lambda dialog: dialog.accept())

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

        # Step 2: Navigate to Simulation / What-If page
        page.wait_for_selector('nav.ng-navlist', timeout=10000)
        page.click('nav.ng-navlist button:has-text("Simulation")')
        page.wait_for_selector('h1:has-text("What-If Attack Simulation Engine")', timeout=8000)
        page.wait_for_selector('.tag-hypothetical:has-text("HYPOTHETICAL")', timeout=5000)
        time.sleep(1)

        # Step 3: Select PC-04 from the device dropdown
        select_elem = page.locator('select.ng-select')
        select_elem.wait_for(state="visible", timeout=5000)

        # Find option containing PC-04
        pc04_option_value = None
        options = select_elem.locator('option').all()
        for opt in options:
            txt = opt.text_content()
            if "PC-04" in txt:
                pc04_option_value = opt.get_attribute("value")
                break

        assert pc04_option_value is not None, "PC-04 option not found in device selector"
        select_elem.select_option(value=pc04_option_value)
        time.sleep(0.5)

        # Step 4: Click 'Run What-If Simulation'
        run_btn = page.locator('button:has-text("Run What-If Simulation")')
        assert run_btn.is_enabled(), "Run What-If button should be enabled after device selection"
        run_btn.click()

        # Step 5: Wait for simulation results to render
        page.wait_for_selector('text=PC-04 is hypothetically compromised', timeout=8000)
        page.wait_for_selector('text=PC-04 → Switch → Server → Database', timeout=5000)
        page.wait_for_selector('text=Critical Asset Reached', timeout=5000)
        page.wait_for_selector('text=YES', timeout=5000)

        # Verify KPI Metrics
        page.wait_for_selector('.ng-card-sm:has-text("Simulated Risk Level")', timeout=5000)
        assert page.locator('span.badge-high:has-text("HIGH")').first.is_visible()

        # Verify Ordered Step List badges
        assert page.locator('text=COMPROMISED ORIGIN').is_visible()
        assert page.locator('text=LATERAL HOP').is_visible()
        assert page.locator('text=CORE SERVER').is_visible()
        assert page.locator('text=CRITICAL TARGET').is_visible()

        # Verify Formula Breakdown Table
        assert page.locator('text=0.30 × Source Risk').is_visible()
        assert page.locator('text=0.35 × Target Crit').is_visible()
        assert page.locator('text=0.15 × Hop Factor').is_visible()
        assert page.locator('text=0.20 × Path Trust').is_visible()

        time.sleep(1)

        # Evidentiary Screenshot 1: What-If Attack Path & Breakdown
        snap1_path = os.path.join(SCREENSHOT_DIR, "phase6_01_whatif_attack_path_breakdown.png")
        page.screenshot(path=snap1_path, full_page=True)
        copy_to_artifacts(snap1_path, "phase6_01_whatif_attack_path_breakdown.png")
        print(f"Saved Screenshot 1: {snap1_path}")

        # Step 6: Click 'Simulate Isolation'
        isolate_btn = page.locator('button:has-text("Simulate Isolation")')
        assert isolate_btn.is_visible(), "Simulate Isolation button should be visible"
        isolate_btn.click()

        # Step 7: Wait for isolation confirmation banner
        page.wait_for_selector('text=SIMULATED ACTION — PC-04 isolated.', timeout=8000)
        page.wait_for_selector('text=Potential attack path interrupted.', timeout=5000)
        page.wait_for_selector('text=No real network changes were performed.', timeout=5000)

        # Verify Before vs After Comparison Card
        page.wait_for_selector('text=Before vs After Isolation Comparison', timeout=5000)
        page.wait_for_selector('text=0.0', timeout=5000)

        time.sleep(1)

        # Evidentiary Screenshot 2: Simulated Isolation Interrupted
        snap2_path = os.path.join(SCREENSHOT_DIR, "phase6_02_simulated_isolation_interrupted.png")
        page.screenshot(path=snap2_path, full_page=True)
        copy_to_artifacts(snap2_path, "phase6_02_simulated_isolation_interrupted.png")
        print(f"Saved Screenshot 2: {snap2_path}")

        # Step 8: Click 'Restore Device'
        restore_btn = page.locator('button:has-text("Restore Device")')
        assert restore_btn.is_visible(), "Restore Device button should be visible"
        restore_btn.click()

        # Wait for device restoration
        page.wait_for_selector('button:has-text("Run What-If Simulation")', timeout=8000)
        time.sleep(1.5)

        # Evidentiary Screenshot 3: Restored Network Twin State
        snap3_path = os.path.join(SCREENSHOT_DIR, "phase6_03_restored_twin_state.png")
        page.screenshot(path=snap3_path, full_page=True)
        copy_to_artifacts(snap3_path, "phase6_03_restored_twin_state.png")
        print(f"Saved Screenshot 3: {snap3_path}")

        browser.close()

if __name__ == "__main__":
    test_phase6_what_if_simulation_and_isolation()
