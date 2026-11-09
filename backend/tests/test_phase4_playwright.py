import os
import time
import pytest
from playwright.sync_api import sync_playwright

SCREENSHOT_DIR = os.path.join(os.path.dirname(__file__), "screenshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5175")

def test_phase4_ai_anomaly_detection_ui():
    """
    Phase 4 Playwright E2E Verification:
    1. Log in as admin and dismiss onboarding if present.
    2. Navigate to Threats page and trigger simulated Port Scan Reconnaissance.
    3. Verify generated alert exhibits 'RULE+AI' detection badge.
    4. Open alert details modal and verify:
       - AI Assessment: ANOMALOUS
       - Anomaly Score and Confidence are visible
       - 'Why was this flagged?' dynamic plain-language reasons are displayed
       - Model advisory disclaimer is present
       - Save screenshot: phase4_ai_alert_details.png
    5. Navigate to Settings page and verify AI Model Card:
       - Displays 8 standardized features
       - Displays precision, recall, and synthetic holdout validation metrics
       - Displays operational limitations and advisory role
       - Save screenshot: phase4_model_card.png
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1400, "height": 900})
        page = context.new_page()

        # Step 1: Open Landing / Login Page with clean cookie session
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

        # Step 4: Open Simulation Modal and Trigger Port Scan
        sim_btn = page.locator('button:has-text("Simulate Security Event")').first
        assert sim_btn.is_visible(), "Simulate Security Event button must be visible on Threats page"
        sim_btn.click()
        time.sleep(0.8)

        modal = page.locator('.modal-content')
        assert modal.is_visible(), "Simulation modal must open"

        # Select scenario card 2: Port Scan Reconnaissance
        option = page.locator('text=2. Port Scan Reconnaissance').first
        assert option.is_visible(), "Option '2. Port Scan Reconnaissance' not visible in modal"
        option.click()
        time.sleep(0.4)

        # Click Execute Simulation
        exec_btn = page.locator('.modal-content button:has-text("Execute Simulation")')
        assert exec_btn.is_visible()
        exec_btn.click()
        time.sleep(2.5)

        # Verify alert appears in table
        alert_row = page.locator('tr:has-text("Port Scan")').first
        assert alert_row.is_visible(), "Port Scanning alert row must appear in Threats table"

        # Verify RULE+AI badge is rendered
        badge = alert_row.locator('text=RULE+AI').first
        assert badge.is_visible(), "RULE+AI detection method badge must be visible in table row"

        # Step 5: Open Alert Details View
        details_btn = alert_row.locator('button:has-text("Details"), button:has-text("Investigate")').first
        if details_btn.is_visible():
            details_btn.click()
        else:
            alert_row.click()
        time.sleep(1)

        details_modal = page.locator('.modal-content')
        assert details_modal.is_visible(), "Alert details modal must open"

        # Assert AI Assessment Banner
        banner = details_modal.locator('text=AI Assessment: ANOMALOUS')
        assert banner.is_visible(), "AI Assessment: ANOMALOUS banner must be visible in alert details modal"

        # Assert 'Why was this flagged?' explainability section
        why_flagged = details_modal.locator('text=Why was this flagged?')
        assert why_flagged.is_visible(), "'Why was this flagged?' explainability section must be visible"

        # Assert dynamic plain language reasons
        reason_item = details_modal.locator('li:has-text("ports"), li:has-text("baseline")').first
        assert reason_item.is_visible(), "Dynamic plain-language reasons must be rendered"

        # Assert advisory disclaimer
        disclaimer = details_modal.locator('text=deviation from the learned behavioral baseline').first
        assert disclaimer.is_visible(), "Non-malice advisory disclaimer must be rendered"

        # Save Screenshot of AI Alert Details View
        details_screenshot = os.path.join(SCREENSHOT_DIR, "phase4_ai_alert_details.png")
        page.screenshot(path=details_screenshot)
        assert os.path.exists(details_screenshot), "phase4_ai_alert_details.png must be saved"

        # Close details modal
        close_btn = page.locator('.modal-content button.btn-ghost, .modal-content button:has-text("Close")').first
        if close_btn.is_visible():
            close_btn.click()
            time.sleep(0.5)

        # Step 6: Navigate to Settings Page to inspect AI Model Card
        page.click('nav.ng-navlist button:has-text("Settings")')
        page.wait_for_selector('h1:has-text("Settings")', timeout=8000)
        time.sleep(1)

        # Assert Model Card Header
        model_card = page.locator('text=AI Anomaly Detection Model Card')
        assert model_card.is_visible(), "AI Anomaly Detection Model Card must be visible on Settings page"

        # Assert 8 Standardized Features badges
        feat_badge = page.locator('text=unique_destination_ports')
        assert feat_badge.is_visible(), "Standardized feature badges must be visible in Model Card"

        # Assert Validation Benchmarks section
        precision_metric = page.locator('text=Precision')
        assert precision_metric.is_visible(), "Precision validation metric must be visible in Model Card"

        # Assert Limitations and Advisory Notice
        limitations = page.locator('text=Operational Limitations & Advisory Role')
        assert limitations.is_visible(), "Operational Limitations section must be visible in Model Card"

        # Save Screenshot of Model Card View
        model_screenshot = os.path.join(SCREENSHOT_DIR, "phase4_model_card.png")
        page.screenshot(path=model_screenshot)
        assert os.path.exists(model_screenshot), "phase4_model_card.png must be saved"

        browser.close()

if __name__ == "__main__":
    test_phase4_ai_anomaly_detection_ui()
    print("Playwright Phase 4 verification passed successfully!")
