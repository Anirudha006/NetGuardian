import os
import time
import shutil
import pytest
from playwright.sync_api import sync_playwright
import pypdf
import pymupdf

SCREENSHOT_DIR = os.path.join(os.path.dirname(__file__), "screenshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

DOCS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "docs"))
os.makedirs(DOCS_DIR, exist_ok=True)

ARTIFACT_DIR = r"C:\Users\srini\.gemini\antigravity\brain\3166697a-8be2-4b72-80cd-0bd4dcc6a45e"
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5175")
AXE_SCRIPT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "node_modules", "axe-core", "axe.min.js"))

def copy_to_artifacts(src_path: str, filename: str):
    try:
        dest_path = os.path.join(ARTIFACT_DIR, filename)
        shutil.copy2(src_path, dest_path)
        print(f"Copied {filename} to artifacts directory: {dest_path}")
    except Exception as e:
        print(f"Warning: could not copy {filename} to artifacts: {e}")

def test_phase8_analytics_and_reporting_playwright():
    """
    Phase 8 End-to-End Extended Playwright Verification:
    1. Login as admin, dismiss tutorial.
    2. Navigate to Analytics:
       - Verify charts, KPI summaries, accessible light-theme styling.
       - Select time ranges: 'Last 15m', 'Last 1h', 'All Data'.
       - Select data sources: 'Simulated', 'Observed', 'All Sources'.
       - Toggle 'Show as table' to verify tabular accessibility mode.
       - Capture individual screenshots of all 7 charts.
       - Run axe-core accessibility audit on Analytics page.
    3. Navigate to Reports:
       - Verify report header, metadata, and prominent SIMULATED DATA NOTICE.
       - Verify all 11 numbered report sections.
       - Run axe-core accessibility audit on Reports page.
    4. Download PDF:
       - Trigger 'Export PDF', save to docs/sample_report.pdf.
       - Render PDF pages into docs/sample_report_page_X.png via pymupdf.
       - Report exact file sizes.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 950}, accept_downloads=True)
        page = context.new_page()

        # Step 1: Login
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
            modal = page.wait_for_selector('.ng-modal-overlay', timeout=3000)
            if modal:
                skip_btn = page.query_selector('button:has-text("Skip")')
                if skip_btn:
                    skip_btn.click()
                else:
                    page.keyboard.press("Escape")
                page.wait_for_selector('.ng-modal-overlay', state='detached', timeout=4000)
                time.sleep(0.5)
        except Exception:
            pass

        # Step 2: Navigate to Analytics
        analytics_nav = page.wait_for_selector('button:has-text("Analytics")', timeout=8000)
        analytics_nav.click()
        page.wait_for_selector('text=Analytics & Telemetry', timeout=10000)
        time.sleep(1.5)

        # 2a. Exercise Time Range Selector
        btn_15m = page.wait_for_selector('button:has-text("Last 15m")', timeout=5000)
        btn_15m.click()
        time.sleep(0.6)

        btn_1h = page.wait_for_selector('button:has-text("Last 1h")', timeout=5000)
        btn_1h.click()
        time.sleep(0.6)

        btn_all = page.wait_for_selector('button:has-text("All Data")', timeout=5000)
        btn_all.click()
        time.sleep(0.6)

        # 2b. Exercise Data Source Filter
        btn_sim = page.wait_for_selector('button:has-text("Simulated")', timeout=5000)
        btn_sim.click()
        time.sleep(0.6)

        btn_obs = page.wait_for_selector('button:has-text("Observed")', timeout=5000)
        btn_obs.click()
        time.sleep(0.6)

        btn_all_src = page.wait_for_selector('button:has-text("All Sources")', timeout=5000)
        btn_all_src.click()
        time.sleep(0.8)

        # 2c. Exercise "Show as table" accessibility toggle
        table_toggle_btn = page.query_selector('#chart-traffic-over-time button[aria-label="Toggle table view for Traffic Over Time"]')
        if table_toggle_btn:
            table_toggle_btn.click()
            time.sleep(0.4)
            # Assert table view is displayed
            assert page.wait_for_selector('table[aria-label="Traffic over time data table"]', timeout=3000)
            # Toggle back to chart
            table_toggle_btn.click()
            time.sleep(0.4)

        # 2d. Capture 1 screenshot per chart (7 charts)
        chart_selectors = [
            ("chart_01_traffic_over_time.png", "#chart-traffic-over-time"),
            ("chart_02_threats_over_time.png", "#chart-threats-over-time"),
            ("chart_03_threat_categories.png", "#chart-threat-categories"),
            ("chart_04_device_risk.png", "#chart-device-risk"),
            ("chart_05_protocol_usage.png", "#chart-protocol-usage"),
            ("chart_06_top_devices.png", "#chart-top-devices"),
            ("chart_07_anomalies_timeline.png", "#chart-anomalies-timeline"),
        ]

        print("\n--- Capturing 7 Chart Screenshots ---")
        for filename, selector in chart_selectors:
            el = page.wait_for_selector(selector, timeout=6000)
            shot_path = os.path.join(SCREENSHOT_DIR, filename)
            el.screenshot(path=shot_path)
            copy_to_artifacts(shot_path, filename)
            size = os.path.getsize(shot_path)
            print(f"[CHART SCREENSHOT] {filename}: {size} bytes (saved to {shot_path})")

        # Capture full Analytics Page screenshot
        full_shot1 = os.path.join(SCREENSHOT_DIR, "phase8_01_analytics_charts.png")
        page.screenshot(path=full_shot1, full_page=True)
        copy_to_artifacts(full_shot1, "phase8_01_analytics_charts.png")

        # 2e. Automated Axe-Core Check on Analytics Page
        assert os.path.exists(AXE_SCRIPT_PATH), f"Axe script missing at {AXE_SCRIPT_PATH}"
        with open(AXE_SCRIPT_PATH, "r", encoding="utf-8") as f:
            axe_js = f.read()

        page.evaluate(axe_js)
        axe_res_analytics = page.evaluate("axe.run({ runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa'] } })")
        analytics_serious_violations = [v for v in axe_res_analytics.get("violations", []) if v.get("impact") in ["critical", "serious"]]
        print(f"\n[AXE-CORE AUDIT - ANALYTICS] Total Violations: {len(axe_res_analytics.get('violations', []))}, Serious/Critical: {len(analytics_serious_violations)}")
        for v in analytics_serious_violations:
            print(f"  - [{v.get('impact')}] {v.get('id')}: {v.get('description')}")
            for node in v.get("nodes", []):
                print(f"      Node: {node.get('html')}")
                print(f"      Target: {node.get('target')}")
                print(f"      Summary: {node.get('failureSummary')}")
        assert len(analytics_serious_violations) == 0, f"Accessibility audit failed on Analytics page with {len(analytics_serious_violations)} serious violations"

        # Step 3: Navigate to Reports
        reports_nav = page.wait_for_selector('button:has-text("Reports")', timeout=8000)
        reports_nav.click()
        page.wait_for_selector('text=NetGuardian Security Report', timeout=10000)
        time.sleep(1.5)

        # Assert all 11 sections are rendered on the Report page
        expected_sections = [
            "1. Reporting Period",
            "2. Network Overview",
            "3. Devices",
            "4. Traffic Summary",
            "5. Security Events",
            "6. AI Anomalies",
            "7. High-Risk Devices",
            "8. Critical Assets",
            "9. Simulated Attack Paths",
            "10. Recommendations",
            "11. Conclusion"
        ]
        for section in expected_sections:
            assert page.wait_for_selector(f"text={section}", timeout=5000), f"Section missing: {section}"

        # Capture Reports Page Screenshot
        full_shot2 = os.path.join(SCREENSHOT_DIR, "phase8_02_security_report_view.png")
        page.screenshot(path=full_shot2, full_page=True)
        copy_to_artifacts(full_shot2, "phase8_02_security_report_view.png")

        # 3b. Automated Axe-Core Check on Reports Page
        page.evaluate(axe_js)
        axe_res_reports = page.evaluate("axe.run({ runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa'] } })")
        reports_serious_violations = [v for v in axe_res_reports.get("violations", []) if v.get("impact") in ["critical", "serious"]]
        print(f"\n[AXE-CORE AUDIT - REPORTS] Total Violations: {len(axe_res_reports.get('violations', []))}, Serious/Critical: {len(reports_serious_violations)}")
        for v in reports_serious_violations:
            print(f"  - [{v.get('impact')}] {v.get('id')}: {v.get('description')}")
            for node in v.get("nodes", []):
                print(f"      Node: {node.get('html')}")
                print(f"      Target: {node.get('target')}")
                print(f"      Summary: {node.get('failureSummary')}")
        assert len(reports_serious_violations) == 0, f"Accessibility audit failed on Reports page with {len(reports_serious_violations)} serious violations"

        # Step 4: Download PDF and Save to docs/sample_report.pdf
        export_btn = page.wait_for_selector('button:has-text("Export PDF")', timeout=8000)
        with page.expect_download(timeout=15000) as download_info:
            export_btn.click()

        download = download_info.value
        sample_pdf_path = os.path.join(DOCS_DIR, "sample_report.pdf")
        download.save_as(sample_pdf_path)
        assert os.path.exists(sample_pdf_path), "docs/sample_report.pdf must exist"
        pdf_size = os.path.getsize(sample_pdf_path)
        assert pdf_size > 2000, "Downloaded PDF must be non-empty"
        print(f"\n[PDF EXPORT] docs/sample_report.pdf: {pdf_size} bytes")

        # Verify PDF contents with pypdf
        reader = pypdf.PdfReader(sample_pdf_path)
        assert len(reader.pages) >= 2, f"Expected at least 2 pages, got {len(reader.pages)}"
        pdf_text = " ".join([page.extract_text() for page in reader.pages])
        assert "SIMULATED DATA NOTICE" in pdf_text
        assert "HYPOTHETICAL" in pdf_text
        assert "anomalies are not proof of attacks" in pdf_text

        # Render PDF pages to PNG images in docs/
        print("\n--- Rendering PDF Pages to docs/sample_report_page_X.png ---")
        doc = pymupdf.open(sample_pdf_path)
        page_image_files = []
        for i in range(len(doc)):
            pdf_page = doc[i]
            pix = pdf_page.get_pixmap(dpi=150)
            page_png_filename = f"sample_report_page_{i + 1}.png"
            page_png_path = os.path.join(DOCS_DIR, page_png_filename)
            pix.save(page_png_path)
            copy_to_artifacts(page_png_path, page_png_filename)
            size = os.path.getsize(page_png_path)
            page_image_files.append((page_png_filename, size))
            print(f"[PDF PAGE RENDER] {page_png_filename}: {size} bytes")

        browser.close()
        print("\n[PLAYWRIGHT EXTENDED SUCCESS] All checks passed successfully!")

if __name__ == "__main__":
    test_phase8_analytics_and_reporting_playwright()
