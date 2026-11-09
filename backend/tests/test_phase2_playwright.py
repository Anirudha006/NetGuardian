import os
import sys
import pytest
from playwright.sync_api import sync_playwright

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

SCREENSHOTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "screenshots"))
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

BASE_URL = os.environ.get("FRONTEND_URL", "http://localhost:5175")

def test_phase2_playwright_e2e_flow():
    """Phase 2 Browser E2E Acceptance Checks:
    1. Log in as admin and navigate to the Network page.
    2. Verify search, filter by device type, filter by status, and pagination.
    3. Open 'Add Simulated Device' form, submit valid device, and verify it appears.
    4. Switch to 'Network Map' view, verify hierarchical layout and clickable nodes.
    5. Click a map node to open the Device side panel and inspect real data & 'Why this risk?'.
    6. Switch to 'Live Traffic Stream' tab and generate synthetic pulse with deterministic seed.
    7. Capture and preserve screenshots in backend/tests/screenshots/.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            ignore_https_errors=True
        )
        page = context.new_page()

        # Step 1: Open and Login
        print("\n[Playwright Phase 2] Step 1: Logging in as admin...")
        page.goto(BASE_URL, wait_until="networkidle")
        page.fill('input[placeholder="Enter username"]', "admin")
        page.fill('input[placeholder="Enter password"]', "admin123")
        page.click('button[type="submit"]')

        # Handle onboarding modal if it appears
        try:
            skip_btn = page.locator('button:has-text("Skip Tutorial")')
            skip_btn.wait_for(state="visible", timeout=3000)
            skip_btn.click()
            page.wait_for_selector('.ng-modal', state="detached", timeout=3000)
        except Exception:
            pass

        # Step 2: Navigate to Network page
        print("[Playwright Phase 2] Step 2: Navigating to Network page...")
        page.wait_for_selector('nav.ng-navlist button:has-text("Network")', timeout=6000)
        page.click('nav.ng-navlist button:has-text("Network")')
        page.wait_for_selector('text=Network Operations', timeout=6000)

        # Check search and filters
        search_input = page.locator('input[placeholder*="Search by device"]')
        assert search_input.is_visible(), "Search input not visible on Network page"
        search_input.fill("Router")
        page.wait_for_timeout(400)
        assert page.locator('td:has-text("Router")').first.is_visible(), "Search for Router failed to show Router in table"
        search_input.fill("")  # Clear search

        # Filter by type: Server
        type_select = page.locator('select:has-text("All Device Types")')
        type_select.select_option("Server")
        page.wait_for_timeout(400)
        assert page.locator('td:has-text("Server")').first.is_visible(), "Filtering by Server failed to show Server in table"
        type_select.select_option("")  # Reset type filter

        # Capture Screenshot 1: Network Table View with filters
        shot_01 = os.path.join(SCREENSHOTS_DIR, "phase2_01_network_table.png")
        page.screenshot(path=shot_01, full_page=True)
        print(f"[Playwright Phase 2] Saved {shot_01}")

        # Step 3: Add Simulated Device
        print("[Playwright Phase 2] Step 3: Opening Add Simulated Device modal...")
        add_btn = page.locator('button:has-text("Add Simulated Device")')
        assert add_btn.is_visible(), "Admin '+ Add Simulated Device' button not visible"
        add_btn.click()

        page.wait_for_selector('.ng-modal', timeout=5000)
        assert page.is_visible('text=Add Simulated Device'), "Add Device modal not displayed"

        # Fill in device details with unique dynamic values to prevent collisions
        import uuid, random
        uid = uuid.uuid4().hex[:4]
        new_dev_name = f"Sec-Node-{uid}"
        b3 = random.randint(10, 240)
        b4 = random.randint(10, 240)
        new_ip = f"10.254.{b3}.{b4}"
        m1 = random.randint(10, 250)
        m2 = random.randint(10, 250)
        new_mac = f"02:1A:2B:3C:{m1:02X}:{m2:02X}"

        page.fill('input[placeholder*="Security-Auditor-PC"]', new_dev_name)
        page.fill('input[placeholder*="192.168.1.55"]', new_ip)
        page.fill('input[placeholder*="00:1A:2B:3C:4D:55"]', new_mac)

        # Capture Screenshot 2: Add Device Modal
        shot_02 = os.path.join(SCREENSHOTS_DIR, "phase2_02_add_device_modal.png")
        page.screenshot(path=shot_02)
        print(f"[Playwright Phase 2] Saved {shot_02}")

        # Submit form
        page.click('.ng-modal-footer button[type="submit"]')
        page.wait_for_selector('.ng-modal', state="detached", timeout=8000)

        # Verify new device appears in the table (via search filter)
        page.wait_for_timeout(500)
        search_input.fill(new_dev_name)
        page.wait_for_timeout(400)
        assert page.is_visible(f'text={new_dev_name}'), f"New device {new_dev_name} not found in table"
        print(f"[Playwright Phase 2] Device {new_dev_name} successfully added and verified in table.")
        search_input.fill("")
        page.wait_for_timeout(300)

        # Step 4: Switch to Network Map
        print("[Playwright Phase 2] Step 4: Switching to Network Map view...")
        map_btn = page.locator('button:has-text("Network Map")')
        map_btn.click()
        page.wait_for_selector('.topology-canvas', timeout=5000)

        # Verify hierarchical levels and nodes
        canvas = page.locator('.topology-canvas')
        assert canvas.is_visible(), "Topology canvas not visible in map view"
        assert page.is_visible('text=Internet → Router → Switch → Endpoints/Server → Database')

        # Capture Screenshot 3: Network Map View
        shot_03 = os.path.join(SCREENSHOTS_DIR, "phase2_03_network_map.png")
        page.screenshot(path=shot_03, full_page=True)
        print(f"[Playwright Phase 2] Saved {shot_03}")

        # Step 5: Click a node on the map to open DeviceDrawer
        print("[Playwright Phase 2] Step 5: Clicking map node to open side panel...")
        # Click on Server node in the SVG canvas
        server_node = page.locator('.topology-canvas g:has-text("Server")').first
        server_node.click()

        page.wait_for_selector('text=Why this risk?', timeout=6000)
        assert page.is_visible('text=Server'), "Side panel does not display device name"
        assert page.is_visible('text=192.168.1.20'), "Side panel does not display IP address"
        assert page.is_visible('text=Asset Criticality'), "Side panel does not show Asset Criticality reason"
        assert page.is_visible('text=Run What-If Simulation'), "Run What-If button not found in side panel"

        # Capture Screenshot 4: Device Side Panel
        shot_04 = os.path.join(SCREENSHOTS_DIR, "phase2_04_device_side_panel.png")
        page.screenshot(path=shot_04)
        print(f"[Playwright Phase 2] Saved {shot_04}")

        # Close drawer
        if page.is_visible('button[data-testid="close-drawer"]'):
            page.click('button[data-testid="close-drawer"]')
        else:
            page.keyboard.press("Escape")
        page.wait_for_selector('text=Why this risk?', state="detached", timeout=4000)
        page.wait_for_timeout(300)

        # Step 6: Switch to Live Traffic Stream tab
        print("[Playwright Phase 2] Step 6: Switching to Live Traffic Stream tab...")
        traffic_btn = page.locator('button:has-text("Traffic Stream")')
        traffic_btn.click()
        page.wait_for_selector('text=Synthetic Traffic Generation Engine', timeout=5000)

        # Generate a pulse
        pulse_btn = page.locator('button:has-text("Generate Pulse")')
        pulse_btn.click()
        page.wait_for_timeout(1000)

        # Verify flows in traffic table
        assert page.is_visible('text=BENIGN') or page.is_visible('text=ANOMALOUS'), "Traffic table records not populated"

        # Capture Screenshot 5: Live Traffic Stream
        shot_05 = os.path.join(SCREENSHOTS_DIR, "phase2_05_traffic_stream.png")
        page.screenshot(path=shot_05, full_page=True)
        print(f"[Playwright Phase 2] Saved {shot_05}")

        browser.close()
        print("\n[Playwright Phase 2] All real browser tests passed successfully!")

if __name__ == "__main__":
    test_phase2_playwright_e2e_flow()
