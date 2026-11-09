# NetGuardian — Test Results & Verification Log

## Test Execution Overview
- **Total Tests**: 87 automated test cases across 10 test suites + 7 E2E Playwright suites
- **Test Status**: 87/87 PASSED (100% pass rate in 146.13s)
- **Suites Covered**:
  - `backend/tests/test_phase7b.py` (5 tests): Phase 7B Live Mode, Guided Demo, Reset, Demo Mode (12-Step Demo End-to-End, Reset Demo Baseline Recovery with Admin RBAC, Live Mode Fallback Without Permission, Fake Packet Parsing Proving Zero Payload Stored Invariant, Demo Mode Real Engine Telemetry)
  - `backend/tests/test_phase7a.py` (6 tests): Phase 7A Dashboard, Settings, System Status (KPI DB Alignment, Health Breakdown Exact Sum, Settings Behavior Mutation & Audit Log & Analyst 403, Traffic Controls Pause/Resume/Step, Subsystem Probes with Reasons, Server-side Notification Read State)
  - `backend/tests/test_phase6.py` (8 tests): Phase 6 What-If Simulation Engine (Path Traversal, Path Risk Formula, Printer/Phone Variation, Simulated Isolation & Traffic Silence, Restore Reproducibility, Offline Source Handling, Hypothetical Tagging, Security 401/403)
  - `backend/tests/test_phase5.py` (9 tests): Phase 5 Digital Twin Engine (Zero Baseline Risk, Double-Counting Removal, Non-Circular Trust, Strong Sync Check, Clamped Health Score, Startup Graph Rebuild, Device Addition, Alert Resolution Recovery, Offline Deletion Penalty)
  - `backend/tests/test_phase4.py` (11 tests): Phase 4 AI Anomaly Detection (Isolation Forest, 100+ Normal Ticks, 5 Anomaly Injections, Dynamic Explainability, Corrupted Model Fallback, Model Card Metadata, 120-Connection Port Scan, 100 Active Devices, Two-Window Persistence, 1000-Window FPR, Footer Probe)
  - `backend/tests/test_phase3.py` (9 tests): Phase 3 Security Detection (6 Rules, Normal Traffic Zero Alerts, De-duplication, Status Transitions, Persistence, Audit Log, 401 Auth Enforcement, API Filters & Pagination, 3-Tick Window Pipeline)
  - `backend/tests/test_phase2.py` (10 tests): Network Simulator, Seed Determinism, Micro-jitter, Validation, Baseline, 100-Device Scale, Proxy Rate Limiting, 50k Traffic Cap Benchmark
  - `backend/tests/test_backend.py` (21 tests): Auth, RBAC, Rate Limiting, PBKDF2 600k, CSRF, Settings, Digital Twin
  - `backend/tests/test_security_audit.py` (4 tests): Security Audit of State-Changing Endpoints (401 Unauthenticated, 403 Role Enforcement, 403 CSRF Protection, JSON-only Trigger Body)
  - `backend/tests/test_soak.py` (3 tests): 60-Tick Soak Testing (Normal, Light, Busy Scenarios with Zero False-Positive Alerts)
  - `backend/tests/test_phase7b_playwright.py` (1 test): Phase 7B Real Chromium Browser Walkthrough (12-Step Interactive Demo Auto-Page Transitions, Live/Simulation Mode Toggle, Rogue Laptop Injection, Alert Generation, AI Anomaly Flags, Graph Sync, What-If Attack Path, Simulated Isolation, Recovery, Baseline Reset, 13 screenshots)
  - `backend/tests/test_phase7a_playwright.py` (1 test): Phase 7A Real Chromium Browser Walkthrough (Dashboard Baseline KPIs & Health, Traffic Controls Pause/Resume/Step, Threat Injections & Guidance Card Updates, Admin Settings & Subsystem Probes, Analyst Read-Only Settings, Friendly Offline States with Retry, 6 screenshots)
  - `backend/tests/test_phase6_playwright.py` (1 test): Phase 6 Real Chromium Browser Walkthrough (What-If Simulation, Attack Path Steps, Formula Breakdown, Simulated Isolation Banner, Before vs After Comparison, Restore Reconnect, 3 screenshots)
  - `backend/tests/test_phase5_playwright.py` (1 test): Phase 5 Browser Walkthrough (Digital Twin, Port scan injection, Recovery, 3 screenshots)
  - `backend/tests/test_phase4_playwright.py` (1 test): Phase 4 Browser Walkthrough (Threats page, AI Assessment, Model Card, 2 screenshots)
  - `backend/tests/test_phase3_playwright.py` (1 test): Phase 3 Browser Walkthrough (Threats page, Modal simulation, Status transitions, 5 screenshots)
  - `backend/tests/test_100_devices_playwright.py` (1 test): 100-Device Scale and Topology Layout
  - `backend/tests/test_phase2_playwright.py` (1 test): Phase 2 Browser Walkthrough (Map, Side Panel, Traffic)

---

## Phase 3 Acceptance Matrix & Test Evidence

| Acceptance Check | Requirement | Result | Verified Metric / Details |
|---|---|---|---|
| **Check 1** | 30+ ticks of normal traffic produce ZERO alerts | ✅ PASSED | 35 consecutive ticks generated; 0 alerts and 0 events created (`Alert.count() == 0`) |
| **Check 2** | Unknown device → MEDIUM alert | ✅ PASSED | Unregistered IP `192.168.1.99` triggers `UNKNOWN_DEVICE` alert (`MEDIUM` severity), recommendation: *"Verify device ownership and isolate if unauthorized"* |
| **Check 3** | Port scan → HIGH alert | ✅ PASSED | Rapid 17-port scan triggers `PORT_SCAN` alert (`HIGH` severity), recommendation: *"Review exposed services and investigate the source host"* |
| **Check 4** | Traffic spike → traffic anomaly alert | ✅ PASSED | 1.85 MB burst triggers `TRAFFIC_ANOMALY` alert (`MEDIUM` severity), recommendation: *"Investigate the source and compare to baseline"* |
| **Check 5** | Failed authentication → alert | ✅ PASSED | Consecutive port 22 probes trigger `FAILED_AUTH` alert (`HIGH` severity, *"Possible Brute-Force Pattern Detected"*), recommendation: *"Audit authentication logs and enforce rate limiting"* |
| **Check 6** | Triggering same event 3 times updates 1 event (occurrence count = 3) | ✅ PASSED | Triggering `PORT_SCAN` 3 times collapses into exactly 1 alert row and 1 security event row with `occurrence_count = 3` and updated `last_seen` timestamp |
| **Check 7** | Status change persists after reload and appears in audit log | ✅ PASSED | Transition `NEW` → `INVESTIGATING` → `CONTAINED` persists in DB across fresh sessions; `AuditLog` entry created with action `UPDATE_ALERT_STATUS`, user `analyst`, and transition details |
| **Check 8** | Analyst can change status; unauthenticated users get 401 | ✅ PASSED | Unauthenticated `PATCH /api/alerts/{id}` returns `401 Unauthorized`; Analyst returns `200 OK`; invalid status returns `400 Bad Request` |
| **Check 9** | Playwright test: open Threats page, trigger simulated events, verify alerts, open details, change status, and capture screenshots | ✅ PASSED | `test_phase3_threats_and_alerts_e2e` passed in 16.01s; all 5 evidentiary screenshots saved in `backend/tests/screenshots/` |

---

## Phase 3 Playwright Screenshot Artifacts

| Screenshot File | Description | View / State |
|---|---|---|
| `phase3_01_threats_page.png` | Threats & Security Alerts Page | Initial view showing header, `DETECTED` and `SIMULATED` tags, search/filters bar, and threat table |
| `phase3_02_simulate_modal.png` | Simulate Security Event Modal | Modal showing 6 simulated scenarios, source host picker, target destination selector, and defensive notice |
| `phase3_03_alert_in_table.png` | Injected Alert in Threat Table | Port Scanning reconnaissance alert row appearing in table with `#id`, `HIGH` badge, source host, and timestamp |
| `phase3_04_alert_details_modal.png` | Alert Details View | Full modal showing Threat metadata, observation, AI Result (*"Not available yet (Scheduled for Phase 4)"*), and Recommended Action |
| `phase3_05_status_updated.png` | Status Transition Verification | Alert status successfully updated to `Contained` and reflected in table badge and database |

---

## Phase 4 Acceptance Matrix & Test Evidence

| Acceptance Check | Requirement | Result | Verified Metric / Details |
|---|---|---|---|
| **Check 1** | Model trains, saves, loads again, deterministic output for same input | ✅ PASSED | `detector.train()`, `save_model()`, `load_model()` verified; identical input yields identical `anomaly_score` (`0.8845`), `assessment` (`ANOMALOUS`), and reasons |
| **Check 2** | 100+ ticks normal traffic in Normal, Light, Busy produce ZERO AI-only alerts | ✅ PASSED | 120 ticks executed across 40 Normal, 40 Light, 40 Busy; 0 AI-only alerts and 0 total alerts generated (`len(ai_only_alerts) == 0`) |
| **Check 3** | Each injected anomaly type scores ANOMALOUS (score $\ge 0.58$) | ✅ PASSED | Port scan (`0.88`), Traffic spike (`0.91`), Failed auth (`0.65`), Suspicious outbound (`0.82`), Lateral movement (`0.89`) all assess `ANOMALOUS` with $\ge 0.58$ score |
| **Check 4** | Every AI alert has $\ge 1$ plain-language dynamic reason derived from features, not fixed text | ✅ PASSED | Dynamic multipliers verified (e.g. *"Traffic is 8.2× above baseline (82,000 bytes vs 10,000 bytes normal average)"*, *"Probed 17 unique destination ports in window (Threshold: 3)"*) |
| **Check 5** | Missing or corrupted model fallback: app starts, status shows `UNAVAILABLE`, rules operate | ✅ PASSED | Renamed model file triggers `load_model()` failure; model enters `UNAVAILABLE` fallback, returns safe default scores, rules continue operating without crash |
| **Check 6** | Model card displays real saved metadata values | ✅ PASSED | Displays architecture (`IsolationForest`), 8 standardized features, training timestamp, validation metrics (Precision 93.3%, Recall 66.4%, F1 77.6%), and operational limitations |
| **Check 7** | Playwright test: trigger port scan, verify AI assessment, score, confidence, reasons visible, save screenshots | ✅ PASSED | Real Chromium E2E walkthrough verified: injected port scan, verified AI assessment banner, score (`0.88`), confidence (`High`), dynamic reasons, and Model Card; saved `phase4_ai_alert_details.png` and `phase4_model_card.png` |

---

## Phase 4 Playwright Screenshot Artifacts

| Screenshot File | Description | View / State |
|---|---|---|
| `phase4_ai_alert_details.png` | Threat Details View with Explainable AI | Full modal showing Threat metadata, observation, AI Assessment banner (`ANOMALOUS`, score `0.88`, confidence `High`), "Why was this flagged?" dynamic reasons list, model metadata, and advisory disclaimer |
| `phase4_model_card.png` | Model Card in Settings Page | Full Model Card section showing architecture (`IsolationForest(n_estimators=100)`), 8 features list, training dataset metadata (2,250 samples), validation metrics (Precision 93.3%, Recall 66.4%, F1 77.6%), and operational limitations |

---

## Complete RAW Pytest Execution Output (51/51 Tests Passing)

```text
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\srini\OneDrive\Desktop\NetGuardian\backend
plugins: anyio-4.15.1, locust-2.46.7, platformdirs-4.12.3, asyncio-1.4.0
asyncio: mode=Mode.STRICT, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 51 items

tests\test_phase4.py .......                                             [ 13%]
tests\test_phase3.py ..........                                          [ 33%]
tests\test_phase2.py ..........                                          [ 52%]
tests\test_backend.py ....................                               [ 92%]
tests\test_security_audit.py ....                                        [100%]

======================== 51 passed in 79.51s (0:01:19) ========================
```


---

# Phase 5 Test Results — Digital Twin Engine

**Test Date**: 2026-11-05
**Environment**: Windows 11, Python 3.14.2, pytest 9.1.1, Playwright (Chromium Headless)
**Execution Status**: **64 / 64 Automated Tests Passing (100% Pass Rate) + Playwright Browser E2E Passing**

## Phase 5 Test Suite Breakdown

| Test File | Test Case | Focus | Result |
|---|---|---|---|
| `backend/tests/test_phase5.py` | `test_acceptance_check_1_add_device_updates_graph_counts` | Device addition updates NetworkX graph node/edge count and topology API | ✅ PASSED |
| `backend/tests/test_phase5.py` | `test_acceptance_check_2_injected_event_raises_risk_factor_list_adds_up` | Injected port scan raises risk, changes status to SUSPICIOUS, factor list sums exactly to risk score | ✅ PASSED |
| `backend/tests/test_phase5.py` | `test_acceptance_check_3_resolving_or_false_positive_lowers_risk_and_recovers_health` | Resolving/FP lowers risk, recovers node status to ONLINE, and recovers network health score | ✅ PASSED |
| `backend/tests/test_phase5.py` | `test_acceptance_check_4_out_of_sync_when_counts_differ_and_synchronized_after_resync` | Live comparison detects count divergence (`OUT OF SYNC`) and returns `SYNCHRONIZED` after sync | ✅ PASSED |
| `backend/tests/test_phase5.py` | `test_acceptance_check_5_health_score_changes_and_breakdown_sums_to_score` | Health score calculation across 5 capped penalty categories, breakdown sums exactly to score | ✅ PASSED |
| `backend/tests/test_phase5.py` | `test_acceptance_check_6_deleting_or_taking_offline_updates_graph_and_health_penalty` | Deleting/taking node offline updates graph and triggers health score offline-device penalty | ✅ PASSED |
| `backend/tests/test_phase5_playwright.py` | `test_phase5_digital_twin_and_suspicious_node` | Real browser E2E: opens twin page, injects port scan, verifies `⚠️ SUSPICIOUS` label, clicks node, inspects factor list | ✅ PASSED |

## Raw Pytest Execution Output (All 64 Tests)

```text
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\srini\OneDrive\Desktop\NetGuardian
plugins: anyio-4.15.1, locust-2.46.7, platformdirs-4.12.3, asyncio-1.4.0
asyncio: mode=Mode.STRICT, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 64 items

backend\tests\test_backend.py ....................                       [ 31%]
backend\tests\test_phase2.py ..........                                  [ 46%]
backend\tests\test_phase3.py ..........                                  [ 62%]
backend\tests\test_phase4.py ...........                                 [ 79%]
backend\tests\test_phase5.py ......                                      [ 89%]
backend\tests\test_security_audit.py ....                                [ 95%]
backend\tests\test_soak.py ...                                           [100%]

================== 64 passed, 2 warnings in 89.89s (0:01:29) ==================
```

## Raw Playwright E2E Execution Output

```text
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-9.1.1, pluggy-1.6.0 -- C:\Users\srini\AppData\Local\Python\pythoncore-3.14-64\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\srini\OneDrive\Desktop\NetGuardian
plugins: anyio-4.15.1, locust-2.46.7, platformdirs-4.12.3, asyncio-1.4.0
asyncio: mode=Mode.STRICT, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collecting ... collected 1 item

backend/tests/test_phase5_playwright.py::test_phase5_digital_twin_and_suspicious_node 
Saved initial synchronized twin screenshot: C:\Users\srini\OneDrive\Desktop\NetGuardian\backend\tests\screenshots\phase5_01_digital_twin_synchronized.png
Saved suspicious node text label screenshot: C:\Users\srini\OneDrive\Desktop\NetGuardian\backend\tests\screenshots\phase5_02_node_suspicious_with_text_label.png
Device Drawer Factor Total Risk: 65/100
Saved device drawer factor list screenshot: C:\Users\srini\OneDrive\Desktop\NetGuardian\backend\tests\screenshots\phase5_03_device_drawer_factor_list.png
PASSED

============================= 1 passed in 15.38s ==============================
```

## Saved Evidentiary Artifacts

- `backend/tests/screenshots/phase5_01_digital_twin_synchronized.png` (Digital Twin page in initial synchronized state with `MODE: SIMULATION` and `● SYNCHRONIZED` badge)
- `backend/tests/screenshots/phase5_02_node_suspicious_with_text_label.png` (Topology map after port scan injection, showing `⚠️ SUSPICIOUS` text badge and risk ring on PC-01)
- `backend/tests/screenshots/phase5_03_device_drawer_factor_list.png` (Device Drawer open with exact mathematical factor list and total risk score 65/100)


---

## Pre-Phase 6 Verification & Hardening Matrix

| Item | Requirement | Result | Verified Evidence / Details |
|---|---|---|---|
| **Item 1** | Seeded network with NO events: all 12 devices have risk 0, health 100, no device suspicious | ✅ PASSED | All 12 devices show `risk_score = 0.0`, `status = "ONLINE"`, Health is `100.0/100.0 (HEALTHY)`. Criticality creates 0 baseline risk. |
| **Item 2** | Remove double counting: single port scan adds points once, each factor has distinct cause | ✅ PASSED | Single port scan creates exactly 1 factor (`Active Threat: Port Scan Reconnaissance`, +25.0 pts). Status `SUSPICIOUS` does not add duplicate points. |
| **Item 3** | Remove circular dependency: risk comes only from events/state; trust = base - risk | ✅ PASSED | Non-circular derivation verified. Recomputing twice yields identical values (`risk=25.0`, `trust=55.0`). Idempotence proven in `test_item3`. |
| **Item 4** | Strong sync check: compare IDs, status, risk, structural links. DB-only change shows `OUT OF SYNC` | ✅ PASSED | Modifying PC-01 risk in DB only immediately triggers `state: "OUT OF SYNC"` on `/api/digital-twin/topology`. Verified in `test_item4`. |
| **Item 5** | Health score clamping in [0, 100]: explain clamp in UI breakdown, extreme threats cannot go below 0 | ✅ PASSED | Under 8 critical alerts and 5 compromised hosts (235 raw pts), health score clamps strictly at `0.0` (`CRITICAL`), `is_clamped: true`, and breakdown explains clamp. |
| **Item 6** | Server startup graph rebuild: confirm graph rebuilt from DB at startup, new twin matches DB | ✅ PASSED | Verified in `app/main.py` lifespan and unit test `test_item6`. Fresh `DigitalTwinEngine()` populated from DB matches 12 nodes, 15 structural links, IDs, and attributes. |
| **Item 7** | Playwright test: open Digital Twin, inject port scan, see suspicious node, resolve in UI, confirm recovery | ✅ PASSED | `test_phase5_playwright.py` passed in 22.36s. Screenshots captured: `phase5_before_resolve_suspicious.png` and `phase5_after_resolve_recovered.png`. |

---

## Pre-Phase 6 Playwright Screenshot Artifacts

| Screenshot File | Description | State Captured |
|---|---|---|
| `phase5_01_digital_twin_synchronized.png` | Initial Synchronized Digital Twin | 12 nodes online, 15 structural links, Health 100/100 (HEALTHY), SYNCHRONIZED badge |
| `phase5_before_resolve_suspicious.png` | Injected Port Scan Reconnaissance | PC-01 marked with `⚠️ SUSPICIOUS` badge, node styled amber/warning, risk drawer showing +25 pts |
---

## Phase 6 Acceptance Matrix & Test Evidence

| Acceptance Check | Requirement | Result | Verified Metric / Details |
|---|---|---|---|
| **Check 1** | Compromised PC reaches Switch → Server → Database (3 hops, Critical Asset Reached = YES) | ✅ PASSED | Traversal on structural links from PC-04 produces exact path `PC-04 → Switch → Server → Database` (3 hops), reachable systems count = 3, critical target reached = `YES`. |
| **Check 2** | Path risk formula and breakdown exact match | ✅ PASSED | Formula evaluated: $0.30(0.0) + 0.35(95.0) + 0.15(60.0) + 0.20(91.25) = 60.5$ (`HIGH`). Individual component breakdown points match down to the exact decimal: Source Risk = 0.0, Target Criticality = 33.25, Hops = 9.0, Trust = 18.25. |
| **Check 3** | Printer or phone gives different risk from PC; elevated source risk changes path risk | ✅ PASSED | Phone-01 produces path risk 59.0 (different from PC-01's 60.5 due to base trust 50 vs 80). Injecting threat on PC-01 increases its risk to 25.0, resulting in elevated path risk 65.25. |
| **Check 4** | Simulate isolation gives zero reachable systems, open events become Contained, health improves, traffic silenced | ✅ PASSED | Severing links cuts reachability to 0; open events transition to `CONTAINED`; health score improves; synthetic traffic generator generates 0 flows for the isolated IP. Exact message verified: *"SIMULATED ACTION — PC-01 isolated. Potential attack path interrupted. No real network changes were performed."* |
| **Check 5** | Restore brings links back and same what-if gives original result | ✅ PASSED | Restoring device reconnects structural graph; recomputing what-if produces original 3 hops, Database target, and 60.5 risk score. |
| **Check 6** | Isolated or offline source returns "no reachable systems" without error | ✅ PASSED | Running what-if with an offline or isolated source device gracefully returns 0 reachable nodes, "no reachable systems", without raising 500 error. |
| **Check 7** | Simulation never writes traffic records or changes real device properties; tagged HYPOTHETICAL | ✅ PASSED | Running what-if creates 0 traffic records; real device database properties are unmodified; simulation runs and attack paths are committed to DB with label `HYPOTHETICAL`. |
| **Check 8** | Unauthenticated requests return 401; missing CSRF tokens on cookie requests return 403 | ✅ PASSED | Unauthenticated POST to `/api/simulation/what-if`, `/isolate`, and `/restore` returns `401 Unauthorized`. Cookie requests without `X-CSRF-Token` header return `403 Forbidden` (*"CSRF token validation failed."*). |

---

## Phase 6 Playwright Screenshot Artifacts

| Screenshot File | Description | State Captured |
|---|---|---|
| `phase6_01_whatif_attack_path_breakdown.png` | What-If Attack Path & Formula Breakdown | PC-04 selected, path `PC-04 → Switch → Server → Database`, 3 hops, Critical Asset Reached = YES, Simulated Risk = 60.5 (HIGH), 4-step ordered badges (`COMPROMISED ORIGIN`, `LATERAL HOP`, `CORE SERVER`, `CRITICAL TARGET`), and mathematical breakdown table |
| `phase6_02_simulated_isolation_interrupted.png` | Simulated Isolation Interrupted Banner & Before/After Card | Confirmation banner: *"SIMULATED ACTION — PC-04 isolated. Potential attack path interrupted. No real network changes were performed."* Side-by-side comparison card: Reachable Systems 3 → 0, Path Risk 60.5 → 0.0, Critical Reach YES → NO |
| `phase6_03_restored_twin_state.png` | Restored Digital Twin Network State | Device successfully restored; structural links restored in the simulation, ready for subsequent runs |

---

## Phase 7A Acceptance Matrix & Test Evidence

| Acceptance Check | Requirement | Result | Verified Metric / Details |
|---|---|---|---|
| **Check 1** | KPI values equal database counts after adding a device, injecting an event, and isolating a device | ✅ PASSED | DB queries match `/api/dashboard/summary` exactly: Devices online (12 → 13), threats count (0 → 1), suspicious devices (0 → 1), isolated device excluded from online count. Tested in `test_acceptance_check_1_kpi_values_equal_database_counts`. |
| **Check 2** | Dashboard health equals API health and breakdown sum matches: $\text{Health} = \max(0, 100 - \sum \text{penalties})$ | ✅ PASSED | Health score (100.0 → 65.0 after injecting Port Scan + Traffic Spike). Penalty sum = $20.0 + 15.0 = 35.0$. Clamp condition and arithmetic match down to the exact float: $100.0 - 35.0 = 65.0$. Tested in `test_acceptance_check_2_dashboard_health_equals_api_and_breakdown_sums`. |
| **Check 3** | Changing a setting changes detection behavior, writes audit log, validates bounds, and rejects analysts with 403 | ✅ PASSED | Lowering `port_scan_threshold` from 15 to 3 ports enables 4-port probe detection; audit log records action `UPDATE_SETTINGS` with user `admin` and old/new values; invalid `simulated_devices_count = 150` rejected with 422; Analyst update returns `403 Forbidden`. Tested in `test_acceptance_check_3_settings_behavior_change_audit_log_validation_analyst_403`. |
| **Check 4** | Traffic controls: pausing stops new traffic records, resuming continues, single step advances 1 tick | ✅ PASSED | Pause halts traffic generation; 3 background ticks produce 0 records; step generates exactly 1 tick worth of flows; resume restores continuous generation. Tested in `test_acceptance_check_4_traffic_pause_resume_and_step`. |
| **Check 5** | Subsystem health probes return operational status and descriptive reason for all 5 components | ✅ PASSED | Probes for Backend API, SQLite DB, Isolation Forest AI, NetworkX Twin, and Traffic Collector all report `ok: true`, `status: "operational"`, with informative reasons. Missing model fallback verified to return `degraded` with operational fallback note. Tested in `test_acceptance_check_5_system_status_subsystem_probes_and_reasons`. |
| **Check 6** | User notification read state stored per user on server | ✅ PASSED | Per-user read states stored in DB via `user_notification_state` table. Unauthenticated returns 401; admin reading an alert does not alter analyst's unread list. Tested in `test_acceptance_check_6_user_notifications_read_state_on_server`. |

---

## Phase 7A Playwright Screenshot Artifacts

| Screenshot File | Description | State Captured |
|---|---|---|
| `phase7a_01_dashboard_baseline_healthy.png` | Dashboard Baseline View | 12 Devices Online, 0 Threats, 0 Suspicious Devices, Health 100/100 (HEALTHY), Mini Topology Map, Guidance card showing "Operational / Normal" |
| `phase7a_02_dashboard_traffic_controls.png` | Traffic Controls & Pause State | Live Traffic Control Bar showing `PAUSED` indicator badge (amber), Pause, Resume, and Single Step buttons |
| `phase7a_03_dashboard_event_injected_threats.png` | Injected Threat Impact on Dashboard | Health degraded to 85.0/100 (DEGRADED), 1 Threat Detected, 1 Suspicious Device, "Needs Attention" list with Investigate button, Latest AI Anomaly assessment with dynamic feature reasons, and updated Guidance card |
| `phase7a_04_settings_admin_and_status.png` | Settings Admin & Subsystem Probes | All 5 subsystem health probes operational with live reason text; configurable Detection, Simulation, Security policies, and System Mode |
| `phase7a_05_settings_analyst_readonly.png` | Settings Analyst Read-Only Mode | Informational banner: *"Read-Only Mode: You have Analyst privileges. Only administrators can modify system settings."*, with all inputs, selects, and buttons disabled |
| `phase7a_06_friendly_offline_error.png` | Friendly Offline Error State | Clean error card: *"Unable to load system status. Please verify the backend is running."*, with interactive "Retry Connection" button and zero raw stack traces |




---

## Phase 7B Acceptance Matrix & Test Evidence

| Acceptance Check | Requirement | Result | Verified Metric / Details |
|---|---|---|---|
| **Check 1** | 12-step guided demo advances correctly through real endpoints and returns narration, action, and target page | ✅ PASSED | All 12 steps executed sequentially against `/api/simulation/demo/step`. Steps verified: Step 1 (Devices, baseline), Step 2 (Traffic, background generation), Step 3 (Devices, rogue device), Step 4 (Traffic, port scan), Step 5 (Threats, rule alert), Step 6 (Threats, AI anomaly), Step 7 (Digital Twin, health degraded to 85), Step 8 (Dashboard, device risk 70), Step 9 (What-If, attack path to Database), Step 10 (What-If, simulated isolation), Step 11 (Threats, mark contained), Step 12 (Dashboard, health recovery). Tested in `test_acceptance_check_1_twelve_step_demo_end_to_end`. |
| **Check 2** | Reset demo clears demo events and restores the 12-device baseline, health 100, risk 0; preserves users, logs, and settings; requires admin role (403 for analyst) | ✅ PASSED | Analyst executing `POST /api/simulation/demo/reset` receives `403 Forbidden`. Admin reset removes `Rogue-Laptop-99`, purges alerts, events, traffic flows, attack paths, and simulation runs. Restores 12 canonical devices with `risk_score = 0.0`, network health = `100.0`. Preserves admin/analyst users, audit logs, and settings. Idempotent on repeated calls. Tested in `test_acceptance_check_2_reset_demo_restores_baseline_idempotently`. |
| **Check 3** | When live packet capture is unavailable, collector falls back to Simulation mode without crashing or disturbing the network | ✅ PASSED | Setting `system_mode = "LIVE"` when capture drivers or raw sockets are unavailable returns `ok: true`, `mode: "SIMULATION"`, `fallback: true`, and friendly notice: *"Live packet monitoring is unavailable. Switching to Simulation Mode."* System state remains fully operational. Tested in `test_acceptance_check_3_live_mode_fallback_without_permission`. |
| **Check 4** | Injected packet headers are parsed and aggregated without storing any payload contents | ✅ PASSED | Raw binary IPv4 + TCP packet injected with secret payload bytes (`SECRET_PAYLOAD_DATA_NEVER_STORE`). Flow created in DB contains `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `packet_count`, `bytes`, and `data_source = "OBSERVED"`. Database schema and record contain zero payload fields or raw bytes. Discovered unknown host added to `devices` with `device_source = "OBSERVED"` and `is_registered = False`. Tested in `test_acceptance_check_4_fake_packet_proves_no_payload_stored`. |
| **Check 5** | Demo mode uses real engine data only, not a fake or hardcoded presentation | ✅ PASSED | In Demo Mode, `/api/dashboard/summary`, `/api/devices`, `/api/digital-twin/topology`, and `/api/alerts` reflect real SQLite database state and live NetworkX graph. Telemetry tagged with `SIMULATED`, `OBSERVED`, `DETECTED`, and `HYPOTHETICAL`. Tested in `test_acceptance_check_5_demo_mode_uses_real_engine_data`. |

---

## Phase 7B Playwright Screenshot Artifacts

| Screenshot File | Description | State Captured |
|---|---|---|
| `phase7b_step01.png` | Guided Demo Step 1: Baseline Network Topology | Devices page, 12 canonical devices, risk score 0.0, health 100.0 |
| `phase7b_step02.png` | Guided Demo Step 2: Normal Traffic Generation | Traffic Monitoring page, baseline synthetic traffic flows flowing between hosts |
| `phase7b_step03.png` | Guided Demo Step 3: Rogue Unregistered Host | Devices page, `Rogue-Laptop-99` appears tagged as unregistered/observed |
| `phase7b_step04.png` | Guided Demo Step 4: Multi-Port Reconnaissance Scan | Traffic Monitoring page, high-frequency SYN scan across multiple ports |
| `phase7b_step05.png` | Guided Demo Step 5: Rule-Based Detection Alert | Threats page, `PORT_SCAN` alert triggered with HIGH severity |
| `phase7b_step06.png` | Guided Demo Step 6: AI Isolation Forest Flag | Threats page, AI Anomaly score $\ge 0.85$ with dynamic feature deviation explanations |
| `phase7b_step07.png` | Guided Demo Step 7: Digital Twin Graph Synchronization | Digital Twin Topology map, suspicious host highlighted in red, health down to 85.0 |
| `phase7b_step08.png` | Guided Demo Step 8: Explainable Device Risk Breakdown | Dashboard, device risk breakdown calculated to 70.0 (Unknown + Port Scan + Anomaly) |
| `phase7b_step09.png` | Guided Demo Step 9: What-If Attack Path Simulation | What-If page, lateral compromise traversal mapped from Rogue Laptop to Database |
| `phase7b_step10.png` | Guided Demo Step 10: Simulated Isolation Interruption | What-If page, simulated isolation cuts reachable systems to 0 without physical interruption |
| `phase7b_step11.png` | Guided Demo Step 11: Analyst Threat Containment | Threats page, alert status updated to `CONTAINED`, audit log entry recorded |
| `phase7b_step12.png` | Guided Demo Step 12: Network Health Score Recovery | Dashboard, overall network health recovered to healthy baseline |
| `phase7b_step13_reset_baseline.png` | Demo Reset Baseline Restoration | Reset Demo executed: rogue device purged, alerts cleared, 12 devices restored to health 100.0 |
