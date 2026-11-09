# NetGuardian — Project Status

## Status Summary
- **Current Phase**: Phase 7B — Live Mode, Guided Demo, Reset, Demo Mode (Fully Implemented, Passive Metadata-Only Live Packet Collector with Zero Payload Storage, Automatic Driver/Permission Fallback, 12-Step Real-Engine Guided Demo with Multi-Page Navigation, Clean Baseline Reset with RBAC, High-Contrast Demo Presentation Mode, Passing 87/87 Pytest Suites + Real Playwright E2E with 13 Screenshots)
- **Design Standard**: Strictly Light Theme Only (white surfaces `#ffffff`/`#f8fafc`, slate borders `#e2e8f0`, dark text `#0f172a`, zero neon/glow)
- **Backend Status**: 87/87 Automated Pytest Suites Passing (100% success rate across 10 test suites)
- **E2E Browser Status**: Real Chromium Playwright E2E suites passing with all screenshots captured & preserved in `backend/tests/screenshots/` and artifacts directory
- **Frontend Status**: Production build verified (`vite build` succeeded with 0 errors)
- **Operational Mode**: MODE: SIMULATION / MODE: LIVE MONITORING visible across all views; all telemetry tagged SIMULATED, OBSERVED, DETECTED, and HYPOTHETICAL

---

## Phases Overview

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | Project Foundation (Directories, DB, Auth, RBAC, Rate Limiting, Light Theme Shell, Status Strip, Security Hardening) | ✅ Completed & Verified |
| **Phase 2** | Network Simulator (Deterministic Traffic, Documentation IPs, Hierarchical Map, Baseline Learning, Side Panel, 100-Device Scale, 50k Cap) | ✅ Completed & Verified |
| **Phase 3** | Security Detection Engine (Rule Engine, Events, Alerts, Severity, Recommendations, De-duplication, Status Audit) | ✅ Completed & Verified |
| **Phase 4** | AI / ML Anomaly Detection (Isolation Forest, 8-Feature Vector, Dynamic Explainability, Model Card, Missing Model Fallback) | ✅ Completed & Verified |
| **Phase 5** | Digital Twin Engine (NetworkX Graph, Bidirectional DB Sync, State & Risk Tracking, Structural vs Observed Links, Explainable Risk) | ✅ Completed & Verified |
| **Phase 6** | What-If Simulation Engine (Attack Path Traversal, Risk Formulas, Simulated Isolation & Restore, Before vs After Comparison, Run History) | ✅ Completed & Verified |
| **Phase 7A** | Dashboard, Settings, System Status (Real Engine Data, KPI Cards, Health Breakdown, Mini Topology, Needs Attention List, Latest AI Card, Guidance Card, Reliable Polling, Traffic Pause/Resume/Step Controls, Subsystem Probes with Reasons, Analyst Read-Only Settings, Server Notification State, Friendly Offline States) | ✅ Completed & Verified |
| **Phase 7B** | Live Mode, Guided Demo, Reset, Demo Mode (Metadata-Only Live Collector, Zero Payload Stored Invariant, Fallback to Simulation, 12-Step Guided Demo with Page Transitions, Demo Reset to Baseline, Demo Presentation Mode, Distinct Tags) | ✅ Completed & Verified |
| **Phase 8** | Reporting & Analytics (Recharts Light Theme, NetGuardian Security Report Export) | Pending |
| **Phase 9** | Automated Testing & Integration Verification (Backend pytest, E2E Flow, Build Verification) | Pending |
| **Phase 10** | Polish, Documentation & Viva Preparation (Academic Report, Diagrams, Guides, Slides) | Pending |

---

## Pre-Phase 3 Hardening & Refinement Deliverables
1. **Rate Limit IP Security & `TRUSTED_PROXIES`**:
   - `X-Forwarded-For` header is **not** trusted by default; rate limiting strictly tracks the real connection address (`request.client.host`).
   - `X-Forwarded-For` is only read when the connecting address matches `TRUSTED_PROXIES` (empty by default).
   - Verified that changing `X-Forwarded-For` on every request does not bypass the 5-attempt limit, and different real client IPs maintain independent rate-limiting buckets.
2. **De-duplicated Trust Levels vs. Criticality**:
   - Trust Level strictly represents device posture: `HIGH`, `MEDIUM`, `LOW`, `UNTRUSTED`.
   - Seeded values: Router (HIGH), Switch (HIGH), Server (HIGH), Database (HIGH), PC-01 to PC-04 (MEDIUM), Phone-01 (LOW), Printer (MEDIUM), IoT-Camera (LOW), Internet (UNTRUSTED).
   - Form, drawer, and device table updated to display Trust Level and Criticality as distinct dimensions.
3. **Canonical Spec Naming**:
   - Seeded network devices updated to exact spec: `Router`, `Switch`, `PC-01`, `PC-02`, `PC-03`, `PC-04`, `Phone-01`, `Printer`, `Server`, `Database`, `IoT-Camera`, `Internet`.
4. **100-Device Scalability & Overlap Elimination**:
   - Level 3 layout re-engineered with multi-column grid wrapping, dynamic dimensions, and density-aware node sizing.
   - Real browser Playwright test executed (`test_100_devices_playwright.py`):
     - API creation of 100 devices: **1,410.94 ms** (14.11 ms/device)
     - Network Page load time: **138.56 ms**
     - Topology Map render time: **108.57 ms**
     - Full-page screenshot saved at `backend/tests/screenshots/phase2_100_devices_map.png`.
5. **Configurable 50,000 Traffic Record Cap**:
   - Raised cap from 5,000 to 50,000 rows via `MAX_TRAFFIC_RECORDS` setting.
   - Benchmarked against 50,000 database rows:
     - `/api/traffic?limit=50`: **9.30 ms**
     - `/api/traffic (anomalies_only)`: **6.36 ms**
     - `/api/traffic/stats` aggregation: **43.20 ms**

---

## Phase 3 — Security Detection (Rules, Events, Alerts) Deliverables
1. **Rule Engine (Layer 1)**:
   - Dynamic thresholds loaded live from `system_settings` with config fallbacks:
     - `port_scan_threshold` (15 unique destination ports in 60s)
     - `traffic_anomaly_threshold` (3.0x multiplier / 500,000 bytes)
     - `failed_auth_threshold` (5 failed attempts on port 22 in 30s)
   - Evaluates 6 deterministic detection rules:
     - Rule 1: Unknown device joins network (`UNKNOWN_DEVICE`, MEDIUM)
     - Rule 2: Port scanning reconnaissance (`PORT_SCAN`, HIGH)
     - Rule 3: Traffic volume anomaly spike (`TRAFFIC_ANOMALY`, MEDIUM)
     - Rule 4: Repeated failed authentication (`FAILED_AUTH`, HIGH, "Possible Brute-Force Pattern Detected")
     - Rule 5: Suspicious outbound connection to C2 port (`SUSPICIOUS_OUTBOUND`, HIGH)
     - Rule 6: Unusual direct access to protected Database asset (`CRITICAL_ASSET_ACCESS`, CRITICAL)
2. **"Simulate Security Event" Modal with Source Device Picker**:
   - Implemented in `ThreatsPage.jsx` supporting all 6 scenarios with live source-device selector populated from network inventory.
   - Defensive synthetic injection: records metadata in SQLite and updates digital twin without real packets or socket calls.
3. **De-duplication & Occurrence Counters**:
   - Repeated events for the same open alert (`NEW` or `INVESTIGATING` with matching `event_type` and `source_device`) increment `occurrence_count` and update `last_seen` timestamp rather than creating duplicate entries.
4. **Lifecycle Status Management & Audit Trail**:
   - Supports statuses: `NEW`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE`.
   - Modifying status requires authentication (`ADMIN` or `ANALYST`); unauthenticated requests receive `401 Unauthorized`.
   - Every status mutation is permanently recorded in `audit_logs` table with username, client IP, timestamp, and details.
5. **Threats Page & Alert Details View**:
   - Tabular layout with Threat ID, Type, Source, Target, Severity, Confidence, Detected Time, and Status.
   - Full search, severity filter, status filter, event type filter, date filter, and pagination.
   - Alert Details modal shows metadata, observation description, AI Result explicitly marked: *"Not available yet (Scheduled for Phase 4)"*, and tailored defensive recommendations without automatic mutations.
6. **Notifications Panel**:
   - Bell icon with unread count badge.
   - Colored notifications with plain English text:
     - 🔴 High-risk device
     - 🟡 Traffic anomaly
     - 🟢 Simulation completed
   - "Mark as read" and "Mark all read" controls with local persistence.
7. **Automated Verification**:
   - `backend/tests/test_phase3.py`: 10/10 acceptance checks passing.
   - `backend/tests/test_phase3_playwright.py`: Real Chromium browser test passing with screenshots saved in `backend/tests/screenshots/phase3_*.png`.
   - Complete test suite: **41/41 passing in 36.56s**.

---

## Phase 4 — AI Anomaly Detection Deliverables
1. **Synthetic Training Dataset**:
   - Generated and persisted to `data/simulation/training_data.csv` (2,250 samples: 2,000 normal across 4 roles + 250 anomalous across 5 threat classes).
   - Documented disclaimer in header: *"Synthetic data is used for demonstration and does not represent a production-grade threat intelligence dataset."*
2. **Standardized 8-Feature Vector**:
   - Extracted per window: `packet_count`, `bytes`, `connection_count`, `connection_duration`, `unique_destination_ports`, `unique_destination_ips`, `failed_connections`, `traffic_rate`.
3. **Role-Based Isolation Forest (`RoleBasedAnomalyDetector`)**:
   - Role-specific models calibrated for `endpoint`, `server`, `iot`, `network`, and a global fallback model.
   - Outputs: `is_anomalous` (`NORMAL` vs `ANOMALOUS`), normalized `anomaly_score` ($0.0$ to $1.0$), `confidence` (`High`, `Medium`, `Low`), and dynamic reasons list.
   - Deterministic training seed (`42`) and model persistence in `data/models/isolation_forest.joblib` and `data/models/model_metadata.json`.
   - Strict advisory posture: never states *"definitely an attack"*; always qualifies that anomalies represent statistical deviations from baseline.
4. **Explainable AI (XAI) Attribution**:
   - Dynamic plain-language reason generator (`backend/app/ml/explainer.py`) computing real multipliers and deltas relative to learned role baselines (e.g. *"Traffic is 8.2× above baseline (82,000 bytes vs 10,000 bytes normal average)"*, *"Probed 17 unique destination ports in window (Threshold: 3)"*, *"Connection rate increased to 48.0 connections/sec"*).
5. **Two-Layer Detection Pipeline Integration**:
   - Merges deterministic rules (Layer 1) with Isolation Forest (Layer 2) producing badges: `RULE`, `AI`, and `RULE+AI`.
   - AI-only alerts require high score ($\ge 0.75$) and 2 consecutive 3-tick evaluation windows before alert escalation.
6. **Graceful Fallback & Model Card in UI**:
   - Missing/corrupted model fallback: status shows `UNAVAILABLE`, rules continue uninterrupted.
   - Model Card on Settings page: displays architecture (`IsolationForest(n_estimators=100)`), 8 features, training timestamp, synthetic validation metrics (Precision 93.3%, Recall 66.4%, F1 77.6%), and operational limitations.
   - Threat Details modal: displays AI Assessment banner, anomaly score, confidence, dynamic reasons, model metadata, and advisory disclaimer.
7. **Automated Verification**:
   - `backend/tests/test_phase4.py`: 7/7 acceptance checks passing.
   - `backend/tests/test_phase4_playwright.py`: Real Chromium browser test passing with screenshots saved in `backend/tests/screenshots/phase4_ai_alert_details.png` and `backend/tests/screenshots/phase4_model_card.png`.
   - Full test suite: **51/51 passing in 79.51s** (100% success rate).


---

## Phase 5 — Digital Twin Engine Deliverables

1. **Living NetworkX Graph Model (`twin_engine.py`)**:
   - In-memory living graph where nodes represent devices (`id`, `name`, `ip`, `mac`, `type`, `os`, `status`, `criticality`, `trust_level`, `risk_score`, `trust_score`, `is_isolated`).
   - Edges differentiate:
     - **Structural Links** (`edge_type="structural"`, solid slate lines `#94a3b8`): Physical infrastructure links (Internet ↔ Router ↔ Switch ↔ all subnet devices; Server ↔ Database).
     - **Observed Communication Edges** (`edge_type="observed"`, dashed indigo lines `#6366f1`): Dynamic application flows recording protocol, destination port, bytes transferred, and trust level.
2. **Centralized 5-Step Synchronization Rule (`sync_state_on_change`)**:
   - Enforced on every device mutation, alert status update, and simulated event:
     1. Update database: recalculates affected device risk and trust; recovers status from `SUSPICIOUS` to `ONLINE` if active threats are resolved.
     2. Update graph: `digital_twin.sync_from_database(db)` updates in-memory graph nodes and edges.
     3. Update dashboard: recomputes network health score.
     4. Recalculate affected risk: factors updated and bounded.
     5. Record in audit log: logs action, user, timestamp, client IP, and transition details.
3. **Real-time Sync Status & Verification**:
   - Compares live database device counts with in-memory graph nodes (`check_sync_status(db)`).
   - If counts differ or unsynchronized: reports `⚠️ OUT OF SYNC`.
   - When synchronized: reports `● SYNCHRONIZED`.
4. **100% Explainable Device Risk Breakdown**:
   - Evaluates additive factors: Criticality Base Exposure, Node Status Modifier, Isolation Containment Credit (-20), Trust Level Deficit, and Active Unresolved Alerts.
   - Exact Normalization Cap: Guarantees that the sum of factor impacts $\sum \text{Impact}(F) \equiv \text{Risk Score}$ down to the exact decimal.
   - Trust score derives from $\max(0, \text{round}(\text{Base Trust} - \text{Risk Score}, 1))$.
5. **NetGuardian Network Health Score & Exact Penalties Breakdown**:
   - Evaluates 5 independently capped penalty categories:
     - Active Threats ($P_{\text{threats}}$, cap = 35)
     - Suspicious Devices ($P_{\text{suspicious}}$, cap = 25)
     - High-Risk Nodes ($P_{\text{high\_risk}}$, cap = 20)
     - Traffic Anomalies ($P_{\text{anomalies}}$, cap = 15)
     - Offline Devices ($P_{\text{offline}}$, cap = 15)
   - Guarantees: $\text{Health Score} + \sum \text{Penalties} \equiv 100.0$.
   - Categorical labels: `HEALTHY` ($\ge 85$), `NEEDS ATTENTION` ($70-84.9$), `AT RISK` ($50-69.9$), `CRITICAL` ($< 50$).
6. **Digital Twin UI & Topology Map Enhancements**:
   - Header with `MODE: SIMULATION` and `SIMULATED DATA` tags.
   - Dynamic real-time Sync Status Badge (`● SYNCHRONIZED` vs `⚠️ OUT OF SYNC`).
   - Suspicious nodes on topology map automatically display prominent text label badges (`⚠️ SUSPICIOUS` / `🚨 COMPROMISED`) in addition to warning/critical node colors and pulsing risk rings.
   - Topology legend showing distinct node states and Structural Links vs Observed Traffic.
   - Selected node panel showing Risk Level, Risk Score, Trust Score, Status, and `🎯 Run What-If Simulation` button.
7. **Automated Verification**:
   - `backend/tests/test_phase5.py`: 6/6 acceptance checks passing (device add count update, injected event risk summation, resolve/FP recovery, out-of-sync detection, health penalty sum, offline penalty).
   - `backend/tests/test_phase5_playwright.py`: Real Chromium browser test passing with screenshots saved in `backend/tests/screenshots/phase5_*.png`.
   - Complete test suite: **64/64 passing in 89.89s**.

---

## Phase 6 — What-If Simulation Engine Deliverables
1. **Graph Traversal & Non-Destructive Exploration**:
   - Traverses the NetworkX Digital Twin graph using structural links only (`edge_type == "structural"`).
   - Excludes offline nodes, isolated nodes, and the Internet WAN gateway.
   - Gracefully handles offline or isolated source nodes: returns 0 reachable systems, "no reachable systems", without raising errors.
2. **Result Payload & Actionable Guidance**:
   - Scenario text: `"{device} is hypothetically compromised"`.
   - Potential reach path display: e.g. `PC-04 → Switch → Server → Database`.
   - Reachable systems list, hop count, path length, and Critical Asset Reached (`YES` / `NO`).
   - Actionable Recommended Controls: Restrict unnecessary communication, Review trust relationships, Isolate the suspicious endpoint, Monitor server connections.
3. **NetGuardian Simulated Path Risk Formula**:
   - Exact mathematical formula documented in `docs/METHODOLOGY.md`:
     $$\text{Path Risk} = 0.30 \times R_{\text{source}} + 0.35 \times C_{\text{target}} + 0.15 \times H_{\text{proximity}} + 0.20 \times T_{\text{avg}}$$
   - Criticality Values: Low = 20, Medium = 45, High = 70, Critical = 95.
   - Hop Factor: $H = \max(0, 100 - 20 \times (\text{hops} - 1))$.
   - Categorical Risk Levels: `LOW` (<30), `MEDIUM` (30–54.9), `HIGH` (55–79.9), `CRITICAL` (≥80).
   - Baseline PC-04 reaching Database: $0.30(0.0) + 0.35(95.0) + 0.15(60.0) + 0.20(91.25) = 60.5$ (`HIGH`).
   - Prioritizes critical asset paths in graph traversal rankings.
4. **Attack-Path Visualization**:
   - Ordered step list with numbered nodes and role labels:
     - Step 1: `COMPROMISED ORIGIN`
     - Step 2: `LATERAL HOP`
     - Step 3: `CORE SERVER`
     - Step 4: `CRITICAL TARGET`
   - Formula breakdown table displaying individual point contributions and factor multipliers.
5. **Simulated Isolation & Network Reconnect**:
   - Severing links in the Digital Twin graph isolates the node, sets status to `ISOLATED`.
   - Transitions active security events and open alerts to `CONTAINED`.
   - Recalculates network health (health score recovers).
   - Silences synthetic traffic generation for the isolated IP.
   - Exact confirmation banner:
     `"SIMULATED ACTION — [device] isolated. Potential attack path interrupted. No real network changes were performed."`
   - Reconnect / Restore Device action restores twin links, updates DB status to `ONLINE`, recalculates health, and re-enables traffic.
   - Confirmation dialogs required before isolation and restoration actions.
6. **Before vs After Isolation Comparison**:
   - Side-by-side comparison cards:
     - Reachable Systems: 3 (Before) vs 0 (After, 100% Severance)
     - Simulated Path Risk: 60.5 (Before, HIGH) vs 0.0 (After, LOW)
     - Critical Asset Reached: YES (Before) vs NO (After)
7. **Hypothetical Persistence & History**:
   - Simulation runs persisted to DB and labeled `HYPOTHETICAL`.
   - Past runs accessible via `/api/simulation/runs` and `/api/simulation/history`.
8. **RBAC & Security Enforcements**:
   - `/api/simulation/what-if`, `/isolate`, and `/restore` require authentication (Analyst or Admin).
   - Cookie session requests enforce CSRF token validation via `X-CSRF-Token` header.
9. **Automated Verification**:
   - `backend/tests/test_phase6.py`: 8/8 acceptance checks passing (path reachability, formula exact match, phone/printer risk variation, isolation severance and traffic silence, restore reproducibility, offline/isolated source handling, hypothetical persistence, security 401/403).
   - `backend/tests/test_phase6_playwright.py`: Real Chromium browser test passing with screenshots:
     - `phase6_01_whatif_attack_path_breakdown.png`
     - `phase6_02_simulated_isolation_interrupted.png`
     - `phase6_03_restored_twin_state.png`
   - Complete test suite: **75/75 passing in 148.51s**.

---

## Phase 7A — Dashboard, Settings, System Status Deliverables
1. **Dashboard with Real Engine Data Only (Never Mock or Random)**:
   - **6 Live KPI Cards**:
     - Devices Online: exact count from database (`devices.status != 'OFFLINE'`).
     - Threats Detected: count of all security events from database.
     - Suspicious Devices: count of devices flagged suspicious or high risk ($R > 50$).
     - Packets Monitored: live sum of `packet_count` across all synthetic traffic records.
     - Active Connections: count of distinct IP pairs active in the current window.
     - High-Risk Devices: count of devices with risk score $\ge 70$.
   - **Network Health Bar & Breakdown**:
     - Displays exact health score ($H \in [0, 100]$), categorical badge (`HEALTHY`, `DEGRADED`, `CRITICAL`), and arithmetic penalty breakdown:
       $$\text{Health} = \max(0, 100 - \sum \text{penalties})$$
   - **Mini Topology Map**: Visual overview of network architecture and real-time state.
   - **"Needs Attention" Open Threats List**:
     - Shows active threats (`NEW` or `INVESTIGATING`) with severity badges and direct "Investigate" navigation buttons.
   - **Latest AI Results Card**:
     - Displays real ML evaluation: Anomaly Score (0.00–1.00), Confidence level (`HIGH`, `MEDIUM`, `LOW`), and dynamic "Why was this flagged?" reason statements derived from real traffic feature comparisons against baseline.
   - **"What Should I Do Next?" Guidance Card**:
     - Dynamically answers all 6 critical SOC operator questions:
       1. What is the network state? (Overall health and status summary)
       2. Are there open threats? (Active incident count and highest severity)
       3. Which device is suspicious? (Most suspicious host name and IP)
       4. What is the possible impact? (Target assets and reach assessment)
       5. What should I investigate? (Recommended triage action)
       6. Can I safely simulate it? (Direct link to What-If simulation engine)
2. **Reliable Polling**:
   - No UI flicker; tab visibility listener pauses interval requests when backgrounded via `document.addEventListener('visibilitychange')`.
   - Exponential backoff on errors (5s base, scaling up to 30s) prevents network spam during transient backend disconnections.
3. **Traffic Simulation Controls on Dashboard**:
   - Live status indicator: `RUNNING` (emerald) or `PAUSED` (amber).
   - Interactive controls:
     - **Pause**: Halts new synthetic traffic generation immediately.
     - **Resume**: Restores background traffic generation ticks.
     - **Single Step**: Advances simulation by exactly 1 tick while paused.
4. **Settings Page with RBAC & Audit Logging**:
   - **Analyst Read-Only Mode**: Analysts see informational banner, all inputs/toggles are disabled, and mutation requests return `403 Forbidden`.
   - **Admin Mutations**: Validated and persisted to `system_settings`; every change recorded in `audit_logs` with username, client IP, old/new values.
   - **Detection Settings**: Traffic anomaly multiplier, Port scan threshold, Failed auth attempts, Unknown device detection toggle.
   - **Simulation Settings**: Traffic generation rate (ms), Simulated devices count (10 to 100 with bounds validation), Simulation seed.
   - **Security Settings**: Session timeout (1–10080 min), Password minimum length ($\ge 8$), Require digit toggle.
   - **System Mode**: Simulation (active) / Live Monitoring (disabled with explicit label: *"Coming in Phase 7B"*).
5. **Subsystem Health Probes**:
   - Real-time probe results for all 5 subsystems:
     - **Backend API**: Operational (FastAPI runtime healthy)
     - **Database**: Operational (SQLite connection and schema verified)
     - **AI Engine**: Operational / Model loaded (`IsolationForest` active with 8 features)
     - **Digital Twin**: Operational (NetworkX synchronized with DB)
     - **Network Collector**: Operational (Synthetic generator active/paused)
   - Each probe includes dynamic operational reason and status indicator.
6. **Friendly Error States & Recovery**:
   - Full coverage across Dashboard, Devices, Threats, and Settings:
     `"Unable to load [resource]. Please verify the backend is running."`
   - Interactive "Retry Connection" button tests recovery without requiring full page refresh. Zero raw stack traces exposed.
7. **Server-Side Notification State**:
   - Per-user notification read states stored on the server via `user_notification_state` table.
   - Marking notifications read persists across devices and browser sessions.
8. **Automated Verification**:
   - `backend/tests/test_phase7a.py`: 6/6 acceptance tests passing (KPI DB alignment after add/event/isolate, health breakdown exact sum, settings behavior change + audit log + analyst 403, traffic pause/resume/step, subsystem probes with reasons, server per-user notification read state).
   - `backend/tests/test_phase7a_playwright.py`: Real Chromium browser test passing (18.00s) with 6 screenshots captured:
     - `phase7a_01_dashboard_baseline_healthy.png`
     - `phase7a_02_dashboard_traffic_controls.png`
     - `phase7a_03_dashboard_event_injected_threats.png`
     - `phase7a_04_settings_admin_and_status.png`
     - `phase7a_05_settings_analyst_readonly.png`
     - `phase7a_06_friendly_offline_error.png`
   - Full test suite: **82/82 passing in 124.09s** (saved to `docs/test_output_phase7a.txt`).


---

## Phase 7B Deliverables: Live Mode, Guided Demo, Reset, Demo Mode

1. **Passive Metadata-Only Live Monitoring (`backend/app/collector/live_collector.py`)**:
   - **Zero-Payload Storage Invariant**: Raw IPv4/TCP/UDP binary packet parser extracts network layer 3 & 4 metadata only (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `packet_count`, `bytes`, `timestamp`, `connection_frequency`). All application data, passwords, and frame payloads are discarded immediately without being buffered or persisted.
   - **Device Discovery & Unregistered Tagging**: Observed source IPs not present in registered inventory are recorded in `devices` with `device_source = "OBSERVED"` and `is_registered = False`.
   - **Driver & Capability Probing**: Safe runtime probe detects raw socket access and Npcap/libpcap driver presence.
   - **Graceful Automatic Fallback**: If permissions or packet drivers are unavailable, the system displays a friendly message (*"Live packet monitoring is unavailable. Switching to Simulation Mode."*), transitions `system_mode` to `SIMULATION`, and continues normal simulation without crashes or network disruption.
   - **Consent Verification**: Pre-activation modal requires explicit user acknowledgment regarding passive, non-intrusive monitoring on authorized networks only.

2. **Strict Data Separation (`OBSERVED` vs `SIMULATED`)**:
   - Database schema updated with backwards-compatible SQLite migrations (`data_source` column on `traffic_flows`, `device_source` and `is_registered` on `devices`).
   - Active mode badge prominently rendered in the global navigation bar (`MODE: SIMULATION` or `MODE: LIVE MONITORING`).
   - Devices and Traffic tables display unambiguous `SIMULATED` (blue) and `OBSERVED` (purple) badges, preventing any telemetry conflation.

3. **12-Step Guided Interactive Demonstration (`backend/app/simulation/scenario_manager.py`)**:
   - Step 1: Create network topology baseline (12 canonical devices, 0.0 risk, 100.0 health) → navigates to `devices`.
   - Step 2: Generate normal background synthetic traffic flows → navigates to `traffic`.
   - Step 3: Introduce unknown unregistered device (`Rogue-Laptop-99`) → navigates to `devices`.
   - Step 4: Inject suspicious multi-port scanning behavior → navigates to `traffic`.
   - Step 5: Rule engine detects reconnaissance scan and creates `PORT_SCAN` alert → navigates to `threats`.
   - Step 6: AI Isolation Forest scores traffic as `ANOMALOUS` (score $\ge 0.85$) with dynamic explainability reasons → navigates to `threats`.
   - Step 7: Digital Twin synchronizes graph state, flags host, and degrades health to 85.0 → navigates to `digital-twin`.
   - Step 8: Calculate explainable device risk breakdown (Unknown + Port Scan + Anomaly = 70.0) → navigates to `dashboard`.
   - Step 9: Run What-If simulation on compromised host to map lateral attack path to Database → navigates to `what-if`.
   - Step 10: Simulate network isolation to sever attack path without modifying live network → navigates to `what-if`.
   - Step 11: Security analyst investigates and marks threat contained in audit trail → navigates to `threats`.
   - Step 12: Network health score recovers toward baseline healthy state → navigates to `dashboard`.
   - Controller provides Previous, Next, Auto-Play (3s interval), direct step jump, and docked/minimized floating bar.

4. **Demo Reset Engine & Administrative RBAC**:
   - Reset endpoint (`POST /api/simulation/demo/reset`) purges rogue/observed devices, alerts, security events, synthetic flows, attack paths, simulation runs, and per-user read states.
   - Restores the 12 canonical devices to baseline (`risk_score = 0.0`, `health = 100.0`).
   - Preserves user accounts, credentials, system settings, and audit logs.
   - Strictly protected with RBAC (`require_admin`): unauthenticated requests return `401 Unauthorized`, and Analysts receive `403 Forbidden`.
   - Confirmation dialog in UI explicitly outlines data cleanup scope before execution.

5. **Demo Presentation Mode**:
   - High-contrast, presentation-optimized layout with enlarged KPI cards and prominent alert styling.
   - Automatically hides administrative configuration pages (Settings and Profile) to keep demonstrations focused on security capabilities.
   - Backed 100% by live engine endpoints—no fake or hardcoded static presentation mockups.

6. **Clear Four-State Security Tagging**:
   - `OBSERVED`: Unregistered/live network telemetry and discovered hosts.
   - `DETECTED`: Real rule engine and ML anomaly detections.
   - `SIMULATED`: Deterministic synthetic network traffic and pre-seeded devices.
   - `HYPOTHETICAL`: What-If attack path projections and simulated isolation states.

7. **Automated Verification**:
   - `backend/tests/test_phase7b.py`: 5/5 acceptance tests passing (12-step demo end-to-end, reset demo restores baseline idempotently with RBAC, live mode fallback without permission, fake packet parsing proves zero payload stored, demo mode uses real engine data).
   - `backend/tests/test_phase7b_playwright.py`: Real Chromium browser test passing with all 13 step screenshots captured and stored in `backend/tests/screenshots/` and brain artifacts.
   - Complete test suite: **87/87 passing across 10 suites in 146.13s** (saved to `docs/test_output_phase7b.txt`).
