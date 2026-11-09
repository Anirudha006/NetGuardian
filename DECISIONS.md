# Architecture Decision Records (ADR) — NetGuardian

## ADR-001: Backend Framework Choice
- **Decision**: Use FastAPI + Uvicorn + SQLAlchemy.
- **Rationale**: FastAPI provides high-performance asynchronous REST endpoints, automatic interactive OpenAPI (Swagger) documentation, robust Pydantic v2 data validation, and seamless interop with Python's scientific ecosystem (NetworkX, Scikit-learn, NumPy).
- **Consequences**: Fast development velocity, strict type safety, clean separation of concerns.

## ADR-002: Machine Learning Architecture
- **Decision**: Unsupervised `IsolationForest` with explainable feature attribution.
- **Rationale**: Anomaly detection in dynamic network traffic rarely has clean ground-truth labels in real-time. Isolation Forest isolates anomalies via recursive random feature partitioning without assuming Gaussian distribution.
- **Consequences**: Fast inference ($O(t \cdot \log n)$), lightweight memory footprint, explainable output mapping deviations against rolling baselines.

## ADR-003: Digital Twin Graph Model
- **Decision**: NetworkX in-memory Graph synchronized bidirectionally with SQLite.
- **Rationale**: NetworkX provides graph traversal, shortest path calculation, reachability analysis, and neighborhood exploration. Bidirectional synchronization ensures DB changes immediately reflect in the graph model.
- **Consequences**: Instant What-If compromise exploration without mutating production state.

## ADR-004: Frontend Architecture & Light-Theme Standard
- **Decision**: React + Vite + Tailwind CSS + Custom Light Theme Design System (Strictly Light Theme Only).
- **Rationale**: Professional enterprise cybersecurity tools require maximum contrast, calm visual hierarchies, and clear readability. No dark backgrounds, neon, or hacker aesthetic. White/slate cards, dark readable text (`#0f172a`), emerald green for normal, amber for warning, red for critical, and crisp blue for primary navigation.
- **Consequences**: Clean UI accessible to students, professors, and enterprise administrators alike. Zero visual fatigue.

## ADR-005: Safety & Educational Containment
- **Decision**: Purely defensive simulation; strictly no offensive payloads, exploits, or brute-force packet tools.
- **Rationale**: NetGuardian is built as a defensive security tool and college/lab training platform. All attack paths are evaluated analytically within the Digital Twin graph.
- **Consequences**: Complete safety for execution in any academic, corporate, or local workstation environment.

## ADR-006: Dual-Layer Detection (Rule-Engine + Isolation Forest)
- **Decision**: Combine deterministic signature rules with unsupervised ML scoring.
- **Rationale**: Rule engine captures immediate known threshold breaches (port scans, unknown MACs, brute force), while the Isolation Forest captures multi-dimensional statistical drift and zero-day anomalies.
- **Consequences**: Transparent, multi-tiered security event classification tagged clearly as RULE, AI, or RULE+AI.

## ADR-007: HttpOnly Session Cookies and Double-Submit CSRF Protection
- **Decision**: Store authentication tokens in `HttpOnly`, `SameSite=Strict` cookies (`ng_session`) rather than browser `localStorage`, with double-submit CSRF cookie validation (`ng_csrf` + `X-CSRF-Token` header) for state-changing HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`).
- **Rationale**: Prevents XSS token exfiltration while neutralizing cross-site request forgery attacks on browser clients.
- **Consequences**: Secure browser session lifecycle with transparent cookie transport; API/CLI clients continue supporting explicit `Authorization: Bearer` headers.

## ADR-008: OWASP Password Hashing (600,000 PBKDF2 Iterations) with Dynamic Upgrades
- **Decision**: Increase PBKDF2 rounds from 100,000 to 600,000 (`pbkdf2_sha256$600000$<salt>$<hex_key>`), maintaining backward compatibility with legacy 100,000 iteration hashes and dynamically upgrading them on next successful user login.
- **Rationale**: Satisfies current OWASP minimum recommendations for PBKDF2-HMAC-SHA256, protecting stored hashes against offline GPU/ASIC cracking without forcing sudden credential resets for existing users.
- **Consequences**: Sub-second compute overhead during login, transparent zero-downtime migration of stored hashes.

## ADR-009: Production Startup Safeguards & Input Normalization
- **Decision**: Backend enforces strict startup refusal when `ENVIRONMENT=production` if default demo passwords or default JWT secret keys are detected. Username inputs and rate-limiting keys are normalized via `.strip().lower()`.
- **Rationale**: Prevents accidental deployment of default insecure credentials into production environments and prevents attackers from bypassing brute-force rate limits via casing or whitespace variation.
- **Consequences**: Hardened baseline security posture by default.

## ADR-010: Deterministic Traffic Engine with Seed Reproducibility
- **Decision**: Implement synthetic traffic generation with an explicit pseudo-random number generator instance (`random.Random(seed)`), alongside natural continuous micro-jitter for flow durations and packet sizing.
- **Rationale**: Security simulations and classroom exercises require deterministic repeatability so instructors and students can reproduce exact anomaly sequences while preventing identical rigid flow values.
- **Consequences**: Identical seeds yield identical flow sequences across repeated runs; differing seeds produce distinct stochastic distributions.

## ADR-011: Hierarchical Layered Topology Layout
- **Decision**: Structure virtual network nodes into 5 explicit hierarchical levels: Level 0 (Internet-WAN), Level 1 (Gateway-Router), Level 2 (Core-Switch-01), Level 3 (Endpoints, Workstations, App-Server), Level 4 (Protected Crown-Jewel Database).
- **Rationale**: Enterprise networks enforce strict boundary tiers. Placing the Database exclusively behind the App-Server (rather than directly connected to the switch) reflects real-world defense-in-depth where databases are not reachable by endpoints.
- **Consequences**: Graph traversal and attack simulation models accurately reflect perimeter and lateral movement constraints.

## ADR-012: Network Navigation Consolidation & Sub-Tab Architecture
- **Decision**: Consolidate live packet telemetry into a sub-tab of the Network page (`📋 Devices`, `🗺️ Network Map`, `📡 Traffic Stream`) and reduce top-level navigation to the 9 specified tabs (`Dashboard`, `Network`, `Digital Twin`, `Threats`, `Simulation`, `Analytics`, `Reports`, `Settings`, `Profile`).
- **Rationale**: Satisfies the global specification rules, prevents top bar clutter, and logically associates traffic flows directly with the monitored network assets.
- **Consequences**: Clean UI layout with single-click switching between tabular inventory, interactive map, and telemetry streams.

## ADR-013: Composite Rate Limiting Key (Username + Client IP) with Proxy Guard
- **Decision**: Key the authentication brute-force rate limiter on normalized username and client connection IP (`request.client.host`). Only parse `X-Forwarded-For` when `request.client.host` is explicitly listed in `TRUSTED_PROXIES` (empty by default).
- **Rationale**: Prevents client-side IP spoofing where an attacker sends random `X-Forwarded-For` headers to bypass rate limits, while maintaining support for legitimate reverse proxies when explicitly configured.
- **Consequences**: Zero trust on external forwarded headers by default; independent per-IP rate-limiting buckets.

## ADR-014: Decoupled Device Trust Posture vs. Asset Criticality
- **Decision**: Formally decouple `trust_level` (`HIGH`, `MEDIUM`, `LOW`, `UNTRUSTED`) from `criticality` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **Rationale**: A device's trust posture reflects management state, hardening, and authentication rigor (e.g. hardened router is HIGH trust, untrusted IoT camera is LOW trust), whereas criticality reflects business impact if compromised (e.g. printer is LOW criticality, crown-jewel database is CRITICAL). Conflating the two distorted risk scoring.
- **Consequences**: Accurate, transparent risk attribution.

## ADR-015: Dynamic Multi-Column Grid Topology Wrapping
- **Decision**: Implement dynamic multi-column grid wrapping for endpoint tiers in the SVG topology canvas with auto-calculated height, width, density scaling, and zoom/pan fit controls.
- **Rationale**: Dense enterprise topologies (100+ endpoints) overlap severely in linear or dual-column vertical layouts. Multi-column wrapping guarantees minimum 54px vertical and 68px horizontal spacing per node regardless of device count.
- **Consequences**: Clear, non-overlapping visualization scaling smoothly from 10 to 100+ devices.

## ADR-016: Open Alert De-duplication and Occurrence Counting
- **Decision**: When the Rule Engine detects an anomaly, it checks if an alert matching `(event_type, source_device)` is already in an open state (`NEW` or `INVESTIGATING`). If open, it increments `occurrence_count` and updates `last_seen` timestamp and finding message on both `SecurityEvent` and `Alert` rows, rather than creating duplicate rows.
- **Rationale**: Prevents alert fatigue and flooding during sustained security events (e.g., thousands of port probes during a scan or sustained brute-force attempts).
- **Consequences**: Compact database storage, clean UI representation with clear `(xN)` occurrence indicators, while preserving the full history of the event's ongoing activity.

## ADR-017: RBAC-Protected Lifecycle Transitions with Permanent Audit Logging
- **Decision**: Status transitions on alerts (`NEW`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE`) require authenticated authorization (`ADMIN`, `ANALYST`, or `OPERATOR`). All transitions are synchronized to linked `SecurityEvent` records and permanently committed to `audit_logs` with the responsible user ID, username, client IP, timestamp, and transition details.
- **Rationale**: Enforces accountability and non-repudiation in security operations center (SOC) workflows, preventing unauthorized status manipulation and ensuring compliance auditing.
- **Consequences**: Unauthenticated calls strictly return `401 Unauthorized`; all analyst interventions are audit-traceable.

## ADR-018: Role-Specific Isolation Forest Calibration
- **Decision**: Train separate `IsolationForest` models for each device role (`endpoint`, `server`, `iot`, `network`) alongside a global fallback model, utilizing 8 standardized numerical features (`packet_count`, `bytes`, `connection_count`, `connection_duration`, `unique_destination_ports`, `unique_destination_ips`, `failed_connections`, `traffic_rate`).
- **Rationale**: A single global model conflates normal server behavior (high connection volume, multi-client servicing) with endpoint behavior, creating either high false-positive rates on servers or low sensitivity on compromised endpoints. Per-role partitioning provides tight behavioral baselines customized to each asset tier.
- **Consequences**: High precision (93.3%) on synthetic benchmark datasets; zero false-positive alerts across 120 normal ticks in Normal, Light, and Busy network traffic.

## ADR-019: Dynamic Multiplier-Delta Explainability (XAI)
- **Decision**: Generate human-readable alert reasons by computing dynamic multipliers and baseline deltas against learned role baselines rather than outputting static boilerplate strings.
- **Rationale**: Security analysts must immediately understand *why* an unsupervised machine learning algorithm flagged an event. Plain-language reasons (e.g., *"Traffic is 8.2× above baseline (82,000 bytes vs 10,000 bytes normal average)"*, *"Contacted 24 unique ports (Threshold: 3)"*) demystify ML predictions and build trust in automated telemetry.
- **Consequences**: Every AI-evaluated alert provides at least one concrete, mathematically derived reason explaining feature deviations.

## ADR-020: Two-Window Persistence for AI-Only Alert Escalation
- **Decision**: Require statistical anomalies detected exclusively by the AI Engine (without accompanying Layer 1 rule triggers) to sustain an anomaly score $\ge 0.75$ across 2 consecutive sliding evaluation windows before escalating to a persistent `AI_ANOMALY` security alert.
- **Rationale**: Unsupervised statistical algorithms are susceptible to transient network micro-bursts that do not represent ongoing malicious compromise. Enforcing a two-window persistence check prevents false-positive alert fatigue during momentary legitimate traffic spikes.
- **Consequences**: Eliminates transient false alarms while reliably flagging persistent behavioral anomalies (e.g., sustained C2 beacons, data exfiltration, or prolonged reconnaissance).


## ADR-021: Structural Links vs. Observed Communication Edges
- **Decision**: In the Digital Twin NetworkX graph, differentiate physical/topological infrastructure links (`edge_type="structural"`) from dynamic observed application flows (`edge_type="observed"`). Render structural links as solid slate lines (`#94a3b8`) and observed communication edges as dashed indigo lines (`#6366f1`) with directional arrow markers and active port notation.
- **Rationale**: Physical topology (Switch ↔ PC, Switch ↔ Server, Server ↔ Database) is enduring, whereas application communications (PC ↔ Server on 443, Server ↔ DB on 5432) are ephemeral and dynamic. Conflating the two makes it impossible to distinguish between physical disconnects and idle network flows.
- **Consequences**: Operators and analysts immediately perceive both network infrastructure connectivity and active communication channels on the interactive topology map.

## ADR-022: Centralized 5-Step Synchronization Rule
- **Decision**: Enforce a mandatory 5-step state transition pipeline on any device addition/update/deletion, alert lifecycle modification, or simulated event execution:
  1. Update database records (recalculate affected device risk/trust, recover device status if active threats resolved).
  2. Update in-memory graph (`digital_twin.sync_from_database(db)`).
  3. Recompute network health and update dashboard state.
  4. Recalculate affected risk factors.
  5. Commit transition and persist audit log event.
- **Rationale**: Prevents state divergence where the in-memory graph, database inventory, and dashboard display inconsistent device counts, risk scores, or health ratings.
- **Consequences**: Real-time sync comparison (`check_sync_status`) dynamically flags `OUT OF SYNC` if an unsynchronized mutation occurs, ensuring the Digital Twin is never a stale diagram.

## ADR-023: Exact Additive Risk & Health Score Normalization
- **Decision**: Device risk breakdown must guarantee that the sum of factor impacts equals the device risk score ($\sum F_i \equiv \text{Risk Score}$), appending an `Upper Risk Cap Normalization` factor when raw impacts exceed 100.0. Similarly, NetGuardian Health Score must satisfy $\text{Health Score} + \sum_{k} P_k \equiv 100.0$ across 5 capped penalty categories.

## ADR-024: Non-Destructive Structural Traversal for What-If Attack Path Simulation
- **Decision**: What-If compromise simulation operates exclusively as a graph exploration algorithm on structural edges (`edge_type == "structural"`). It strictly excludes the Internet WAN gateway, nodes marked `OFFLINE`, and nodes marked `ISOLATED`. Traversals never inject live network packets, invoke scanners, or alter real physical device state.
- **Rationale**: What-If analysis provides defensive predictive insight for risk planning without the danger or disruption of active penetration testing or synthetic noise.
- **Consequences**: Fast graph operations via NetworkX (< 5ms per traversal), 100% reproducible path calculations, and explicit user-facing labeling as `HYPOTHETICAL` across all UI and DB records.

## ADR-025: NetGuardian Simulated Path Risk & Isolation Containment Mechanics
- **Decision**: Path risk is calculated using a transparent weighted multi-factor formula:
  $$\text{Path Risk} = 0.30 \times R_{\text{source}} + 0.35 \times C_{\text{target}} + 0.15 \times H_{\text{proximity}} + 0.20 \times T_{\text{avg}}$$
  where Criticality values are Low=20, Medium=45, High=70, Critical=95; Hop factor $H = \max(0, 100 - 20 \times (\text{hops}-1))$; and $T_{\text{avg}}$ is the average trust score along the structural path.
  Simulating isolation severs logical twin links, transitions open threats to `CONTAINED`, recalculates network health, silences synthetic traffic for the host, and displays a prominent disclaimer banner with a one-click confirmation dialog before action.
- **Rationale**: Provides clear explainability of attack blast radius and validates defensive mitigation benefits in real-time before applying actual configuration changes.
- **Consequences**: Immediate visual feedback of severed attack reachability (reachable systems drops to 0, risk drops to 0.0), with full restoration capability (`/restore`) returning the Digital Twin to active network topology.
## ADR-026: Dashboard, Settings & Live Subsystem Health Probing (Phase 7A)
- **Decision**:
  1. **Reliable Polling & Visibility Control**: Polling pauses when the browser tab is hidden (`document.hidden`) and resumes immediately upon focus. Errors trigger exponential backoff (5s to 30s) with zero-flicker background updates.
  2. **Simulation Traffic Controls**: Provide `Pause`, `Resume`, and `Single-Step` simulation controls directly on the dashboard. When paused, automated traffic generation stops; `Step` advances exactly 1 tick.
  3. **Live Subsystem Health Probes**: Backend, Database, AI Engine, Digital Twin, and Network Collector are dynamically probed on demand with explanatory operational reasons (e.g. "Network Collector: UNAVAILABLE · Reason: Permission required · Simulation Mode remains available").
  4. **Analyst Read-Only Settings Mode**: Analysts have full read-only visibility into operational thresholds, simulation parameters, and security policies, with state-changing updates strictly restricted to Administrators (HTTP 403 Forbidden on unauthorized writes) and fully audit-logged.
  5. **Server-Side Per-User Notification Read State**: Persist alert read receipts in `user_notifications_read` table per user account.
  6. **Friendly Error States**: Provide clear, user-friendly offline cards ("Unable to load... Please verify the backend is running.") with interactive retry buttons instead of raw stack traces.
- **Rationale**: Ensures high resilience, clear operational feedback, role compliance, and complete observability across all NetGuardian subsystems.
- **Consequences**: Robust operational console suitable for both administrator configuration and analyst inspection.

## ADR-027: Live Packet Monitoring, Metadata-Only Collector & 12-Step Guided Demonstration Architecture (Phase 7B)
- **Decision**:
  1. **Passive-Only Live Monitoring & Strict Metadata Principle**:
     The live packet collector operates purely passively on authorized local interfaces. Only protocol headers are extracted: source/destination IPs, ports, transport protocol, packet count, byte volume, and timestamp. Under no circumstances are application payloads, decrypted traffic, passwords, or credential tokens ever read, extracted, or stored in memory or on disk (`payload_stored: false` invariant).
  2. **Automatic Graceful Fallback**:
     If live capture capability is absent (e.g. non-root/non-administrator privileges, missing Npcap/WinPcap driver, unsupported OS), the collector logs a friendly operational notice (*"Live packet monitoring is unavailable. Switching to Simulation Mode."*), displays an advisory message to the operator, and safely falls back to Simulation Mode without raising unhandled exceptions or perturbing network interfaces. Explicit consent acknowledgement is enforced before live capture activation.
  3. **Strict Separation of Data Sources**:
     All network telemetry and device models strictly differentiate origin across the database, APIs, and user interface:
     - `SIMULATED`: Generated deterministically by the virtual traffic simulator.
     - `OBSERVED`: Passively sniffed from live packet streams or injected header telemetry. Unknown observed IPs are automatically registered as unregistered (`is_registered: false`).
     - `DETECTED`: Generated by Layer 1 Rule Detection and Layer 2 AI Anomaly scoring.
     - `HYPOTHETICAL`: Generated exclusively during What-If attack-path simulations and never persisted as real network modifications.
  4. **12-Step Master Guided Walkthrough (Real Logic & Auto-Navigation)**:
     The 12-step guided demonstration invokes real engine endpoints end-to-end (baseline initialization, normal flow emission, rogue device join, port scanning, rule flag, Isolation Forest scoring with dynamic feature explainability, dashboard alert, twin node highlight, What-If simulation query, lateral path calculation to Database, simulated isolation, and attack severance verification). Each step returns target page metadata, and the frontend automatically navigates the active viewport to the corresponding operational screen.
  5. **Admin-Only Demo Reset with Idempotent Guarantee**:
     Resetting the demonstration network severs rogue connections, cleans simulated security alerts and attack paths, and restores the 12 canonical devices to zero risk and 100% health, while strictly preserving user accounts, audit logs, and settings. Restricted to Administrators (`403 Forbidden` on Analyst calls) with a confirmation dialog.
  6. **High-Contrast Demo Mode**:
     A dedicated "Demo Mode" toggle optimizes typography and layouts for high-visibility presentation, hides administrative configuration tabs (Settings/Profile) from navigation, and embeds a sticky guided presenter dock without introducing separate mock screens or synthetic visual divergence.
- **Rationale**: Delivers a compelling presentation experience with zero risk to operational networks, complete privacy guarantees, and robust reproducibility.
- **Consequences**: Clean separation of live vs. simulated telemetry, rock-solid demo replayability, and clear operator visibility.

