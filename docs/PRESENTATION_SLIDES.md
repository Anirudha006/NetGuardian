# NetGuardian — Project Presentation Slide Deck & Speaker Notes

**Presentation File**: `NetGuardian_Project_Presentation.pptx` (Microsoft PowerPoint Widescreen 16:9)  
**Location**: `c:\Users\srini\OneDrive\Desktop\NetGuardian\NetGuardian_Project_Presentation.pptx`

---

## Slide 1: Title & Cover Slide
* **Title**: **NETGUARDIAN**
* **Subtitle**: AI-Powered Digital Twin for Real-Time Network Security, Dual-Layer Threat Detection, Attack-Path Simulation & Virtual Containment
* **Badges**: FASTAPI + REACT 18 | SCIKIT-LEARN ISOLATION FOREST | NETWORKX GRAPH TWIN | ZERO PHYSICAL DOWNTIME
* **Speaker Notes**:
  > *"Good morning respected evaluators and professors. Today I am presenting NetGuardian, an AI-powered Digital Twin designed to solve a fundamental dilemma in cybersecurity: how to proactively understand network risk, detect zero-day anomalies, and simulate lateral attack paths without risking downtime on live physical networks."*

---

## Slide 2: Executive Summary & Core Vision
* **Traditional Defense**:
  * Blind to lateral pivots inside the perimeter.
  * SIEM alert fatigue with no topological context.
  * Live penetration testing risks server crashes and outages.
* **The Digital Twin Paradigm**:
  * In-memory graph ($G = (V, E)$) synchronizing network hosts and connections in real time.
  * Dual-layer threat detection: Heuristic rules + Scikit-learn Isolation Forest ML.
  * Predictive "What-If" attack path simulation.
* **Value**: Zero downtime, Explainable AI (XAI), and proactive containment.
* **Speaker Notes**:
  > *"Rather than relying on static network diagrams or risking live equipment during tests, NetGuardian mirrors the physical environment into an active software digital twin. This allows us to observe, model, and simulate attack behaviors completely in software space."*

---

## Slide 3: Problem Statement & Industry Motivation
* **Critical Challenges**:
  * Perimeter defenses are outdated (attackers compromise internal laptops via phishing or rogue Wi-Fi).
  * The Penetration Testing Dilemma (cannot safely run exploits against production databases).
  * Static diagrams in Visio are disconnected from live telemetry.
  * Black-box AI causes distrust due to unexplainable alerts.
* **NetGuardian's Innovation**:
  * Continuous real-time graph synchronization.
  * Safe What-If sandbox queries.
  * Explainable AI (XAI) output with human-readable multipliers.
  * Zero-impact virtual containment.

---

## Slide 4: Hardware & Software Specifications
* **Hardware Requirements**:
  * Processor: Minimum Dual-Core 2.0 GHz (Intel i3/Ryzen 3); Recommended Quad-Core 2.5 GHz+ (Intel i5/i7, AMD Ryzen 5, Apple Silicon).
  * RAM: Minimum 4 GB; Recommended 8 GB – 16 GB for concurrent packet ingestion and in-memory graph models.
  * Storage: Minimum 2 GB; Recommended 10 GB SSD for rapid SQLite transactions.
  * Network Interface: 1x Gigabit Ethernet / Wi-Fi (supports optional promiscuous mode).
  * Display: 1366x768 or 1920x1080 (Full HD).
* **Software Stack**:
  * OS: Windows 10/11, Ubuntu Linux 20.04+, macOS Sonoma.
  * Backend: Python 3.10+, FastAPI (ASGI), Uvicorn, SQLAlchemy ORM, SQLite / PostgreSQL.
  * Machine Learning & Graph: Scikit-learn (Isolation Forest), NumPy, NetworkX.
  * Frontend Console: React 18, Vite 5, Tailwind CSS, Lucide Icons, Recharts, SVG canvas.
  * Security: Passlib (PBKDF2-HMAC-SHA256), PyJWT (HS256 tokens), RBAC.

---

## Slide 5: System Architecture & 5-Layer Pipeline
* **Layer 1: Ingestion & Telemetry** — Synthetic traffic generator & Scapy passive sniffer.
* **Layer 2: Dual-Layer Threat Detection** — Deterministic Rule Engine + Isolation Forest ML.
* **Layer 3: Digital Twin Graph Model** — NetworkX graph nodes, edges, risk scores, health calculation.
* **Layer 4: What-If Attack Simulator** — Dijkstra shortest-path traversal, reachability analysis, simulated isolation.
* **Layer 5: Operations Console** — React 18 frontend, dark cyber aesthetic, interactive SVG topology map, Swagger API docs.

---

## Slide 6: Dual-Layer Threat Detection Engine
* **Layer 1: Heuristic Rule Engine**:
  * `RULE-01 (Port Scan)`: > 15 unique target ports probed within 60 seconds.
  * `RULE-02 (Traffic Surge)`: Flows > 500 KB or > 3x baseline average.
  * `RULE-03 (Unknown Rogue Host)`: Unregistered MAC/IP address transmitting packets.
  * `RULE-04 (Brute Force Spike)`: > 5 rapid authentication failures/minute.
  * `RULE-05 (Compromised Host)`: Lateral movement and unauthorized subnet scanning.
* **Layer 2: Isolation Forest Machine Learning**:
  * Unsupervised tree ensemble ($n=100$, contamination $= 0.08$).
  * 8-Dimensional feature vector: `[packets, bytes, connections, duration, dst_ports, dst_ips, failed_conns, traffic_rate]`.
  * Explainable AI (XAI): Human-readable evidence strings (e.g. *"9.2x baseline volume, 17 target ports probed"*).

---

## Slide 7: Graph-Based Digital Twin Engine (NetworkX)
* **Mathematical Graph Formulation $G = (V, E)$**:
  * Vertices ($V$): Routers, Switches, Lab Workstations, App Server, Crown Jewel Database.
  * Edges ($E$): Active network links with protocol and bandwidth metadata.
* **Dynamic Node Metrics**:
  * Risk Score ($0 - 100$) and Trust Rating ($0 - 100$).
  * Asset Criticality: Low, Medium, High, Critical Crown Jewel.
* **Network Health Score Formula**:
  $$\text{Health} = 100 - (\text{Threat Penalties} + \text{Device Penalties} + \text{Anomaly Penalties})$$

---

## Slide 8: "What-If" Attack Path Simulation Studio
* **Core Question**: *"If an attacker breaches Lab-PC-01, can they pivot to the Database?"*
* **Dijkstra & BFS Graph Traversal**: Explores all reachable paths and minimum hop counts.
* **NetGuardian Path Risk Algorithm**:
  $$\text{PathRisk} = \min\left(100.0, \, R_{\text{src}} \times 0.3 + C_{\text{tgt}} \times 0.4 + \left(\frac{1}{\text{Hops}}\right) \times 20.0 + T_{\text{def}} \times 10.0\right)$$
* **Visual Attack Path Overlay**: Glowing crimson path rendered directly on the SVG topology.

---

## Slide 9: Simulated Defensive Isolation (Virtual Containment)
* **In-Memory Graph Containment**:
  * Analyst triggers "Simulated Isolation" on an infected node.
  * The Digital Twin severs all incident graph edges in memory.
  * Node reachability drops from $N$ to $0$.
  * Attack path to the Crown Jewel Database is instantly broken.
* **Physical Safety Guarantee**: Zero hardware ports disabled, zero server downtime, completely safe for academic labs.

---

## Slide 10: Cyber Operations Center UI (With Screenshot)
* **Features Displayed**:
  * 2-Tier Header with Brand and Module Toolbar.
  * 6-Column KPI Grid with explicit box gaps.
  * Real-time Network Health circular gauge.
  * Interactive SVG Digital Twin Network Topology Map.
  * Embedded screenshot: `presentation_assets/dashboard_full.png`.

---

## Slide 11: Real-Time Telemetry & KPI Box Columns
* **KPI Columns**:
  * Devices Online ($10 / 11$)
  * Threats Detected (Active alerts)
  * Suspicious Devices (Flagged nodes)
  * Packets Monitored (Stream volume)
  * Active Connections (Graph edges)
  * High-Risk Devices (Score $\ge 60$)
* Embedded screenshot: `presentation_assets/kpi_metrics.png`.

---

## Slide 12: Incident Center & Compliance Audit Reports
* **Threat Incident Management**:
  * Real-time incident table with severity badges (CRITICAL, HIGH, MEDIUM, LOW).
  * Status transition workflow: NEW $\to$ INVESTIGATING $\to$ CONTAINED $\to$ RESOLVED.
* **Compliance & Audit Reports**:
  * One-click PDF/HTML export via `/api/reports/export-html`.
  * Verified defensive audit trail confirming zero physical disruption.

---

## Slide 13: 12-Step Guided Demonstration Walkthrough
1. **Network Setup** — Baseline topology initialized.
2. **Traffic Pulse** — Normal packet stream.
3. **Rogue Device** — Unauthorized Rogue-Laptop connects to switch.
4. **Port Recon** — Host scans 17 ports.
5. **Rule Detection** — RULE-01 flags port scan.
6. **AI Anomaly** — Isolation Forest scores outlier.
7. **Alert Raised** — CRITICAL alert; Health drops to 5%.
8. **Twin Highlight** — Node pulses red on map.
9. **What-If Query** — Analyst models breach toward DB.
10. **Attack Path** — Path traced to Crown Jewel Database.
11. **Isolation** — Simulated isolation breaks path.
12. **Restoration** — Network restored to clean state.

---

## Slide 14: Testing & Validation Results
* **Automated Pytest**: 10/10 test cases passed (100% success rate).
* **Graph Traversal Speed**: $< 15\text{ ms}$.
* **AI Anomaly Inference**: $< 5\text{ ms}$ per vector.
* **Detection Accuracy**: 100% detection rate on benchmark port scan and surge attack patterns.
* **Frontend Build**: 2,398 modules built in 5.9 seconds.

---

## Slide 15: Viva / Interview Defense Masterclass
* **Q1**: Why use a Digital Twin for cybersecurity instead of testing on real hardware?
* **Q2**: Why use Isolation Forest instead of Supervised ML?
* **Q3**: How is the 'Path Risk' score calculated during What-If simulation?
* **Q4**: What is the practical value of 'Simulated Defensive Isolation'?

---

## Slide 16: Future Scope & Conclusion
* **Future Roadmap**: Graph Neural Networks (GNNs), Hardware Firewall SOAR Webhooks (pfSense/Fortinet), Cloud Multi-Site Twins (Kafka).
* **Conclusion**: NetGuardian is a complete, working defensive cybersecurity prototype bridging the gap between monitoring and proactive simulation.
