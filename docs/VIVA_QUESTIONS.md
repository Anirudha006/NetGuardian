# NetGuardian — Comprehensive Viva Voce & Defense Guide

This guide prepares students and developers to confidently answer questions during project reviews, viva examinations, and technical presentations.

---

## Section 1: Conceptual & Architectural Questions

### Q1: What is NetGuardian, and what is the core innovation of the project?
**Answer**:  
NetGuardian is an **AI-Powered Digital Twin platform for Network Security**. The primary innovation is the convergence of:
1. **Network Monitoring & Telemetry** (real-time/simulated packet flows),
2. **Dual-Layer Threat Detection** (deterministic heuristics + Machine Learning anomaly scoring),
3. **Graph-Based Digital Twin** (NetworkX in-memory synchronized topology), and
4. **Safe "What-If" Attack-Path Simulation & Defensive Isolation**.  
Traditional tools (like Wireshark or tcpdump) merely log raw packets. NetGuardian models the network as an active graph, identifies critical assets, calculates multi-hop lateral attack paths, and allows administrators to test simulated isolation without attacking or disrupting real systems.

---

### Q2: What is a "Digital Twin" in the context of cybersecurity? How is it different from a static diagram?
**Answer**:  
A Digital Twin is a software-based, virtual representation of a physical or logical system that is kept in synchronization with the actual system's state.  
- A **static diagram** (like a Visio drawing) is fixed and decoupled from real-time events.
- A **Digital Twin** continuously reflects dynamic node operational statuses (Online, Suspicious, Compromised, Isolated), risk scores, traffic volumes, and active communication edges. Furthermore, it allows administrators to execute **hypothetical simulations** ("What if PC-04 is infected?") directly on the graph model.

---

### Q3: Why is NetGuardian built as a purely defensive tool?
**Answer**:  
Safety and educational ethics are central to the project. NetGuardian strictly avoids deploying real exploits, malware, brute-force credential stuffing tools, or packet flooding. All attack paths are evaluated **analytically** using graph traversal algorithms within the Digital Twin model, making it 100% safe to demonstrate on personal laptops, university laboratories, and corporate environments.

---

### Q4: What are the three operational modes of NetGuardian?
**Answer**:  
- **Mode A — Simulation / Demo Mode (Default)**: Generates realistic synthetic traffic pulses across 10+ devices with deterministic seedability. Works on any normal laptop with zero special privileges.
- **Mode B — Live Monitoring Mode**: Passively captures network metadata (IP, port, protocol, byte count) using Scapy on authorized interfaces. If raw socket permissions are missing, it gracefully falls back to Mode A.
- **Mode C — What-If / Digital Twin Mode**: Allows interactive selection of any node to simulate hypothetical compromise, discover reachable paths to critical assets, and test simulated defensive isolation.

---

## Section 2: Machine Learning & AI Anomaly Detection

### Q5: Why did you choose Isolation Forest instead of a supervised classifier like Random Forest or SVM?
**Answer**:  
In real-world computer networks, traffic data is predominantly normal, and malicious zero-day anomalies are rare and unlabelled. Supervised models require large, perfectly labeled datasets and cannot detect novel attack patterns they were not trained on.  
**Isolation Forest** is an unsupervised ensemble algorithm that isolates anomalies without requiring labels. Anomalies are "few and different", which means they have shorter tree path lengths than dense clusters of normal traffic.

---

### Q6: What is the mathematical basis of the Isolation Forest anomaly score?
**Answer**:  
The anomaly score $s(x, n)$ for an instance $x$ in a dataset of $n$ instances is:
$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
Where:
- $h(x)$ is the number of tree edges traversed to isolate instance $x$.
- $E(h(x))$ is the average path length across all $t$ trees in the forest.
- $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree (BST):
  $$c(n) = 2 \left(\ln(n - 1) + 0.5772156649\right) - \frac{2(n - 1)}{n}$$

**Interpretation**:
- When $E(h(x)) \to 0 \implies s(x, n) \to 1$: The data point is isolated near the root, meaning it is an **extreme anomaly**.
- When $E(h(x)) \to c(n) \implies s(x, n) \to 0.5$: Normal instance deep within the tree clusters.

---

### Q7: What are the 8 features used in the ML feature pipeline?
**Answer**:  
1. `packet_count`: Number of packets transferred in the observation window.
2. `bytes`: Total volume in bytes transferred.
3. `connection_count`: Number of concurrent connections established.
4. `duration`: Connection duration in seconds.
5. `unique_dst_ports`: Number of unique destination ports targeted (flags port sweeps).
6. `unique_dst_ips`: Number of unique destination hosts contacted (flags horizontal scanning).
7. `failed_connections`: Number of TCP RST flags or failed handshakes.
8. `traffic_rate`: Throughput velocity ($\text{bytes} / \text{duration}$).

---

### Q8: How does NetGuardian ensure Explainable AI (XAI)?
**Answer**:  
Instead of outputting an unexplained number, NetGuardian compares the input features against the learned normal baseline distribution. If a feature exceeds threshold multipliers ($\Delta_j = x_j / \mu_j$), the system outputs human-readable diagnostic bullets:
- *"• Traffic volume (1,850,000 bytes) is 9.2× above baseline average."*
- *"• Targeted 17 distinct destination ports within observation window (typical: 1-2)."*
- *"• High connection rejection rate: 12 failed handshakes."*

---

## Section 3: Digital Twin & Graph Theory

### Q9: How is the network topology modeled in software?
**Answer**:  
Using Python's **NetworkX** library as an in-memory graph $G = (V, E)$:
- **Vertices ($V$)**: Represent network devices (Routers, Switches, Workstations, Servers, DBs) storing attributes: IP, MAC, OS, status, criticality, risk score, trust score, and isolation state.
- **Edges ($E$)**: Represent communication channels storing attributes: protocol, ports, transferred bytes, and active/severed status.
The graph is synchronized bidirectionally with the SQLite database whenever devices or connections change.

---

### Q10: How does the "What-If" simulation work algorithmically?
**Answer**:  
When an administrator selects a target node (e.g. `PC-04`):
1. NetGuardian constructs an active subgraph excluding severed/isolated links.
2. It executes **Breadth-First Search (BFS)** or **Connected Components** to identify all reachable nodes.
3. It filters reachable nodes for **Crown Jewels** (`criticality == 'CRITICAL'` or `'HIGH'`).
4. For each reachable target, it finds the shortest simple path using Dijkstra / BFS.
5. It computes the **NetGuardian Simulated Path Risk** score.

---

### Q11: What is the formula for the Simulated Path Risk score?
**Answer**:  
$$\text{PathRisk} = \min\left(100.0, \, R_{\text{src}} \times 0.3 + C_{\text{tgt}} \times 0.4 + \left(\frac{1}{\text{Hops}}\right) \times 20.0 + T_{\text{def}} \times 10.0\right)$$
Where:
- $R_{\text{src}}$: Risk score of the compromised source node ($0-100$).
- $C_{\text{tgt}}$: Criticality baseline of destination ($\text{LOW}=20, \text{MEDIUM}=50, \text{HIGH}=75, \text{CRITICAL}=95$).
- $\text{Hops}$: Shortest path distance in edges.
- $T_{\text{def}}$: Trust deficiency penalty: $\max(0, (100 - \text{Trust}_{\text{src}}) \times 0.01)$.

---

### Q12: What is "Simulated Isolation", and does it affect real network equipment?
**Answer**:  
Simulated Isolation is a defensive containment feature executed within the Digital Twin model. When triggered:
- The device's status in the database is set to `ISOLATED`.
- In the NetworkX graph, all incident edges connected to that node are deactivated (`active = False`).
- Reachability immediately drops from $N$ to 0, demonstrating attack-path interruption.  
**Crucial Distinction**: No physical cables are cut and no real switch port commands are dispatched. It is a simulation to evaluate the defensive efficacy of quarantining a device before executing physical intervention.

---

## Section 4: Security Detection & Rule Engine

### Q13: What specific rules are implemented in the Rule Detection Engine?
**Answer**:  
- **RULE-01 (Port Scan)**: Flagged when a single source IP contacts $> 15$ unique destination ports within a 60-second sliding window.
- **RULE-02 (Traffic Anomaly)**: Flagged when transferred bytes exceed $3\times$ historical baseline or a single burst $> 500,000$ bytes.
- **RULE-03 (Unknown Device)**: Flagged when packets originate from an IP or MAC address not registered in the approved device inventory.
- **RULE-04 (Brute-Force Pattern)**: Flagged when $\ge 5$ failed connection handshakes occur within 30 seconds.
- **RULE-05 (Compromised Device)**: Flagged when lateral traversal or C2 beaconing behavior is observed.

---

### Q14: How is the NetGuardian Network Health Score calculated?
**Answer**:  
The Network Health score is transparent and explainable:
$$\text{Health} = \max\left(0, 100 - \left(\sum \text{ThreatPenalties} + \text{DevicePenalties} + \text{AnomalyPenalties}\right)\right)$$
- Active Critical Alert: -25 pts
- Active High Alert: -15 pts
- Active Medium Alert: -8 pts / Low: -3 pts
- Suspicious / Compromised Device: -12 pts each
- Active ML Anomaly Burst: up to -20 pts

---

## Section 5: Security, Implementation & Verification

### Q15: How are user passwords stored in NetGuardian?
**Answer**:  
Passwords are **never** stored as plain text. NetGuardian uses salted **PBKDF2-HMAC-SHA256** with 100,000 iterations and a cryptographically secure 16-byte random salt (`secrets.token_hex(16)`). Verification uses constant-time string comparison (`secrets.compare_digest`) to prevent timing attacks.

---

### Q16: How is Role-Based Access Control (RBAC) enforced?
**Answer**:  
NetGuardian issues signed **JSON Web Tokens (JWT)** upon login using the HS256 algorithm.
- **ADMIN Role**: Full access to all dashboards, device creation/deletion, simulation triggering, simulated isolation, threshold settings configuration, and user management.
- **ANALYST Role**: Read-only monitoring, What-If simulation execution, alert triage, and report generation. Modification of detection thresholds is blocked with HTTP 403 Forbidden.

---

### Q17: What test cases were performed, and what were the results?
**Answer**:  
We implemented an automated pytest test suite (`backend/tests/test_backend.py`) covering 10 core integration test cases:
1. PBKDF2 password hashing & rejection of invalid passwords.
2. Admin JWT authentication and claims extraction.
3. Dashboard KPI metrics aggregation.
4. Device inventory querying.
5. Mathematical risk score breakdown calculation.
6. Isolation Forest normal flow vs extreme anomaly detection ($s \ge 0.60$).
7. NetworkX graph serialization and edge integrity.
8. What-If lateral traversal reaching Crown Jewel DB (`192.168.1.21`).
9. Simulated Isolation edge severance and reachability drop to 0.
10. 12-step guided demo scenario progression and pristine reset.  
**Result**: All 10 test suites passed with a 100% pass rate.

---

### Q18: What is the 12-step guided demo scenario in NetGuardian?
**Answer**:  
It tells a coherent cybersecurity incident story:
1. Baseline virtual network is initialized.
2. Normal benign background traffic pulses.
3. Rogue laptop (`192.168.1.199`) joins the network.
4. Rogue laptop initiates multi-port reconnaissance.
5. Rule Engine flags `Possible Port Scan`.
6. AI model flags anomaly ($s = 0.89$, High confidence).
7. Red Alert raised on Dashboard; Health score drops to 62%.
8. Digital Twin highlights rogue laptop with a warning pulse.
9. Admin runs What-If simulation on the rogue laptop.
10. Graph traversal detects attack path reaching Crown Jewel DB (Path Risk: 84/100).
11. Admin executes "Simulate Isolation".
12. Digital Twin severs graph edges, reachability drops to 0, path risk drops to 0, and a comprehensive Security Audit Report is exported.
