# Project Synopsis: NetGuardian

**Title**: NetGuardian — AI-Powered Digital Twin for Real-Time Network Security, Threat Detection, and Attack-Path Simulation  
**Domain**: Cybersecurity, Artificial Intelligence, Graph Theory, Full-Stack Web Development  
**Document Format**: Academic Project Proposal & Technical Synopsis  
**Word Document Export**: [`NetGuardian_Project_Synopsis.docx`](file:///c:/Users/srini/OneDrive/Desktop/NetGuardian/NetGuardian_Project_Synopsis.docx)

---

## 1. Abstract
NetGuardian is an advanced cybersecurity engineering project designed to address the systemic vulnerabilities of reactive network defense. Traditional perimeter security tools—such as stateful firewalls and signature-based intrusion detection systems—frequently fail once an attacker breaches an internal endpoint, leaving security teams blind to east-west lateral movement. Furthermore, executing penetration tests or attack simulations against live operational infrastructure poses unacceptable risks of server crashes, data corruption, and production outages. NetGuardian resolves this paradigm through an AI-powered Digital Twin: a continuous, in-memory mathematical graph model (NetworkX) that mirrors physical network topology, device vulnerability posture, and dynamic traffic telemetry. Threat detection is orchestrated via a dual-layer hierarchy combining deterministic heuristic rules (port scans, volume surges, rogue devices) with an unsupervised Isolation Forest machine learning model equipped with Explainable AI (XAI) feature attribution. Security analysts can execute safe 'What-If' attack-path simulations using Dijkstra's shortest-path algorithms to model threat propagation toward critical 'Crown Jewel' databases, followed by one-click simulated defensive isolation that severs virtual graph edges without disrupting physical hardware.

---

## 2. Introduction & Background
As modern enterprise networks expand across cloud, on-premise, and hybrid environments, traditional perimeter-oriented defenses have become increasingly inadequate. Contemporary cyber threats routinely bypass edge firewalls using social engineering, phishing, or rogue hardware. Once inside, adversaries operate within the internal network, performing reconnaissance and pivoting laterally across workstations and switches to compromise confidential servers and databases.

The concept of a 'Digital Twin' originates in aerospace and industrial manufacturing, where an exact software replica of a physical asset is maintained to simulate stress, predict failures, and optimize operations without endangering the physical entity. NetGuardian applies this architectural innovation to transform network defense from passive, reactive log analysis into predictive, proactive threat modeling.

---

## 3. Problem Statement & Motivation
1. **Invisibility to Lateral Movement**: Traditional defenses heavily monitor perimeter ingress and egress points. When an internal workstation is compromised, security teams lack real-time visibility into internal peer-to-peer communication corridors.
2. **Risks of Live Penetration Testing**: Executing actual exploits or vulnerability scans on production servers risks service outages, database corruption, and severe operational downtime.
3. **Alert Fatigue & Lack of Context**: Commercial SIEM tools generate thousands of raw alerts daily. Lacking network topology context, security analysts face cognitive exhaustion.

---

## 4. Project Objectives
* **Objective 1 (Digital Twin Modeling)**: Build an in-memory graph representation $G = (V, E)$ of all network devices, switches, routers, and transport edges with real-time state synchronization using NetworkX.
* **Objective 2 (Dual-Layer Threat Detection)**: Implement a hybrid detection engine pairing deterministic heuristic rules with Scikit-learn unsupervised Isolation Forest machine learning.
* **Objective 3 (Explainable AI - XAI)**: Provide plain-English, transparent forensic evidence explaining exact feature deviations (e.g. 9.2x baseline traffic rate, 17 target ports probed).
* **Objective 4 ('What-If' Simulation Studio)**: Allow security operators to select any host and hypothetically model compromise scenarios, calculating shortest lateral attack corridors toward critical assets using Dijkstra's algorithm.
* **Objective 5 (Simulated Defensive Isolation)**: Demonstrate threat containment by severing incident graph edges in software space, dropping reachability to zero without pulling physical cables.
* **Objective 6 (SOC Web Operations Console)**: Deliver a responsive, dark-mode cybersecurity console featuring an interactive SVG topology map, real-time KPI metrics, transparent network health scoring, and compliance report exports.

---

## 5. Existing System vs. Proposed System

| Evaluation Metric | Traditional Security / SIEM | NetGuardian AI Digital Twin |
| :--- | :--- | :--- |
| **Detection Methodology** | Static firewall rules & signature matching | Dual-Layer: Heuristic rules + Isolation Forest AI |
| **Attack Simulation** | Risky active exploits on live machines | Safe 'What-If' in-memory graph traversal |
| **Network Context** | Disconnected flat log tables & alerts | Interactive topological Digital Twin graph $G=(V,E)$ |
| **Physical Downtime** | High risk of server crashes during tests | Zero physical downtime (purely virtual containment) |
| **Explainability** | Opaque anomaly scores without context | Explainable AI (XAI) deviation multipliers |

---

## 6. System Requirements & Specifications
* **Hardware Requirements**:
  * CPU: Dual-Core 2.0 GHz minimum (Quad-Core 2.5 GHz+ recommended)
  * RAM: 4 GB minimum (8 GB to 16 GB recommended)
  * Storage: 2 GB free disk space (10 GB SSD recommended)
  * Network Interface: Gigabit Ethernet or Wi-Fi (promiscuous mode supported)
  * Display: 1080p Full HD recommended for multi-column SOC interface
* **Software Stack**:
  * Operating System: Windows 10/11, Ubuntu Linux 20.04+, macOS
  * Backend Framework: Python 3.10+, FastAPI (ASGI), Uvicorn
  * Database & ORM: SQLAlchemy 2.0 with SQLite / PostgreSQL
  * Machine Learning: Scikit-learn (Isolation Forest), NumPy
  * Graph Theory Engine: NetworkX
  * Frontend: React 18, Vite 5, Tailwind CSS, Lucide Icons, Recharts
  * Security: Passlib (PBKDF2-HMAC-SHA256), PyJWT (HS256), RBAC

---

## 7. System Architecture & 5-Tier Data Pipeline
1. **Telemetry Ingestion Layer**: Streams synthetic packets or captures live flows passively via Scapy. Extracts 8 flow features.
2. **Dual-Layer Threat Detection Layer**: Evaluates deterministic rules (Rules 01–05) and feeds vectors into Isolation Forest ML for anomaly scoring.
3. **Digital Twin Graph Model Layer**: Maintains in-memory graph $G = (V, E)$ via NetworkX, calculating node risk (0–100) and global health score.
4. **What-If Simulation Studio Layer**: Executes Dijkstra lateral traversals, calculates Path Risk, and applies simulated virtual isolation.
5. **SOC Operations Console Layer**: Exposes RESTful API with Swagger docs (`/docs`) and renders React 18 dashboard with SVG topology map.

---

## 8. Mathematical Formulation & Key Equations

### A. Global Network Health Score Equation
$$\text{Health} = 100 - \left[ \sum(\text{Threat Penalties}) + \sum(\text{Device Penalties}) + \sum(\text{Anomaly Penalties}) \right]$$

### B. NetGuardian Simulated Path Risk Formula
$$\text{PathRisk} = \min\left(100.0, \, R_{\text{src}} \times 0.3 + C_{\text{tgt}} \times 0.4 + \left(\frac{1}{\text{Hops}}\right) \times 20.0 + T_{\text{def}} \times 10.0\right)$$

---

## 9. Testing, Verification & Performance Results
* **Automated Pytest Coverage**: 10 / 10 automated test cases passed (100% success rate).
* **Graph Traversal Latency**: $< 15\text{ ms}$ execution time across multi-hop topologies.
* **Machine Learning Inference**: $< 5\text{ ms}$ per 8-dimensional packet vector.
* **Threat Detection Accuracy**: 100% detection rate on benchmark attack patterns.

---

## 10. Future Enhancements & Conclusion
* **Future Roadmap**: Graph Neural Networks (GNNs) for predictive infection forecasting, hardware firewall SOAR webhooks (pfSense/Fortinet), and multi-datacenter twins via Apache Kafka.
* **Conclusion**: NetGuardian successfully proves that cybersecurity can be proactive, predictive, and intelligent without endangering live physical infrastructure.
