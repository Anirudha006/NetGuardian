# NetGuardian — AI-Powered Digital Twin for Network Security

> **"See your network. Understand the risk. Simulate the threat. Protect the system."**

NetGuardian is a production-grade defensive cybersecurity prototype that combines **real-time/simulated network monitoring**, **rule-based detection heuristics**, **unsupervised Machine Learning anomaly scoring (Isolation Forest)**, **graph-based Digital Twin modeling (NetworkX)**, and **safe What-If attack-path simulation with simulated defensive isolation**.

---

## 🌟 Key Innovations

1. **Digital Twin for Network Security**: An active in-memory graph representation (NetworkX) of physical and logical network devices, continually synchronized with relational database state.
2. **Dual-Layer Threat Detection**:
   - **Layer 1 (Heuristic Rule Engine)**: Catches port reconnaissance, traffic surges, unregistered/rogue devices, and brute-force patterns.
   - **Layer 2 (AI Isolation Forest)**: Evaluates 8-dimensional feature vectors to identify subtle statistical outliers.
3. **Explainable AI (XAI)**: Eliminates "black-box" scores by providing concrete deviation ratios (e.g. *9.2× baseline volume*, *17 target ports*).
4. **Safe What-If Attack-Path Simulation**: Graph-theoretical traversal computing reachable assets, hop counts, and simulated path risk towards high-value **Crown Jewel Databases** without executing any real attacks.
5. **Simulated Defensive Isolation**: Test switch-port quarantine in the Digital Twin graph model, demonstrating path severance and risk reduction before taking real physical action.
6. **12-Step Guided Demonstration Walkthrough**: Built-in 1-click end-to-end incident scenario with Auto-Play and 1-click demo reset.

---

## 🏗️ Architecture Overview

```text
                  ┌──────────────────────────────┐
                  │   ADMINISTRATOR / ANALYST    │
                  └──────────────┬───────────────┘
                                 │
                                 ▼
                  ┌──────────────────────────────┐
                  │    REACT + VITE OPS CONSOLE  │
                  │ (Topology, KPIs, Studio, UI) │
                  └──────────────┬───────────────┘
                                 │ REST / JSON (JWT Auth)
                                 ▼
                  ┌──────────────────────────────┐
                  │     FASTAPI BACKEND CORE     │
                  ├──────────────┬───────────────┤
                  │ Auth & RBAC  │ Traffic Pulse │
                  │ Health Score │ Audit Trail   │
                  └──────┬───────┴───────┬───────┘
                         │               │
        ┌────────────────┴───────────────┴────────────────┐
        ▼                                                 ▼
┌──────────────────┐                            ┌───────────────────┐
│ RULE DETECTION   │                            │ AI / ML ENGINE    │
│ Heuristic Layer  │                            │ Isolation Forest  │
└────────┬─────────┘                            └─────────┬─────────┘
         │                                                │
         └───────────────────────┬────────────────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │   DIGITAL TWIN ENGINE   │
                    │ NetworkX In-Memory Graph│
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │    SQLITE RELATIONAL    │
                    │    DATABASE PERSISTENCE │
                    └─────────────────────────┘
```

---

## 💻 Tech Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React 18, Vite, Lucide React, Recharts, Custom Dark Ops Theme CSS |
| **Backend** | Python 3.10+, FastAPI, Uvicorn, SQLAlchemy, Pydantic v2, NetworkX |
| **Machine Learning** | Scikit-learn (Isolation Forest), NumPy |
| **Security & Auth** | Salted PBKDF2-HMAC-SHA256, JSON Web Tokens (python-jose) |
| **Database** | SQLite (Production-extensible to PostgreSQL) |
| **DevOps & Testing** | Pytest, Docker Compose |

---

## ⚡ Quick Start & Installation

### Prerequisites
- **Python**: 3.10 to 3.14 installed (`python` or `py`)
- **Node.js**: v18+ with `npm`

---

### Step 1: Clone or Navigate to Project Directory
```powershell
cd c:\Users\srini\OneDrive\Desktop\NetGuardian
```

---

## 🚀 Quick Start & Installation (8 Steps for Windows & Linux)

### Windows (PowerShell)
1. **Open project**: `cd c:\Users\srini\OneDrive\Desktop\NetGuardian`
2. **Create Python venv**: `python -m venv venv`
3. **Install backend dependencies**: `.\venv\Scripts\Activate.ps1; pip install -r backend\requirements.txt`
4. **Install frontend dependencies**: `cd frontend; npm install; cd ..`
5. **Initialize database & seed data**: `cd backend; python -c "from app.database import Base, engine, SessionLocal; from app.utils.seed_data import seed_database; Base.metadata.create_all(bind=engine); db=SessionLocal(); seed_database(db); db.close()"; cd ..`
6. **Start backend**: `cd backend; python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload`
7. **Start frontend**: Open a new terminal: `cd frontend; npm run dev`
8. **Open browser**: Visit `http://localhost:5173/` (API Docs at `http://127.0.0.1:8000/docs`)

### Linux / macOS (Bash)
1. **Open project**: `cd /path/to/NetGuardian`
2. **Create Python venv**: `python3 -m venv venv`
3. **Install backend dependencies**: `source venv/bin/activate && pip install -r backend/requirements.txt`
4. **Install frontend dependencies**: `cd frontend && npm install && cd ..`
5. **Initialize database & seed data**: `cd backend && python3 -c "from app.database import Base, engine, SessionLocal; from app.utils.seed_data import seed_database; Base.metadata.create_all(bind=engine); db=SessionLocal(); seed_database(db); db.close()" && cd ..`
6. **Start backend**: `cd backend && uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload`
7. **Start frontend**: Open a new terminal: `cd frontend && npm run dev`
8. **Open browser**: Visit `http://localhost:5173/` (API Docs at `http://127.0.0.1:8000/docs`)

---

## 🔑 Demo Credentials

> [!NOTE]
> These credentials are generated automatically during database initial seeding.

| Role | Username | Password | Privileges |
|---|---|---|---|
| **Admin** | `admin` | `admin123` | Full control: simulations, isolation, user management, settings |
| **Analyst** | `analyst` | `analyst123` | Operations: view topology, run What-If, triage alerts, reports |

*(Quick-fill buttons are provided on the login screen for 1-click sign-in.)*

---

## 🎬 12-Step Guided Demonstration Walkthrough

Click **"Launch Demo Story"** or the **"Guided Demo"** button in the top navigation bar to execute the complete scenario:

1. **Step 1 — Baseline Network Initialized**: 10 monitored devices active (Router, Switch, PCs, Servers, DB). Network Health is **100% HEALTHY**.
2. **Step 2 — Benign Traffic Pulse**: Realistic background flows (HTTP, DNS, DB queries). Zero false alerts.
3. **Step 3 — Unknown Rogue Device Detected**: `Rogue-Laptop-99` (`192.168.1.199`) appears on `Core-Switch-01`. Flagged by RULE-03.
4. **Step 4 — Port-Reconnaissance Scan**: Rogue laptop initiates multi-port sweeps targeting internal services.
5. **Step 5 — Rule Engine Flags Port Scan**: RULE-01 triggers: `Possible Port-Scanning Behavior`.
6. **Step 6 — AI Model Identifies Anomaly**: Isolation Forest scores flow at **0.89 Anomaly Score** with High confidence.
7. **Step 7 — Red Alert Raised**: Dashboard displays alert; Network Health drops to **62% (ELEVATED_RISK)**.
8. **Step 8 — Digital Twin Highlights Node**: Rogue laptop pulses with warning aura in the interactive topology map.
9. **Step 9 — What-If Simulation Triggered**: Administrator tests: *"What if Rogue-Laptop-99 is compromised?"*
10. **Step 10 — Attack Path Traced to Crown Jewel DB**:
    $$\text{Rogue-Laptop-99} \longrightarrow \text{Core-Switch-01} \longrightarrow \text{App-Server} \longrightarrow \text{Crown-Jewel-DB}$$
    Path Risk calculated at **84.0 / 100** (CRITICAL).
11. **Step 11 — Simulated Isolation Executed**: Admin clicks **"Simulate Immediate Isolation"**. Digital Twin severs all incident graph edges.
12. **Step 12 — Attack Path Neutralized & Report Export**: Reachable nodes drop to 0, path risk drops to 0, and a comprehensive Security Audit Report is exported.

Click **"Reset Demo"** at any time to return to the clean baseline state.

---

## 📊 Transparent Mathematical Formulas

### 1. NetGuardian Network Health Score ($0 - 100\%$)
$$\text{Health} = \max\left(0, 100 - \left(\sum \text{ThreatPenalties} + \text{DevicePenalties} + \text{AnomalyPenalties}\right)\right)$$
- Critical Alert: **-25 pts**
- High Alert: **-15 pts**
- Medium Alert: **-8 pts** / Low Alert: **-3 pts**
- Suspicious / Compromised Device: **-12 pts each**
- Recent Active Anomaly Spike: up to **-20 pts**

### 2. NetGuardian Simulated Path Risk Score ($0 - 100$)
$$\text{PathRisk} = \min\left(100.0, \, R_{\text{src}} \times 0.3 + C_{\text{tgt}} \times 0.4 + \left(\frac{1}{\text{Hops}}\right) \times 20.0 + T_{\text{def}} \times 10.0\right)$$
- Source Device Risk Baseline ($30\%$ weighting)
- Target Asset Criticality Baseline ($40\%$ weighting: Database=95, Server=75)
- Inverse Distance / Hop Count Proximity
- Source Host Trust Deficiency Modifier

---

## 🐳 Optional Docker Deployment

```bash
docker-compose up --build
```
- Backend container mapped to port 8000
- Frontend container mapped to port 5173

---

## 📑 Project Documentation & Deliverables

- [`docs/PROJECT_REPORT.md`](file:///c:/Users/srini/OneDrive/Desktop/NetGuardian/docs/PROJECT_REPORT.md): 14-Chapter Academic Project Report.
- [`docs/ARCHITECTURE.md`](file:///c:/Users/srini/OneDrive/Desktop/NetGuardian/docs/ARCHITECTURE.md): 10 Detailed Mermaid System & Sequence Diagrams.
- [`docs/VIVA_QUESTIONS.md`](file:///c:/Users/srini/OneDrive/Desktop/NetGuardian/docs/VIVA_QUESTIONS.md): 25+ Viva Voce Defense Q&As.
- [`TEST_RESULTS.md`](file:///c:/Users/srini/OneDrive/Desktop/NetGuardian/TEST_RESULTS.md): Automated & Integration Test Verification Matrix.
- [`DECISIONS.md`](file:///c:/Users/srini/OneDrive/Desktop/NetGuardian/DECISIONS.md): Architecture Decision Records (ADR).
- [`PROJECT_STATUS.md`](file:///c:/Users/srini/OneDrive/Desktop/NetGuardian/PROJECT_STATUS.md): Real-time phase tracking log.

---

## 🛡️ Educational Safety Notice

NetGuardian is designed specifically for **defensive cybersecurity education, network monitoring research, and academic demonstrations**. It does not contain any exploit payloads, real malware, destructive DDoS automation, or unauthorized network intrusion scripts. All attack path modeling is safely computed using in-memory graph algorithms.
