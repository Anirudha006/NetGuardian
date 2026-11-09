# NetGuardian Architecture & System Design Diagrams

This document contains Mermaid diagrams illustrating all 10 architectural views specified in the NetGuardian Master Specification.

---

## 1. System Architecture Diagram

```mermaid
graph TD
    subgraph UI ["User / Presentation Layer"]
        A[Administrator / Analyst] -->|HTTPS / REST| B[React + Vite Ops Dashboard]
    end

    subgraph ServiceLayer ["FastAPI Service Layer"]
        B --> C[FastAPI Gateway]
        C --> D[Auth & RBAC Service]
        C --> E[Rule Detection Engine]
        C --> F[AI / ML Anomaly Engine]
        C --> G[Digital Twin Graph Engine]
        C --> H[What-If & Mitigation Engine]
        C --> I[Synthetic Traffic Simulator]
    end

    subgraph StorageLayer ["Persistence & Telemetry Layer"]
        D & E & F & G & H & I --> J[(SQLite Database)]
        G <--> K[NetworkX In-Memory Graph]
    end

    subgraph DataCollectors ["Data Sources"]
        L[Simulated Network Pulse] --> I
        M[Passive Network Sniffer - Scapy] -.->|Controlled Live Mode| E
    end
```

---

## 2. End-to-End Data Flow Diagram

```mermaid
flowchart TD
    A[Network Packet / Synthetic Flow] --> B[Traffic Collector]
    B --> C[Data Normalization & Logging]
    C --> D[(SQLite Database)]
    
    C --> E[8-Dimensional Feature Extractor]
    E --> F[Rule-Based Heuristics]
    E --> G[Isolation Forest ML Model]
    
    F -->|Threshold Violation| H{Security Incident?}
    G -->|Anomaly Score >= 0.60| H
    
    H -->|Yes| I[Generate Security Alert]
    H -->|No| J[Log Benign Telemetry]
    
    I --> K[Update Device Risk & Status]
    K --> L[Synchronize Digital Twin Graph]
    L --> M[Update Web Dashboard KPIs & Topology]
```

---

## 3. Network Topology Architecture

```mermaid
graph TD
    WAN((External WAN)) --- Router[Gateway-Router<br/>192.168.1.1]
    Router --- Switch[Core-Switch-01<br/>192.168.1.2]
    
    Switch --- PC1[Lab-PC-01<br/>192.168.1.10]
    Switch --- PC2[Lab-PC-02<br/>192.168.1.11]
    Switch --- PC3[Lab-PC-03<br/>192.168.1.12]
    Switch --- Laptop[Faculty-Laptop<br/>192.168.1.15]
    Switch --- Printer[Network-Printer<br/>192.168.1.30]
    Switch --- IoT[Security-Camera-IoT<br/>192.168.1.40]
    
    Switch --- Server[App-Server<br/>192.168.1.20]
    Server === DB[(Crown-Jewel-DB<br/>192.168.1.21)]
    
    Rogue[Rogue-Laptop-99<br/>192.168.1.199] -.->|Unauthorized Access| Switch

    classDef critical fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;
    classDef high fill:#451a03,stroke:#f59e0b,stroke-width:2px,color:#fcd34d;
    classDef rogue fill:#581c87,stroke:#a855f7,stroke-width:2px,color:#d8b4fe;
    
    class DB critical;
    class Server,Router,Switch high;
    class Rogue rogue;
```

---

## 4. Digital Twin Engine Synchronization

```mermaid
sequenceDiagram
    participant DB as SQLite DB
    participant DT as Digital Twin (NetworkX)
    participant WT as What-If Simulator
    participant UI as React Frontend

    Note over DB,DT: Bidirectional State Synchronization
    DB->>DT: Query active devices & network connections
    DT->>DT: Build Graph(Nodes, Edges, Risk, Trust, Isolation)
    DT-->>UI: Export serialized Topology JSON
    
    Note over UI,WT: What-If Compromise Traversal
    UI->>WT: POST /api/simulation/what-if (Target Device)
    WT->>DT: Traverse active graph via BFS/Shortest Path
    DT->>WT: Return reachable nodes & critical asset paths
    WT-->>UI: Return Path Risk & Defensive Mitigations
```

---

## 5. AI / ML Anomaly Detection Pipeline

```mermaid
flowchart LR
    A[Raw Traffic Record] --> B[Feature Pipeline]
    subgraph Features ["8-Dimensional Feature Vector"]
        B --> F1[packet_count]
        B --> F2[bytes]
        B --> F3[connection_count]
        B --> F4[duration]
        B --> F5[unique_dst_ports]
        B --> F6[unique_dst_ips]
        B --> F7[failed_connections]
        B --> F8[traffic_rate]
    end
    
    Features --> C[Isolation Forest Model]
    C --> D[Compute Path Length h_x]
    D --> E[Normalized Anomaly Score 0.0 - 1.0]
    E --> F_comp{Score >= 0.60?}
    F_comp -->|Yes| G[Explainable AI Attribution Engine]
    F_comp -->|No| H[Classified Normal Flow]
    G --> I[Output Deviation Multipliers & Alert]
```

---

## 6. Multi-Layer Threat Detection Engine

```mermaid
flowchart TD
    P[Incoming Network Traffic] --> Split{Inspection Layer}
    
    subgraph Layer1 ["Layer 1: Rule-Based Heuristics"]
        Split --> R1["RULE-01: Port Scan (>15 ports in 60s)"]
        Split --> R2["RULE-02: Volume Spike (>3x baseline)"]
        Split --> R3["RULE-03: Unknown Device (Unregistered MAC/IP)"]
        Split --> R4["RULE-04: Brute-Force (>=5 failed auths)"]
    end
    
    subgraph Layer2 ["Layer 2: AI Isolation Forest"]
        Split --> ML1[Unsupervised Anomaly Isolation]
        ML1 --> ML2[Explainable Feature Deviation]
    end

    R1 & R2 & R3 & R4 --> Agg[Incident Aggregator]
    ML2 --> Agg
    Agg --> Final[Correlated Security Alert & Health Impact]
```

---

## 7. What-If Simulation & Simulated Isolation Flow

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Security Admin
    participant UI as What-If Studio
    participant API as FastAPI Backend
    participant DT as Digital Twin Graph
    participant DB as SQLite DB

    Admin->>UI: Select Target: Rogue-Laptop-99
    Admin->>UI: Click "Run What-If Simulation"
    UI->>API: POST /api/simulation/what-if
    API->>DT: Traverse Graph (Find paths to Crown Jewel DB)
    DT-->>API: Path found: Rogue -> Switch -> Server -> DB (Risk: 84/100)
    API-->>UI: Display Reachable Nodes & Attack Path
    
    Admin->>UI: Click "Simulate Isolation"
    UI->>API: POST /api/simulation/isolate
    API->>DB: Update Device: is_isolated=True, status='ISOLATED'
    API->>DT: Sever all incident graph edges
    DT-->>API: Confirm reachability drops from 8 to 0
    API-->>UI: Return "Potential attack path interrupted"
    UI->>Admin: Graph visualizes severed dashed connections
```

---

## 8. Database Entity-Relationship (ER) Diagram

```mermaid
erDiagram
    USERS ||--o{ AUDIT_LOGS : generates
    DEVICES ||--o{ NETWORK_CONNECTIONS : sources
    DEVICES ||--o{ NETWORK_CONNECTIONS : targets
    SECURITY_EVENTS ||--o{ ALERTS : triggers
    SIMULATION_RUNS ||--o{ ATTACK_PATHS : contains

    USERS {
        int id PK
        string username
        string email
        string password_hash
        string role
        datetime created_at
        datetime last_login
    }

    DEVICES {
        int id PK
        string device_name
        string ip_address
        string mac_address
        string device_type
        string os_type
        string status
        string criticality
        float risk_score
        float trust_score
        boolean is_isolated
    }

    NETWORK_CONNECTIONS {
        int id PK
        int source_device_id FK
        int destination_device_id FK
        string protocol
        int source_port
        int destination_port
        int packet_count
        bigint bytes_transferred
    }

    SECURITY_EVENTS {
        int id PK
        string event_type
        string severity
        string source_device
        string destination_device
        string description
        float confidence
        string status
    }

    ALERTS {
        int id PK
        int event_id FK
        string title
        string severity
        string message
        string rule_name
        float ai_score
        text recommendation
        string status
    }

    SIMULATION_RUNS {
        int id PK
        string simulation_type
        string target_device
        string result
        string risk_level
        float path_risk_score
        int critical_assets_reached
    }

    ATTACK_PATHS {
        int id PK
        int simulation_id FK
        string source_node
        string destination_node
        json path
        int hop_count
        float risk
    }
```

---

## 9. Role-Based Access Control (Use Case Diagram)

```mermaid
graph LR
    subgraph Roles ["System Actors"]
        Admin((Admin))
        Analyst((Analyst))
    end

    subgraph Actions ["Operational Capabilities"]
        UC1[View Operations Dashboard]
        UC2[Inspect Network Topology]
        UC3[Run What-If Attack Simulation]
        UC4[View & Triage Security Alerts]
        UC5[Export Security Audit Report]
        UC6[Execute Simulated Isolation]
        UC7[Configure Detection Thresholds]
        UC8[Manage System Users]
    end

    Analyst --> UC1
    Analyst --> UC2
    Analyst --> UC3
    Analyst --> UC4
    Analyst --> UC5

    Admin --> UC1
    Admin --> UC2
    Admin --> UC3
    Admin --> UC4
    Admin --> UC5
    Admin --> UC6
    Admin --> UC7
    Admin --> UC8
```

---

## 10. Deployment Topology (Simulation vs Controlled Real Network)

```mermaid
graph TD
    subgraph Workstation ["Local Workstation / Laptop (Default Mode A)"]
        WS_BE[FastAPI + NetworkX Backend]
        WS_FE[React Web Dashboard]
        WS_SIM[Synthetic Traffic Generator]
        WS_FE <--> WS_BE
        WS_SIM --> WS_BE
    end

    subgraph ControlledLab ["Controlled Testbed / College Lab (Mode B)"]
        SW[Managed Switch with Port Mirroring / SPAN]
        PI[Monitoring Host / Raspberry Pi with Scapy]
        DEVS[Lab PCs / IoT Cameras / Servers]
        
        DEVS --> SW
        SW -.->|Mirror Port RX/TX| PI
        PI -->|Passive Metadata Stream| WS_BE
    end
```
