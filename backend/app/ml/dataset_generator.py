import os
import csv
import numpy as np
from typing import Tuple, List, Dict, Any

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "simulation"))
CSV_PATH = os.path.join(DATA_DIR, "training_data.csv")

# Exact Phase 4 Task 2 feature names
FEATURE_NAMES = [
    "packet_count",
    "bytes",
    "connection_count",
    "connection_duration",
    "unique_destination_ports",
    "unique_destination_ips",
    "failed_connections",
    "traffic_rate"
]

def generate_and_save_training_dataset(
    output_path: str = CSV_PATH,
    n_normal_per_role: int = 500,
    n_anomalies: int = 250,
    random_seed: int = 42
) -> str:
    """
    Generate representative (imbalanced) synthetic training dataset for network anomaly detection (2,000 normal, 250 anomalous).
    Covers 4 roles: endpoint, server, iot, network.
    Includes normal baselines and realistic anomalies (scans, exfiltration, brute-force).
    Saves to data/simulation/training_data.csv with explicit synthetic documentation header.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    rng = np.random.RandomState(random_seed)

    rows: List[Dict[str, Any]] = []

    # 1. Role: Endpoint (Workstations, Laptops)
    # Typical: HTTP/S web, DNS, local print, business apps, multi-tab browsing across 30s window
    for _ in range(n_normal_per_role):
        is_burst = rng.rand() < 0.35
        if is_burst:
            pkts = rng.gamma(shape=4.5, scale=20.0) + 10
            dur = rng.exponential(scale=1.8) + 0.2
            b = pkts * rng.uniform(350, 1400)
            conns = rng.poisson(lam=9.0) + 3
            ports = rng.choice([1, 2, 3, 4], p=[0.55, 0.30, 0.12, 0.03])
            ips = rng.choice([1, 2, 3], p=[0.60, 0.30, 0.10])
        else:
            pkts = rng.gamma(shape=2.5, scale=8.0) + 4
            dur = rng.exponential(scale=0.8) + 0.1
            b = pkts * rng.uniform(200, 1100)
            conns = rng.poisson(lam=4.0) + 1
            ports = rng.choice([1, 2, 3], p=[0.75, 0.20, 0.05])
            ips = rng.choice([1, 2], p=[0.80, 0.20])
        failed = 1 if rng.rand() < 0.01 else 0
        rate = b / max(0.001, dur)
        rows.append({
            "role": "endpoint",
            "packet_count": round(pkts, 1),
            "bytes": int(b),
            "connection_count": int(conns),
            "connection_duration": round(dur, 3),
            "unique_destination_ports": int(ports),
            "unique_destination_ips": int(ips),
            "failed_connections": int(failed),
            "traffic_rate": round(rate, 2),
            "is_anomaly": 0
        })

    # 2. Role: Server (Application Server, Database)
    # Higher throughput, constant connections, few fixed ports (443, 5432)
    for _ in range(n_normal_per_role):
        pkts = rng.gamma(shape=4.5, scale=16.0) + 10
        dur = rng.exponential(scale=1.5) + 0.1
        b = pkts * rng.uniform(400, 1500)
        conns = rng.poisson(lam=8.0) + 2
        ports = rng.choice([1, 2], p=[0.90, 0.10])
        ips = rng.choice([1, 2, 3, 4], p=[0.60, 0.25, 0.10, 0.05])
        failed = 1 if rng.rand() < 0.01 else 0
        rate = b / max(0.001, dur)
        rows.append({
            "role": "server",
            "packet_count": round(pkts, 1),
            "bytes": int(b),
            "connection_count": int(conns),
            "connection_duration": round(dur, 3),
            "unique_destination_ports": int(ports),
            "unique_destination_ips": int(ips),
            "failed_connections": int(failed),
            "traffic_rate": round(rate, 2),
            "is_anomaly": 0
        })

    # 3. Role: IoT (IP Cameras, Printers)
    # Camera: steady video stream, high rate, 1 destination. Printer: idle, rare burst.
    for _ in range(n_normal_per_role):
        is_camera = rng.rand() > 0.4
        if is_camera:
            pkts = rng.uniform(40, 240)
            dur = rng.uniform(0.3, 1.8)
            b = pkts * rng.uniform(700, 1400)
            conns = rng.choice([1, 2, 3, 4, 5])
            ports = 1
            ips = 1
            failed = 0
        else: # printer
            pkts = rng.uniform(3, 20)
            dur = rng.uniform(0.1, 0.8)
            b = pkts * rng.uniform(200, 900)
            conns = 1
            ports = 1
            ips = 1
            failed = 0
        rate = b / max(0.001, dur)
        rows.append({
            "role": "iot",
            "packet_count": round(pkts, 1),
            "bytes": int(b),
            "connection_count": int(conns),
            "connection_duration": round(dur, 3),
            "unique_destination_ports": int(ports),
            "unique_destination_ips": int(ips),
            "failed_connections": int(failed),
            "traffic_rate": round(rate, 2),
            "is_anomaly": 0
        })

    # 4. Role: Network Infrastructure (Router, Switch)
    # High routing volume, ICMP, DNS relay, ARP
    for _ in range(n_normal_per_role):
        pkts = rng.gamma(shape=5.0, scale=15.0) + 10
        dur = rng.exponential(scale=0.5) + 0.05
        b = pkts * rng.uniform(300, 1100)
        conns = rng.poisson(lam=8.0) + 3
        ports = rng.choice([1, 2, 3], p=[0.85, 0.12, 0.03])
        ips = rng.choice([2, 3, 4], p=[0.70, 0.20, 0.10])
        failed = 0
        rate = b / max(0.001, dur)
        rows.append({
            "role": "network",
            "packet_count": round(pkts, 1),
            "bytes": int(b),
            "connection_count": int(conns),
            "connection_duration": round(dur, 3),
            "unique_destination_ports": int(ports),
            "unique_destination_ips": int(ips),
            "failed_connections": int(failed),
            "traffic_rate": round(rate, 2),
            "is_anomaly": 0
        })

    # 5. Anomalies (250 samples spanning 5 threat categories)
    # Anomaly 1: Port Scan Reconnaissance (70 samples)
    for _ in range(70):
        pkts = rng.uniform(40, 180)
        dur = rng.uniform(0.2, 1.5)
        b = pkts * 64 # small probe packets
        conns = rng.uniform(15, 60)
        ports = rng.uniform(12, 45)
        ips = rng.uniform(1, 4)
        failed = rng.uniform(8, 30)
        rate = b / max(0.001, dur)
        rows.append({
            "role": "endpoint",
            "packet_count": round(pkts, 1),
            "bytes": int(b),
            "connection_count": int(conns),
            "connection_duration": round(dur, 3),
            "unique_destination_ports": int(ports),
            "unique_destination_ips": int(ips),
            "failed_connections": int(failed),
            "traffic_rate": round(rate, 2),
            "is_anomaly": 1
        })

    # Anomaly 2: Volumetric Traffic Spike / Data Exfiltration (60 samples)
    for _ in range(60):
        pkts = rng.uniform(3000, 18000)
        dur = rng.uniform(0.5, 3.0)
        b = rng.uniform(1500000, 18000000) # >= 1.5 MB
        conns = rng.uniform(5, 25)
        ports = rng.choice([1, 2])
        ips = rng.choice([1, 2])
        failed = rng.choice([0, 1])
        rate = b / max(0.001, dur)
        rows.append({
            "role": "endpoint",
            "packet_count": round(pkts, 1),
            "bytes": int(b),
            "connection_count": int(conns),
            "connection_duration": round(dur, 3),
            "unique_destination_ports": int(ports),
            "unique_destination_ips": int(ips),
            "failed_connections": int(failed),
            "traffic_rate": round(rate, 2),
            "is_anomaly": 1
        })

    # Anomaly 3: Brute-Force Authentication Storm (45 samples)
    for _ in range(45):
        pkts = rng.uniform(60, 200)
        dur = rng.uniform(0.4, 2.0)
        b = pkts * rng.uniform(120, 250)
        conns = rng.uniform(10, 35)
        ports = 1 # target port 22 SSH or 3389 RDP
        ips = 1
        failed = rng.uniform(7, 28)
        rate = b / max(0.001, dur)
        rows.append({
            "role": "endpoint",
            "packet_count": round(pkts, 1),
            "bytes": int(b),
            "connection_count": int(conns),
            "connection_duration": round(dur, 3),
            "unique_destination_ports": int(ports),
            "unique_destination_ips": int(ips),
            "failed_connections": int(failed),
            "traffic_rate": round(rate, 2),
            "is_anomaly": 1
        })

    # Anomaly 4: Suspicious Outbound / C2 Beaconing (40 samples)
    for _ in range(40):
        pkts = rng.uniform(40, 120)
        dur = rng.uniform(0.1, 0.4)
        b = pkts * rng.uniform(400, 900)
        conns = rng.uniform(5, 15)
        ports = rng.choice([1, 2]) # 1-2 distinct outbound ports (e.g. 4444)
        ips = 1 # external WAN destination
        failed = rng.choice([0, 1, 2])
        rate = b / max(0.001, dur)
        rows.append({
            "role": "endpoint",
            "packet_count": round(pkts, 1),
            "bytes": int(b),
            "connection_count": int(conns),
            "connection_duration": round(dur, 3),
            "unique_destination_ports": int(ports),
            "unique_destination_ips": int(ips),
            "failed_connections": int(failed),
            "traffic_rate": round(rate, 2),
            "is_anomaly": 1
        })

    # Anomaly 5: Compromised Host Lateral Traversal (35 samples)
    for _ in range(35):
        pkts = rng.uniform(250, 900)
        dur = rng.uniform(0.3, 1.8)
        b = pkts * rng.uniform(300, 950)
        conns = rng.uniform(8, 25)
        ports = rng.uniform(4, 12)
        ips = rng.uniform(3, 8)
        failed = rng.uniform(2, 8)
        rate = b / max(0.001, dur)
        rows.append({
            "role": "endpoint",
            "packet_count": round(pkts, 1),
            "bytes": int(b),
            "connection_count": int(conns),
            "connection_duration": round(dur, 3),
            "unique_destination_ports": int(ports),
            "unique_destination_ips": int(ips),
            "failed_connections": int(failed),
            "traffic_rate": round(rate, 2),
            "is_anomaly": 1
        })

    # Write to CSV with clear documentation banner (Task 1 requirement)
    fieldnames = ["role"] + FEATURE_NAMES + ["is_anomaly"]
    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        f.write("# NetGuardian AI Anomaly Detection Synthetic Training Dataset\n")
        f.write("# Synthetic data is used for demonstration and does not represent a production-grade threat intelligence dataset.\n")
        f.write(f"# Total Samples: {len(rows)} | Normal: {n_normal_per_role * 4} | Anomalies: {n_anomalies}\n")
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return output_path

if __name__ == "__main__":
    path = generate_and_save_training_dataset()
    print(f"Generated synthetic training dataset at: {path}")
