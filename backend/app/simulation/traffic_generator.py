import random
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.device import Device
from app.models.traffic import TrafficRecord
from app.models.connection import NetworkConnection
from app.detection.rule_engine import RuleDetectionEngine
from app.ml.model import ai_detector
from app.digital_twin.twin_engine import digital_twin
from app.config import settings
from app.utils.time_utils import utcnow

class SyntheticTrafficGenerator:
    """
    Phase 2 Traffic Engine:
    - Generates realistic, deterministic (seeded) or stochastic synthetic traffic.
    - Implements required normal patterns:
        * PC -> Server (443 HTTPS)
        * PC -> DNS (53 UDP)
        * Phone -> Internet (80/443 Web)
        * PC -> Printer (9100 RAW)
        * Server -> Database (5432 PostgreSQL)
        * Camera -> Server (554 RTSP)
    - Naturally varying values (packets, bytes, durations) that are never identical.
    - Scenarios: Normal, Light, Busy, Suspicious Activity, Security Incident.
    - Aggregates flows into network_connections and prunes historical traffic_records table.
    - Baseline learning from warm-up normal ticks per device (bytes, connections, usual peers).
    """

    @property
    def max_records_stored(self) -> int:
        return getattr(settings, "MAX_TRAFFIC_RECORDS", 50000)

    def __init__(self, seed: Optional[int] = 42):
        if seed is not None:
            self.set_seed(seed)
        else:
            self.simulated_clock = utcnow()
        self.tick_counter = 0
        self.current_seed: Optional[int] = seed
        self.is_paused: bool = False

        # Baseline profiling structures
        self.device_baselines: Dict[str, Dict[str, Any]] = {}
        self.is_baseline_learned: bool = False

    def set_seed(self, seed: int):
        """Set deterministic random seed for repeatable traffic generation."""
        self.current_seed = seed
        self.simulated_clock = utcnow()
        random.seed(seed)

    def learn_baseline(self, db: Session, warm_up_ticks: int = 5, seed: Optional[int] = 42) -> Dict[str, Any]:
        """
        Task 7 Baseline Learning:
        Runs warm-up ticks of normal traffic to calculate per-device baselines:
        - average bytes per tick
        - average connections per tick
        - set of usual peers (IPs)
        """
        if seed is not None:
            self.set_seed(seed)

        accumulated_bytes: Dict[str, int] = defaultdict(int)
        accumulated_flows: Dict[str, int] = defaultdict(int)
        usual_peers: Dict[str, Set[str]] = defaultdict(set)
        usual_ports: Dict[str, Set[int]] = defaultdict(set)

        for _ in range(warm_up_ticks):
            tick_records = self.generate_tick(db, scenario="NORMAL")
            for rec in tick_records:
                accumulated_bytes[rec.source_ip] += rec.bytes
                accumulated_bytes[rec.destination_ip] += rec.bytes
                accumulated_flows[rec.source_ip] += 1
                accumulated_flows[rec.destination_ip] += 1

                usual_peers[rec.source_ip].add(rec.destination_ip)
                usual_peers[rec.destination_ip].add(rec.source_ip)
                usual_ports[rec.source_ip].add(rec.destination_port)

        baselines = {}
        all_ips = set(accumulated_bytes.keys())
        for ip in all_ips:
            baselines[ip] = {
                "avg_bytes_per_tick": round(accumulated_bytes[ip] / max(1, warm_up_ticks), 1),
                "avg_flows_per_tick": round(accumulated_flows[ip] / max(1, warm_up_ticks), 1),
                "usual_peers": sorted(list(usual_peers[ip])),
                "usual_ports": sorted(list(usual_ports[ip])),
                "warm_up_ticks": warm_up_ticks
            }

        self.device_baselines = baselines
        self.is_baseline_learned = True
        return self.get_baseline_summary()

    def get_baseline_summary(self) -> Dict[str, Any]:
        """Return learned baseline metadata and device-level profiles."""
        return {
            "baseline_status": "LEARNED" if self.is_baseline_learned else "DEFAULT",
            "total_profiled_devices": len(self.device_baselines),
            "device_baselines": self.device_baselines
        }

    def pause(self):
        """Pause synthetic traffic generation."""
        self.is_paused = True

    def resume(self):
        """Resume synthetic traffic generation."""
        self.is_paused = False

    def step(
        self,
        db: Session,
        count: Optional[int] = None,
        scenario: str = "NORMAL",
        seed: Optional[int] = None
    ) -> List[TrafficRecord]:
        """Advance the simulation by exactly one single step (tick) even when paused."""
        return self.generate_tick(db, count=count, scenario=scenario, seed=seed, ignore_pause=True)

    def generate_tick(
        self,
        db: Session,
        count: Optional[int] = None,
        scenario: str = "NORMAL",
        seed: Optional[int] = None,
        ignore_pause: bool = False
    ) -> List[TrafficRecord]:
        """
        Generate a single tick (representing 10 simulated seconds of network activity).
        Applies scenario logic, ML inference, rule-based detection, and DB storage.
        """
        if self.is_paused and not ignore_pause:
            return []

        if seed is not None:
            self.set_seed(seed)

        devices = db.query(Device).filter(Device.status != "OFFLINE", Device.is_isolated == False).all()
        if len(devices) < 2:
            return []

        # Collect isolated and offline IP addresses to guarantee they never generate or receive traffic
        isolated_ips = {
            d.ip_address for d in db.query(Device).filter(
                (Device.status.in_(["ISOLATED", "OFFLINE"])) | (Device.is_isolated == True)
            ).all()
        }

        dev_by_type: Dict[str, List[Device]] = defaultdict(list)
        dev_map: Dict[str, Device] = {}
        for d in devices:
            dtype = (d.device_type or "workstation").lower()
            dev_by_type[dtype].append(d)
            dev_map[d.ip_address] = d

        # Resolve role IPs
        pc_nodes = dev_by_type.get("workstation", []) + dev_by_type.get("laptop", [])
        server_nodes = dev_by_type.get("server", [])
        db_nodes = dev_by_type.get("database", [])
        printer_nodes = dev_by_type.get("printer", [])
        phone_nodes = dev_by_type.get("mobile", [])
        camera_nodes = dev_by_type.get("camera", []) + dev_by_type.get("iot", [])
        router_nodes = dev_by_type.get("router", [])
        internet_nodes = dev_by_type.get("internet", [])

        # Default fallbacks
        dns_ip = router_nodes[0].ip_address if router_nodes else "192.168.1.1"
        inet_ip = internet_nodes[0].ip_address if internet_nodes else "203.0.113.1"
        server_ip = server_nodes[0].ip_address if server_nodes else "192.168.1.20"
        db_ip = db_nodes[0].ip_address if db_nodes else "192.168.1.21"
        printer_ip = printer_nodes[0].ip_address if printer_nodes else "192.168.1.30"

        scen = scenario.upper()
        if count is None:
            if scen == "LIGHT":
                flow_count = random.randint(2, 4)
            elif scen == "BUSY":
                flow_count = random.randint(15, 25)
            elif scen == "SUSPICIOUS_ACTIVITY":
                flow_count = random.randint(10, 16)
            elif scen == "SECURITY_INCIDENT":
                flow_count = random.randint(20, 35)
            else:  # NORMAL
                flow_count = random.randint(6, 12)
        else:
            flow_count = count

        created_records: List[TrafficRecord] = []
        rule_engine = RuleDetectionEngine(db)

        # Advance simulated clock by 10 seconds per tick
        if not hasattr(self, "simulated_clock") or self.simulated_clock is None:
            self.simulated_clock = utcnow()
        else:
            self.simulated_clock += timedelta(seconds=10)
        tick_timestamp = self.simulated_clock

        for _ in range(flow_count):
            flow = self._synthesize_flow(
                scen, pc_nodes, server_ip, db_ip, dns_ip, inet_ip, printer_ip,
                phone_nodes, camera_nodes, dev_map
            )
            if not flow:
                continue

            src_ip, dst_ip, proto, dport, pkts, bytes_cnt, dur = flow
            if src_ip in isolated_ips or dst_ip in isolated_ips:
                continue

            sport = random.randint(32768, 61000)

            # Feature vector for ML Anomaly Evaluation
            traffic_dict = {
                "packet_count": pkts,
                "bytes": bytes_cnt,
                "connection_count": 1,
                "duration": dur,
                "unique_dst_ports": 1,
                "unique_dst_ips": 1,
                "failed_connections": 1 if scen == "SECURITY_INCIDENT" and dport in [22, 23, 445] else 0,
                "traffic_rate": bytes_cnt / max(dur, 0.001)
            }

            src_dev = dev_map.get(src_ip)
            src_role = src_dev.device_type if src_dev else "endpoint"
            ai_result = ai_detector.predict(traffic_dict, role=src_role)
            is_anom = 1 if (ai_result["is_anomalous"] or scen in ["SECURITY_INCIDENT", "SUSPICIOUS_ACTIVITY"]) else 0

            # Store in traffic_records
            record = TrafficRecord(
                timestamp=tick_timestamp,
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol=proto,
                source_port=sport,
                destination_port=dport,
                packet_count=pkts,
                bytes=bytes_cnt,
                duration=dur,
                is_anomalous=is_anom,
                data_source="SIMULATED"
            )
            db.add(record)
            created_records.append(record)

            # Evaluate against Rule Engine
            rule_engine.evaluate_traffic_record(record)

            # Aggregate into network_connections
            src_dev = dev_map.get(src_ip)
            dst_dev = dev_map.get(dst_ip)
            if src_dev and dst_dev:
                conn = db.query(NetworkConnection).filter(
                    NetworkConnection.source_device_id == src_dev.id,
                    NetworkConnection.destination_device_id == dst_dev.id
                ).first()
                if conn:
                    conn.packet_count += pkts
                    conn.bytes_transferred += bytes_cnt
                    conn.timestamp = tick_timestamp
                else:
                    new_conn = NetworkConnection(
                        source_device_id=src_dev.id,
                        destination_device_id=dst_dev.id,
                        protocol=proto,
                        source_port=sport,
                        destination_port=dport,
                        packet_count=pkts,
                        bytes_transferred=bytes_cnt,
                        timestamp=tick_timestamp
                    )
                    db.add(new_conn)

        # Prune old records to keep database fast (Task 6)
        self._prune_old_records(db)

        # Run 3-tick window detection pipeline (Task 3)
        rule_engine.run_detection_pipeline(window_seconds=30)

        db.commit()
        self.tick_counter += 1

        # Periodic Digital Twin Graph sync
        if self.tick_counter % 3 == 0:
            digital_twin.sync_from_database(db)

        return created_records

    def _synthesize_flow(
        self,
        scenario: str,
        pc_nodes: List[Device],
        server_ip: str,
        db_ip: str,
        dns_ip: str,
        inet_ip: str,
        printer_ip: str,
        phone_nodes: List[Device],
        camera_nodes: List[Device],
        dev_map: Dict[str, Device]
    ) -> Optional[tuple]:
        """Synthesizes a naturally varying flow based on scenario and standard patterns."""
        pc_ip = random.choice(pc_nodes).ip_address if pc_nodes else "192.168.1.10"
        phone_ip = random.choice(phone_nodes).ip_address if phone_nodes else "192.168.1.14"
        cam_ip = random.choice(camera_nodes).ip_address if camera_nodes else "192.168.1.40"

        # Micro-jitter to guarantee values are never identical
        jitter_b = random.randint(-45, 85)
        jitter_p = random.randint(-1, 2)
        jitter_d = round(random.uniform(-0.015, 0.025), 3)

        if scenario == "SUSPICIOUS_ACTIVITY":
            # Suspicious port exploration or unusual flows
            weird_ports = [23, 445, 3389, 8080, 21, 1433]
            port = random.choice(weird_ports)
            pkts = max(3, 8 + jitter_p)
            bytes_cnt = max(300, 3200 + jitter_b)
            dur = max(0.02, 0.15 + jitter_d)
            return (pc_ip, server_ip, "TCP", port, pkts, bytes_cnt, dur)

        if scenario == "SECURITY_INCIDENT":
            # High-volume anomalous probes
            scan_ports = [22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]
            port = random.choice(scan_ports)
            target = random.choice([server_ip, db_ip])
            pkts = max(10, 35 + jitter_p * 3)
            bytes_cnt = max(1500, 18500 + jitter_b * 10)
            dur = max(0.01, 0.05 + jitter_d)
            return (pc_ip, target, "TCP", port, pkts, bytes_cnt, dur)

        # Standard normal patterns from Phase 2 Task 4:
        # 1. PC -> Server (443)
        # 2. PC -> DNS (53)
        # 3. Phone -> Internet (80/443)
        # 4. PC -> Printer (9100)
        # 5. Server -> Database (5432)
        # 6. Camera -> Server (554)
        pattern = random.choice(["PC_SERVER", "PC_DNS", "PHONE_INET", "PC_PRINTER", "SERVER_DB", "CAM_SERVER"])

        if pattern == "PC_SERVER":
            pkts = max(2, 6 + jitter_p)
            bytes_cnt = max(500, 2800 + jitter_b)
            dur = max(0.03, 0.08 + jitter_d)
            return (pc_ip, server_ip, "TCP", 443, pkts, bytes_cnt, dur)

        elif pattern == "PC_DNS":
            pkts = max(1, 2 + jitter_p)
            bytes_cnt = max(40, 96 + jitter_b // 2)
            dur = max(0.005, 0.015 + jitter_d)
            return (pc_ip, dns_ip, "UDP", 53, pkts, bytes_cnt, dur)

        elif pattern == "PHONE_INET":
            pkts = max(3, 8 + jitter_p)
            bytes_cnt = max(600, 3500 + jitter_b)
            dur = max(0.04, 0.12 + jitter_d)
            port = 443 if random.random() > 0.3 else 80
            return (phone_ip, inet_ip, "TCP", port, pkts, bytes_cnt, dur)

        elif pattern == "PC_PRINTER":
            pkts = max(5, 12 + jitter_p)
            bytes_cnt = max(1200, 6400 + jitter_b * 3)
            dur = max(0.1, 0.45 + jitter_d)
            return (pc_ip, printer_ip, "TCP", 9100, pkts, bytes_cnt, dur)

        elif pattern == "SERVER_DB":
            pkts = max(4, 10 + jitter_p)
            bytes_cnt = max(800, 4200 + jitter_b * 2)
            dur = max(0.02, 0.06 + jitter_d)
            return (server_ip, db_ip, "TCP", 5432, pkts, bytes_cnt, dur)

        elif pattern == "CAM_SERVER":
            pkts = max(15, 30 + jitter_p * 2)
            bytes_cnt = max(2000, 8900 + jitter_b * 4)
            dur = max(0.1, 0.25 + jitter_d)
            return (cam_ip, server_ip, "TCP", 554, pkts, bytes_cnt, dur)

        return None

    def _prune_old_records(self, db: Session):
        """Keep traffic_records table bounded to MAX_TRAFFIC_RECORDS (Item 5)."""
        limit_cap = self.max_records_stored
        count = db.query(func.count(TrafficRecord.id)).scalar() or 0
        if count > limit_cap:
            excess = count - limit_cap
            oldest_ids = db.query(TrafficRecord.id).order_by(TrafficRecord.id.asc()).limit(excess).all()
            if oldest_ids:
                ids_to_del = [r[0] for r in oldest_ids]
                db.query(TrafficRecord).filter(TrafficRecord.id.in_(ids_to_del)).delete(synchronize_session=False)

traffic_generator = SyntheticTrafficGenerator()
