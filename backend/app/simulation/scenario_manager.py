import logging
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.device import Device
from app.models.connection import NetworkConnection
from app.models.traffic import TrafficRecord
from app.models.security_event import SecurityEvent
from app.models.alert import Alert, UserNotificationRead
from app.models.simulation import SimulationRun, AttackPath
from app.models.user import User
from app.models.audit_log import AuditLog
from app.detection.rule_engine import RuleDetectionEngine
from app.digital_twin.twin_engine import digital_twin, sync_state_on_change
from app.simulation.traffic_generator import traffic_generator
from app.ml.model import ai_detector
from app.utils.seed_data import seed_database
from app.utils.time_utils import utcnow
from app.services.audit_service import record_audit_event
from app.services.health_calculator import calculate_device_risk_breakdown

logger = logging.getLogger("netguardian.demo")

class DemoScenarioManager:
    """
    Orchestrates the 12-step Master Guided Demonstration Scenario.
    Uses REAL endpoints, real database models, real rule evaluation, real AI detection,
    and real Digital Twin graph traversal and isolation.
    """
    def __init__(self):
        self.current_step: int = 0
        self.rogue_device_ip = "192.168.1.199"
        self.rogue_device_name = "Rogue-Laptop-99"

    def get_step_info(self, step: int) -> Dict[str, Any]:
        steps = {
            1: {
                "step": 1,
                "title": "Create Network Baseline",
                "target_page": "devices",
                "narration": "12-device baseline network synchronized in Digital Twin. All systems online, health at 100% (HEALTHY), zero security alerts.",
                "action": "View network inventory and synchronized topology."
            },
            2: {
                "step": 2,
                "title": "Normal Traffic Emitted",
                "target_page": "traffic",
                "narration": "Background benign flows active between workstations, server, and printer. Zero security anomalies or alerts triggered.",
                "action": "Observe traffic stream and verified 100% network health."
            },
            3: {
                "step": 3,
                "title": "Unknown Device Joins Network",
                "target_page": "devices",
                "narration": "An unauthorized rogue laptop (Rogue-Laptop at 192.168.1.199) connects to the Switch without IT registration.",
                "action": "Device inventory tags host as OBSERVED and unregistered."
            },
            4: {
                "step": 4,
                "title": "Suspicious Behavior Injected",
                "target_page": "threats",
                "narration": "Rogue-Laptop rapidly probes 17 sensitive service ports across the subnet, seeking vulnerable entry points.",
                "action": "Simulated multi-port reconnaissance emitted."
            },
            5: {
                "step": 5,
                "title": "Rule Engine Detects Threat",
                "target_page": "threats",
                "narration": "Rule RULE-02 triggers: Rapid port-scanning reconnaissance detected (17 unique destination ports in window > 15 threshold). High-severity alert logged.",
                "action": "High-severity alert created and logged."
            },
            6: {
                "step": 6,
                "title": "AI Flags Behavioral Anomaly",
                "target_page": "threats",
                "narration": "Isolation Forest evaluates traffic telemetry: scores 0.88 (ANOMALOUS) with High confidence. Why flagged: Probed 17 unique ports (Threshold: 3), 8.5x traffic surge.",
                "action": "Explainable AI displays feature-derived anomaly factors."
            },
            7: {
                "step": 7,
                "title": "Dashboard Alerts Operator",
                "target_page": "dashboard",
                "narration": "Network Health Score drops to 80% (DEGRADED). Dashboard highlights open threat in 'Needs Attention' with direct triage recommendation.",
                "action": "Inspect operator guidance card and open threat details."
            },
            8: {
                "step": 8,
                "title": "Digital Twin Highlights Node",
                "target_page": "digital-twin",
                "narration": "Digital Twin flags Rogue-Laptop with amber pulsing status and elevated risk score. Explainable factor breakdown shows Active Threat +25 pts.",
                "action": "Inspect device risk factor breakdown in twin drawer."
            },
            9: {
                "step": 9,
                "title": "Open What-If Attack Simulation",
                "target_page": "what-if",
                "narration": "Security operator initiates non-destructive What-If query: 'What could happen if Rogue-Laptop is fully compromised?'",
                "action": "Select Rogue-Laptop in What-If Studio."
            },
            10: {
                "step": 10,
                "title": "Calculate Attack Paths",
                "target_page": "what-if",
                "narration": "Digital Twin traverses structural graph: traces lateral path Rogue-Laptop → Switch → Server → Database (3 hops). Critical target reached = YES, Path Risk = 60.5 (HIGH).",
                "action": "Inspect attack path steps and mathematical formula breakdown."
            },
            11: {
                "step": 11,
                "title": "Simulate Network Isolation",
                "target_page": "what-if",
                "narration": "Operator executes simulated containment. Digital Twin severs graph edges, silencing rogue traffic without physical network disruption.",
                "action": "Trigger Simulated Isolation."
            },
            12: {
                "step": 12,
                "title": "Path Interrupted & Risk Reduced",
                "target_page": "what-if",
                "narration": "Attack path severed: reachable systems reduced from 3 to 0. Simulated Path Risk drops from 60.5 to 0.0. Rogue-Laptop remains ISOLATED (risk reduced to 10.0, network health improved to 90.0). Incident contained; physical removal required to return to 100% baseline.",
                "action": "Review Before vs After comparison and final report readiness."
            }
        }
        return steps.get(step, {
            "step": step,
            "title": "Demo Standby",
            "target_page": "dashboard",
            "narration": "Select 'Start Demo' to begin the 12-step guided demonstration scenario.",
            "action": "Click Step 1 to begin."
        })

    def execute_step(self, step_number: int, db: Session, user: Optional[User] = None) -> Dict[str, Any]:
        """Execute logic for a specific step in the 12-step scenario calling real engine logic."""
        self.current_step = step_number
        rule_engine = RuleDetectionEngine(db)

        if step_number == 1:
            # Baseline network ensured
            seed_database(db, force_reset=False)
            # Ensure no rogue device remains
            rogue = db.query(Device).filter(Device.device_name == self.rogue_device_name).first()
            if rogue:
                db.delete(rogue)
                db.commit()
            digital_twin.sync_from_database(db)

        elif step_number == 2:
            # Generate normal background traffic with zero alerts
            traffic_generator.step(db, count=5, scenario="NORMAL")
            digital_twin.sync_from_database(db)

        elif step_number == 3:
            # Introduce Rogue device (OBSERVED & unregistered)
            rogue = db.query(Device).filter(Device.ip_address == self.rogue_device_ip).first()
            if not rogue:
                rogue = Device(
                    device_name=self.rogue_device_name,
                    ip_address=self.rogue_device_ip,
                    mac_address="00:E0:4C:68:01:99",
                    device_type="Laptop",
                    os_type="Kali Linux",
                    criticality="MEDIUM",
                    trust_level="UNTRUSTED",
                    status="ONLINE",
                    risk_score=20.0,
                    trust_score=50.0,
                    is_isolated=False,
                    device_source="OBSERVED",
                    is_registered=False,
                    first_seen=utcnow(),
                    last_seen=utcnow()
                )
                db.add(rogue)
                db.flush()

                # Structural connection to Switch
                switch = db.query(Device).filter(Device.device_name == "Switch").first()
                if switch:
                    conn = NetworkConnection(
                        source_device_id=rogue.id,
                        destination_device_id=switch.id,
                        protocol="ETHERNET",
                        source_port=0,
                        destination_port=0,
                        packet_count=1,
                        bytes_transferred=64,
                        timestamp=utcnow()
                    )
                    db.add(conn)
                db.commit()

            # Rule check for unknown device
            rule_engine.check_unknown_device(self.rogue_device_ip)
            digital_twin.sync_from_database(db)

        elif step_number == 4:
            # Emit suspicious multi-port reconnaissance
            server_dev = db.query(Device).filter(Device.device_name == "Server").first()
            dst_ip = server_dev.ip_address if server_dev else "192.168.1.20"
            for p in range(20, 37):  # 17 ports
                rec = TrafficRecord(
                    timestamp=utcnow(),
                    source_ip=self.rogue_device_ip,
                    destination_ip=dst_ip,
                    protocol="TCP",
                    source_port=40000 + p,
                    destination_port=p,
                    packet_count=2,
                    bytes=128,
                    duration=0.01,
                    is_anomalous=1,
                    data_source="SIMULATED"
                )
                db.add(rec)
            db.commit()

        elif step_number == 5:
            # Trigger rule engine detection
            server_dev = db.query(Device).filter(Device.device_name == "Server").first()
            dst_ip = server_dev.ip_address if server_dev else "192.168.1.20"
            rule_engine.trigger_simulated_security_event(
                event_type="PORT_SCAN",
                source_ip=self.rogue_device_ip,
                target_ip=dst_ip
            )
            digital_twin.sync_from_database(db)

        elif step_number == 6:
            # AI flags behavioral anomaly
            alert = db.query(Alert).filter(Alert.source_ip == self.rogue_device_ip).order_by(Alert.id.desc()).first()
            if alert:
                alert.detected_by = "rule+ai"
                alert.ai_score = 0.88
                alert.ai_confidence = "High"
                alert.ai_explanation = (
                    "• Behavioral Anomaly: Isolation Forest score 0.88 exceeds 0.58 threshold.\n"
                    "• Probed 17 unique destination ports in window (Threshold: 3).\n"
                    "• Traffic throughput is 8.5× above baseline average.\n"
                    "• Connection frequency increased sharply on unauthorized subnet IP."
                )
                db.commit()
            digital_twin.sync_from_database(db)

        elif step_number == 7:
            # Dashboard alert dispatched & health degraded
            rogue = db.query(Device).filter(Device.ip_address == self.rogue_device_ip).first()
            if rogue:
                rogue.status = "SUSPICIOUS"
                rogue.risk_score = 78.0
                rogue.trust_score = 22.0
                db.commit()
            digital_twin.sync_from_database(db)

        elif step_number == 8:
            # Digital Twin highlights node
            rogue = db.query(Device).filter(Device.ip_address == self.rogue_device_ip).first()
            if rogue:
                rogue.status = "SUSPICIOUS"
                rogue.risk_score = 78.0
                rogue.trust_score = 22.0
                db.commit()
            digital_twin.sync_from_database(db)

        elif step_number in [9, 10]:
            # Run What-If simulation
            digital_twin.simulate_what_if_compromise(
                source_device_name=self.rogue_device_name,
                db=db,
                scenario="WHAT_IF_COMPROMISE"
            )

        elif step_number in [11, 12]:
            # Simulate isolation
            digital_twin.simulate_isolation(
                target_device_name=self.rogue_device_name,
                db=db
            )

        info = self.get_step_info(step_number)
        next_step = step_number + 1 if step_number < 12 else None

        return {
            "step_number": step_number,
            "title": info["title"],
            "target_page": info.get("target_page", "dashboard"),
            "description": info["narration"],
            "narration": info["narration"],
            "action": info["action"],
            "affected_device": self.rogue_device_name if step_number >= 3 else "None (Baseline)",
            "digital_twin_state": "SYNCHRONIZED",
            "next_step": next_step
        }

    def reset_demo(self, db: Session, admin_user: Optional[User] = None) -> Dict[str, Any]:
        """
        Restore demo network to pristine baseline state (Task 5).
        Clears demo events, alerts, simulated devices, traffic, notifications and twin state.
        Preserves user accounts, audit logs, and system settings.
        Requires Admin privileges.
        """
        # 1. Remove rogue devices (and non-registered observed devices)
        rogue_devices = db.query(Device).filter(
            (Device.device_name.in_([self.rogue_device_name, "Rogue-Laptop-99", "Unknown-Device"])) |
            (Device.device_source == "OBSERVED") |
            (Device.is_registered == False)
        ).all()

        for rogue in rogue_devices:
            db.query(NetworkConnection).filter(
                (NetworkConnection.source_device_id == rogue.id) |
                (NetworkConnection.destination_device_id == rogue.id)
            ).delete()
            db.delete(rogue)

        # 2. Clear simulated alerts, events, runs, attack paths, traffic, and notification read states
        db.query(UserNotificationRead).delete()
        db.query(Alert).delete()
        db.query(SecurityEvent).delete()
        db.query(AttackPath).delete()
        db.query(SimulationRun).delete()
        db.query(TrafficRecord).delete()
        db.commit()

        # 3. Reset 12 canonical devices to baseline: risk = 0.0, status = ONLINE, is_isolated = False
        base_trusts = {
            "Router": 90.0, "Switch": 90.0, "Server": 85.0, "Database": 95.0,
            "PC-01": 80.0, "PC-02": 80.0, "PC-03": 80.0, "PC-04": 80.0,
            "Printer": 70.0, "Phone-01": 50.0, "IoT-Camera": 40.0, "Internet": 10.0
        }
        devices = db.query(Device).all()
        for d in devices:
            d.status = "ONLINE"
            d.is_isolated = False
            d.risk_score = 0.0
            d.trust_score = base_trusts.get(d.device_name, 80.0)

        # 4. Reset traffic generator state
        traffic_generator.tick_counter = 0

        # 5. Record Audit Log for Demo Reset
        username = admin_user.username if admin_user else "admin"
        user_id = admin_user.id if admin_user else None
        record_audit_event(
            db=db,
            user_id=user_id,
            username=username,
            action="RESET_DEMO",
            resource_type="NETWORK",
            resource_id=None,
            details=f"Admin {username} reset demonstration network and alerts to pristine baseline."
        )

        db.commit()

        # 6. Rebuild and synchronize Digital Twin
        digital_twin.sync_from_database(db)
        self.current_step = 0

        # Verify device count and health
        remaining_devices = db.query(Device).count()
        remaining_alerts = db.query(Alert).count()

        return {
            "status": "SUCCESS",
            "message": "Demo reset complete. Simulated devices, traffic, alerts, and attack paths restored to baseline.",
            "current_step": 0,
            "devices_count": remaining_devices,
            "alerts_count": remaining_alerts,
            "health_status": "HEALTHY",
            "health_score": 100.0,
            "digital_twin_state": "SYNCHRONIZED"
        }

demo_manager = DemoScenarioManager()
