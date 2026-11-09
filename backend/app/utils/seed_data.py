from datetime import datetime
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.device import Device
from app.models.connection import NetworkConnection
from app.models.audit_log import SystemSetting, AuditLog
from app.models.alert import Alert, UserNotificationRead
from app.models.security_event import SecurityEvent
from app.models.traffic import TrafficRecord
from app.models.simulation import SimulationRun
from app.services.auth_service import hash_password
from app.config import settings
from app.database import Base, engine
from app.utils.time_utils import utcnow

def seed_database(db: Session, force_reset: bool = False):
    """Seed baseline users, devices, network topology, and system settings."""
    Base.metadata.create_all(bind=engine)
    if force_reset:
        db.query(UserNotificationRead).delete()
        db.query(Alert).delete()
        db.query(SecurityEvent).delete()
        db.query(TrafficRecord).delete()
        db.query(SimulationRun).delete()
        db.query(NetworkConnection).delete()
        db.query(Device).delete()
        db.query(User).delete()
        db.query(SystemSetting).delete()
        db.commit()

    # 1. Seed Users (passwords loaded from env / settings; DEMO ONLY)
    if db.query(User).count() == 0:
        admin_user = User(
            username="admin",
            email="admin@netguardian.local",
            password_hash=hash_password(settings.DEMO_ADMIN_PASSWORD),
            role="ADMIN",
            created_at=utcnow()
        )
        analyst_user = User(
            username="analyst",
            email="analyst@netguardian.local",
            password_hash=hash_password(settings.DEMO_ANALYST_PASSWORD),
            role="ANALYST",
            created_at=utcnow()
        )
        db.add_all([admin_user, analyst_user])
        db.commit()

    # 2. Seed Default System Settings
    default_settings = [
        {"key": "system_mode", "value": "SIMULATION", "description": "Operational Mode (SIMULATION or LIVE)"},
        {"key": "traffic_anomaly_threshold", "value": "3.0", "description": "Traffic volume anomaly multiplier"},
        {"key": "port_scan_threshold", "value": "15", "description": "Max unique ports scanned in 60s"},
        {"key": "failed_auth_threshold", "value": "5", "description": "Max failed logins in 30s"},
        {"key": "simulation_tick_seconds", "value": "2", "description": "Interval for synthetic traffic pulse"},
        {"key": "session_timeout_minutes", "value": "1440", "description": "Session timeout in minutes"},
    ]
    for s in default_settings:
        if not db.query(SystemSetting).filter(SystemSetting.key == s["key"]).first():
            db.add(SystemSetting(**s))
    db.commit()

    # 3. Seed Network Devices (Specification Names, Documentation IPs & Levels)
    # Baseline with NO events: every device risk_score = 0.0, status = ONLINE, health = 100
    if db.query(Device).count() == 0:
        devices_data = [
            {
                "device_name": "Internet",
                "ip_address": "203.0.113.1",
                "mac_address": "00:00:5E:00:53:01",
                "device_type": "Internet",
                "os_type": "External WAN",
                "criticality": "MEDIUM",
                "trust_level": "UNTRUSTED",
                "status": "ONLINE",
                "risk_score": 0.0,
                "trust_score": 20.0
            },
            {
                "device_name": "Router",
                "ip_address": "192.168.1.1",
                "mac_address": "00:1A:2B:3C:4D:01",
                "device_type": "Router",
                "os_type": "NetworkOS",
                "criticality": "HIGH",
                "trust_level": "HIGH",
                "status": "ONLINE",
                "risk_score": 0.0,
                "trust_score": 95.0
            },
            {
                "device_name": "Switch",
                "ip_address": "192.168.1.2",
                "mac_address": "00:1A:2B:3C:4D:02",
                "device_type": "Switch",
                "os_type": "NetworkOS",
                "criticality": "HIGH",
                "trust_level": "HIGH",
                "status": "ONLINE",
                "risk_score": 0.0,
                "trust_score": 95.0
            },
            {
                "device_name": "PC-01",
                "ip_address": "192.168.1.10",
                "mac_address": "00:1A:2B:3C:4D:10",
                "device_type": "Workstation",
                "os_type": "Windows 11",
                "criticality": "MEDIUM",
                "trust_level": "MEDIUM",
                "status": "ONLINE",
                "risk_score": 0.0,
                "trust_score": 80.0
            },
            {
                "device_name": "PC-02",
                "ip_address": "192.168.1.11",
                "mac_address": "00:1A:2B:3C:4D:11",
                "device_type": "Workstation",
                "os_type": "Windows 11",
                "criticality": "MEDIUM",
                "trust_level": "MEDIUM",
                "status": "ONLINE",
                "risk_score": 0.0,
                "trust_score": 80.0
            },
            {
                "device_name": "PC-03",
                "ip_address": "192.168.1.12",
                "mac_address": "00:1A:2B:3C:4D:12",
                "device_type": "Workstation",
                "os_type": "Ubuntu Linux",
                "criticality": "MEDIUM",
                "trust_level": "MEDIUM",
                "status": "ONLINE",
                "risk_score": 0.0,
                "trust_score": 80.0
            },
            {
                "device_name": "PC-04",
                "ip_address": "192.168.1.13",
                "mac_address": "00:1A:2B:3C:4D:13",
                "device_type": "Laptop",
                "os_type": "macOS",
                "criticality": "MEDIUM",
                "trust_level": "MEDIUM",
                "status": "ONLINE",
                "risk_score": 0.0,
                "trust_score": 80.0
            },
            {
                "device_name": "Phone-01",
                "ip_address": "192.168.1.14",
                "mac_address": "00:1A:2B:3C:4D:14",
                "device_type": "Mobile",
                "os_type": "Android",
                "criticality": "LOW",
                "trust_level": "LOW",
                "status": "ONLINE",
                "risk_score": 0.0,
                "trust_score": 50.0
            },
            {
                "device_name": "Printer",
                "ip_address": "192.168.1.30",
                "mac_address": "00:1A:2B:3C:4D:30",
                "device_type": "Printer",
                "os_type": "Embedded RTOS",
                "criticality": "LOW",
                "trust_level": "MEDIUM",
                "status": "ONLINE",
                "risk_score": 0.0,
                "trust_score": 80.0
            },
            {
                "device_name": "Server",
                "ip_address": "192.168.1.20",
                "mac_address": "00:1A:2B:3C:4D:20",
                "device_type": "Server",
                "os_type": "Debian Linux",
                "criticality": "HIGH",
                "trust_level": "HIGH",
                "status": "ONLINE",
                "risk_score": 0.0,
                "trust_score": 95.0
            },
            {
                "device_name": "Database",
                "ip_address": "192.168.1.21",
                "mac_address": "00:1A:2B:3C:4D:21",
                "device_type": "Database",
                "os_type": "Enterprise Linux",
                "criticality": "CRITICAL",
                "trust_level": "HIGH",
                "status": "ONLINE",
                "risk_score": 0.0,
                "trust_score": 95.0
            },
            {
                "device_name": "IoT-Camera",
                "ip_address": "192.168.1.40",
                "mac_address": "00:1A:2B:3C:4D:40",
                "device_type": "Camera",
                "os_type": "Embedded Linux",
                "criticality": "LOW",
                "trust_level": "LOW",
                "status": "ONLINE",
                "risk_score": 0.0,
                "trust_score": 50.0
            },
        ]
        created_devices = {}
        for d in devices_data:
            dev = Device(**d, first_seen=utcnow(), last_seen=utcnow())
            db.add(dev)
            db.flush()
            created_devices[dev.device_name] = dev

        # 4. Seed Connections: Internet–Router–Switch–endpoints/Server, Server–Database
        internet = created_devices["Internet"]
        router = created_devices["Router"]
        switch = created_devices["Switch"]
        server = created_devices["Server"]
        db_node = created_devices["Database"]

        conns = [
            # Internet <-> Router
            (internet.id, router.id, "WAN", 0, 0, 5000, 4194304),
            (router.id, internet.id, "WAN", 0, 0, 4800, 3932160),
            # Router <-> Switch
            (router.id, switch.id, "ETHERNET", 0, 0, 3500, 3145728),
            (switch.id, router.id, "ETHERNET", 0, 0, 3400, 2980000),
        ]

        # Endpoints & Server <-> Switch
        endpoint_names = [
            "PC-01", "PC-02", "PC-03", "PC-04",
            "Phone-01", "Printer", "IoT-Camera", "Server"
        ]
        for name in endpoint_names:
            node = created_devices[name]
            conns.append((node.id, switch.id, "ETHERNET", 0, 0, 400, 250000))
            conns.append((switch.id, node.id, "ETHERNET", 0, 0, 380, 240000))

        # Server <-> Database (Direct database link only, isolated from switch)
        conns.append((server.id, db_node.id, "POSTGRESQL", 54321, 5432, 1200, 1450000))
        conns.append((db_node.id, server.id, "POSTGRESQL", 5432, 54321, 1150, 1400000))

        for src, dst, proto, sport, dport, pkts, bytes_tr in conns:
            conn = NetworkConnection(
                source_device_id=src,
                destination_device_id=dst,
                protocol=proto,
                source_port=sport,
                destination_port=dport,
                packet_count=pkts,
                bytes_transferred=bytes_tr,
                timestamp=utcnow()
            )
            db.add(conn)

        db.commit()
