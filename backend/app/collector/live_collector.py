import struct
import socket
import logging
import platform
from typing import Dict, Any, Optional, Tuple, Union
from datetime import datetime
from sqlalchemy.orm import Session

from app.config import settings
from app.utils.time_utils import utcnow
from app.models.device import Device
from app.models.connection import NetworkConnection
from app.models.traffic import TrafficRecord
from app.detection.rule_engine import RuleDetectionEngine
from app.digital_twin.twin_engine import digital_twin

logger = logging.getLogger("netguardian.collector")

def parse_raw_ip_packet(packet_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Passive Metadata-Only Packet Header Parser.
    Extracts purely network and transport layer headers:
      - source_ip, destination_ip, protocol, source_port, destination_port, packet_count, bytes, timestamp.
    
    STRICT PRIVACY / SECURITY SAFEGUARD:
    NEVER reads, decodes, extracts, or stores application payload contents,
    passwords, user credentials, or unencrypted data segments.
    """
    if len(packet_bytes) < 20:
        return None

    # Handle Ethernet frame if present (14 bytes)
    offset = 0
    if len(packet_bytes) >= 34:
        # Check for typical Ethernet II header (EtherType 0x0800 for IPv4 at byte offset 12)
        eth_type = struct.unpack("!H", packet_bytes[12:14])[0]
        if eth_type == 0x0800:
            offset = 14

    ip_header_bytes = packet_bytes[offset:offset + 20]
    if len(ip_header_bytes) < 20:
        return None

    # Unpack IPv4 Header: 
    # Version/IHL (1B), ToS (1B), Total Length (2B), ID (2B), Flags/Frag (2B), TTL (1B), Protocol (1B), Checksum (2B), Src IP (4B), Dst IP (4B)
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header_bytes)
    version_ihl = iph[0]
    version = version_ihl >> 4
    if version != 4:
        # Only IPv4 metadata currently aggregated
        return None

    ihl = (version_ihl & 0xF) * 4
    total_length = iph[2] or len(packet_bytes)
    protocol_num = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

    # Protocol mapping
    protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    protocol_str = protocol_map.get(protocol_num, f"IP-{protocol_num}")

    src_port = 0
    dst_port = 0

    transport_offset = offset + ihl
    if protocol_num == 6 and len(packet_bytes) >= transport_offset + 4:  # TCP
        tcph = struct.unpack("!HH", packet_bytes[transport_offset:transport_offset + 4])
        src_port = tcph[0]
        dst_port = tcph[1]
    elif protocol_num == 17 and len(packet_bytes) >= transport_offset + 4:  # UDP
        udph = struct.unpack("!HH", packet_bytes[transport_offset:transport_offset + 4])
        src_port = udph[0]
        dst_port = udph[1]

    # NOTICE: Any payload bytes beyond the transport header are STRICTLY DISCARDED.
    return {
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol": protocol_str,
        "source_port": src_port,
        "destination_port": dst_port,
        "packet_count": 1,
        "bytes": total_length,
        "timestamp": utcnow(),
        "payload_stored": False
    }

def sanitize_packet_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize and normalize dictionary packet header input.
    Guarantees no payload or sensitive text is carried through.
    """
    src_ip = str(data.get("source_ip", "0.0.0.0"))
    dst_ip = str(data.get("destination_ip", "0.0.0.0"))
    protocol = str(data.get("protocol", "TCP")).upper()
    src_port = int(data.get("source_port", 0))
    dst_port = int(data.get("destination_port", 80))
    pkts = int(data.get("packet_count", 1))
    bytes_count = int(data.get("bytes", 64))

    # Explicitly verify no payload is retained
    return {
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol": protocol,
        "source_port": src_port,
        "destination_port": dst_port,
        "packet_count": max(1, pkts),
        "bytes": max(0, bytes_count),
        "timestamp": utcnow(),
        "payload_stored": False
    }

class LivePacketCollector:
    """
    Passive Network Packet Collector & Metadata Streamer.
    Monitors authorized local network interfaces in passive mode only.
    Collects metadata strictly: IPs, ports, protocol, bytes, timestamp.
    """
    def __init__(self):
        self.is_capturing: bool = False
        self.last_error: Optional[str] = None
        self.capture_count: int = 0
        self.connection_frequency: Dict[Tuple[str, str], int] = {}

    def check_capture_capability(self) -> Tuple[bool, str]:
        """
        Check if the runtime environment possesses packet capture privileges
        (e.g. Administrator/root privileges, Npcap on Windows, raw socket driver).
        """
        # Under Windows, raw sockets require elevated administrator privileges or Npcap driver.
        # Check safely without perturbing network or raising unhandled crashes.
        try:
            # Test raw socket creation
            if platform.system().lower() == "windows":
                # Raw sockets on Windows require Administrator and typically fail with WinError 10013 / 10022
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.close()
                return True, "Raw packet driver available."
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.close()
                return True, "Raw packet driver available."
        except (PermissionError, OSError) as e:
            msg = "Live packet monitoring is unavailable. Switching to Simulation Mode."
            logger.info(f"Packet capture unavailable ({e}). Fallback active.")
            return False, msg
        except Exception as e:
            msg = "Live packet monitoring is unavailable. Switching to Simulation Mode."
            logger.warning(f"Packet probe encountered error: {e}. Fallback active.")
            return False, msg

    def enable_live_mode(self, consent_granted: bool = False, db: Optional[Session] = None) -> Dict[str, Any]:
        """
        Enable Live Monitoring Mode with explicit consent and driver verification.
        If permission or driver is missing, automatically falls back to Simulation Mode.
        """
        if not consent_granted:
            return {
                "ok": False,
                "status": "CONSENT_REQUIRED",
                "message": (
                    "Explicit consent notice required: Live mode passively monitors network metadata "
                    "on authorized networks only. You must acknowledge authorization before activating."
                ),
                "system_mode": "SIMULATION"
            }

        capable, reason = self.check_capture_capability()
        if not capable:
            settings.SYSTEM_MODE = "SIMULATION"
            self.last_error = reason
            return {
                "ok": False,
                "status": "FALLBACK",
                "message": reason,
                "system_mode": "SIMULATION",
                "notice": "The application fell back safely to Simulation Mode. No real network disruption occurred."
            }

        # If capable, activate live mode
        settings.SYSTEM_MODE = "LIVE"
        self.is_capturing = True
        return {
            "ok": True,
            "status": "LIVE_ACTIVE",
            "message": "Live monitoring mode activated passively on local interface.",
            "system_mode": "LIVE"
        }

    def switch_to_simulation(self) -> Dict[str, Any]:
        """Switch operational mode back to Simulation Mode."""
        self.is_capturing = False
        settings.SYSTEM_MODE = "SIMULATION"
        return {
            "ok": True,
            "status": "SIMULATION_ACTIVE",
            "message": "Switched to Simulation Mode.",
            "system_mode": "SIMULATION"
        }

    def process_packet(
        self,
        packet_input: Union[bytes, Dict[str, Any]],
        db: Session
    ) -> Dict[str, Any]:
        """
        Process a single packet (raw bytes or header dictionary).
        1. Strips payload, extracts metadata only.
        2. Discovers and tags unknown devices as OBSERVED / Unregistered.
        3. Persists TrafficRecord tagged with data_source='OBSERVED'.
        4. Updates connection frequency and Digital Twin.
        5. Evaluates Rule Engine.
        """
        if isinstance(packet_input, bytes):
            meta = parse_raw_ip_packet(packet_input)
            if not meta:
                return {"error": "Invalid or non-IPv4 packet bytes."}
        elif isinstance(packet_input, dict):
            meta = sanitize_packet_dict(packet_input)
        else:
            return {"error": "Unsupported packet input format."}

        src_ip = meta["source_ip"]
        dst_ip = meta["destination_ip"]

        # Track connection frequency
        pair_key = (src_ip, dst_ip)
        self.connection_frequency[pair_key] = self.connection_frequency.get(pair_key, 0) + 1
        freq = self.connection_frequency[pair_key]

        # 1. Device Discovery & Tagging: check if source IP is in known inventory
        src_dev = db.query(Device).filter(Device.ip_address == src_ip).first()
        is_new_device = False
        if not src_dev and src_ip not in ["0.0.0.0", "255.255.255.255", "127.0.0.1"]:
            # Auto-register newly observed host as OBSERVED and unregistered
            octets = src_ip.split(".")
            last_oct = octets[-1] if len(octets) == 4 else "x"
            mac_suffix = f"{int(octets[1]):02x}:{int(octets[2]):02x}:{int(octets[3]):02x}" if len(octets) == 4 and all(o.isdigit() for o in octets) else "00:00:01"
            
            src_dev = Device(
                device_name=f"Observed-Host-{last_oct}",
                ip_address=src_ip,
                mac_address=f"02:00:{mac_suffix}:99",
                device_type="Workstation",
                os_type="Unknown",
                criticality="LOW",
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
            db.add(src_dev)
            db.flush()
            is_new_device = True

        # 2. Persist TrafficRecord strictly with data_source='OBSERVED'
        rec = TrafficRecord(
            timestamp=meta["timestamp"],
            source_ip=src_ip,
            destination_ip=dst_ip,
            protocol=meta["protocol"],
            source_port=meta["source_port"],
            destination_port=meta["destination_port"],
            packet_count=meta["packet_count"],
            bytes=meta["bytes"],
            duration=0.05,
            is_anomalous=0,
            data_source="OBSERVED"
        )
        db.add(rec)
        db.commit()

        self.capture_count += 1

        # 3. Evaluate Rule Engine
        rule_engine = RuleDetectionEngine(db)
        if is_new_device:
            rule_engine.check_unknown_device(src_ip)
        rule_engine.evaluate_traffic_record(rec)

        # 4. Synchronize Digital Twin
        digital_twin.sync_from_database(db)

        return {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": meta["protocol"],
            "source_port": meta["source_port"],
            "destination_port": meta["destination_port"],
            "packet_count": meta["packet_count"],
            "bytes": meta["bytes"],
            "timestamp": meta["timestamp"].isoformat(),
            "connection_frequency": freq,
            "data_source": "OBSERVED",
            "is_unregistered_device": is_new_device,
            "payload_stored": False
        }

live_collector = LivePacketCollector()
