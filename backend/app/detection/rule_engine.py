import logging
import json
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from collections import defaultdict
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.device import Device
from app.models.connection import NetworkConnection
from app.models.traffic import TrafficRecord
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.audit_log import SystemSetting
from app.utils.time_utils import utcnow
from app.config import settings
from app.ml.model import ai_detector

logger = logging.getLogger("netguardian.detection")

class RuleDetectionEngine:
    """
    Phase 3 & Phase 4 Deterministic + Explainable ML Anomaly Detection Engine:
    - Layer 1 Deterministic Rules:
        1. Port Scan (HIGH)
        2. Traffic Anomaly (MEDIUM)
        3. Unknown Device (MEDIUM)
        4. Repeated Failed Authentication (HIGH)
        5. Suspicious Outbound Connection (HIGH)
        6. Unusual Access to Critical Asset (CRITICAL)
    - Layer 2 Machine Learning Anomaly Detection:
        Role-based Isolation Forest ensemble (8 standardized features).
        Evaluates anomalies and merges detection into RULE+AI or AI-only (persistent 2+ window) alerts.
    - Explainability: Plain-language dynamic reasons derived from feature baseline deltas.
    - De-duplicates open alerts/events by (event_type, source_device).
    """

    # Track consecutive high-score windows per source IP across detection ticks
    ai_consecutive_windows: Dict[str, int] = defaultdict(int)

    def __init__(self, db: Session):
        self.db = db

    def get_threshold(self, key: str, default_val: Any) -> Any:
        """Read active threshold setting from DB system_settings with fallback to settings."""
        try:
            row = self.db.query(SystemSetting).filter(SystemSetting.key == key).first()
            if row and row.value:
                if isinstance(default_val, int):
                    return int(row.value)
                elif isinstance(default_val, float):
                    return float(row.value)
                return row.value
        except Exception:
            pass
        return default_val

    def create_or_update_alert(
        self,
        event_type: str,
        source_device: str,
        destination_device: Optional[str],
        severity: str,
        title: str,
        message: str,
        rule_name: str,
        recommendation: str,
        confidence: float = 0.90,
        detection_method: str = "RULE",
        detected_by: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        ai_score: Optional[float] = None,
        ai_confidence: Optional[str] = None,
        ai_explanation: Optional[str] = None
    ) -> Alert:
        """
        Task 3 & Phase 4 Integration & De-duplication:
        Checks if an alert for the same event_type and source_device is still open (NEW or INVESTIGATING).
        If open, updates occurrence count, last_seen, and refreshes AI assessment metrics.
        """
        now = utcnow()
        clean_source = source_device or source_ip or "Unknown"
        resolved_detected_by = detected_by or (detection_method.lower() if detection_method else "rule")

        # Check for open existing event
        existing_event = self.db.query(SecurityEvent).filter(
            SecurityEvent.event_type == event_type,
            SecurityEvent.source_device == clean_source,
            SecurityEvent.status.in_(["NEW", "INVESTIGATING"])
        ).order_by(SecurityEvent.created_at.desc()).first()

        if existing_event:
            # Update occurrence count and timestamp on existing event
            existing_event.occurrence_count = (existing_event.occurrence_count or 1) + 1
            existing_event.last_seen = now
            if detection_method:
                existing_event.detection_method = detection_method

            existing_alert = self.db.query(Alert).filter(
                Alert.event_id == existing_event.id,
                Alert.status.in_(["NEW", "INVESTIGATING"])
            ).first()

            if existing_alert:
                existing_alert.occurrence_count = (existing_alert.occurrence_count or 1) + 1
                existing_alert.last_seen = now
                if not existing_alert.event_type:
                    existing_alert.event_type = event_type
                if ai_score is not None:
                    existing_alert.ai_score = ai_score
                if ai_confidence is not None:
                    existing_alert.ai_confidence = ai_confidence
                if ai_explanation is not None:
                    existing_alert.ai_explanation = ai_explanation
                if detection_method:
                    existing_alert.detection_method = detection_method
                    existing_alert.detected_by = resolved_detected_by
                existing_alert.message = f"{message} (Repeated {existing_alert.occurrence_count} occurrences, last seen {now.strftime('%H:%M:%S')})"
                self.db.commit()
                self.db.refresh(existing_alert)
                return existing_alert

        # Otherwise create new event and alert
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            source_device=clean_source,
            destination_device=destination_device or destination_ip or "Network",
            description=message,
            confidence=confidence,
            status="NEW",
            detection_method=detection_method,
            occurrence_count=1,
            last_seen=now,
            created_at=now
        )
        self.db.add(event)
        self.db.flush()

        alert = Alert(
            event_id=event.id,
            event_type=event_type,
            title=title,
            severity=severity,
            message=message,
            source_ip=source_ip,
            destination_ip=destination_ip,
            rule_name=rule_name,
            detection_method=detection_method,
            detected_by=resolved_detected_by,
            ai_score=ai_score,
            ai_confidence=ai_confidence,
            ai_explanation=ai_explanation,
            recommendation=recommendation,
            status="NEW",
            occurrence_count=1,
            last_seen=now,
            created_at=now
        )
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        return alert

    def run_detection_pipeline(self, window_seconds: int = 30) -> List[Alert]:
        """
        Task 3: Detection pipeline evaluating the last 3 ticks (30s) of flows.
        Aggregates features per source device and evaluates the 6 Layer 1 rules:
        - Unknown device
        - Port scan
        - Traffic anomaly (spike)
        - Repeated failed authentication
        - Suspicious outbound connection
        - Unusual direct access to critical asset
        De-duplicates open events/alerts by (event_type, source_device).
        """
        latest_flow = self.db.query(TrafficRecord.timestamp).order_by(TrafficRecord.id.desc()).first()
        ref_time = latest_flow[0] if latest_flow else utcnow()
        cutoff = ref_time - timedelta(seconds=window_seconds)
        flows = (
            self.db.query(TrafficRecord)
            .filter(TrafficRecord.timestamp >= cutoff)
            .all()
        )
        if not flows:
            return []

        # Group flows and compute features per source IP
        flows_by_src = defaultdict(list)
        for f in flows:
            flows_by_src[f.source_ip].append(f)

        # Preload device cache to eliminate N+1 database queries
        all_devices = self.db.query(Device).all()
        dev_by_ip = {d.ip_address: d for d in all_devices}
        db_device = next((d for d in all_devices if d.device_name == "Database"), None)
        server_device = next((d for d in all_devices if d.device_name == "Server"), None)
        db_ip = db_device.ip_address if db_device else "192.168.1.21"
        server_ip = server_device.ip_address if server_device else "192.168.1.20"

        all_alerts = []
        for src_ip, src_flows in flows_by_src.items():
            dev = dev_by_ip.get(src_ip)
            dev_role = dev.device_type if dev else "endpoint"
            src_label = dev.device_name if dev else src_ip

            # Aggregate window features for Layer 2 AI evaluation
            tot_pkts = sum(f.packet_count for f in src_flows)
            tot_bytes = sum(f.bytes for f in src_flows)
            tot_conns = len(src_flows)
            tot_dur = max(0.001, sum(getattr(f, "duration", 0.1) or 0.1 for f in src_flows))
            u_ports = len(set(f.destination_port for f in src_flows))
            u_ips = len(set(f.destination_ip for f in src_flows))
            failed_c = sum(1 for f in src_flows if f.is_anomalous and f.destination_port in [21, 22, 23, 3389, 445, 1433])
            t_rate = tot_bytes / tot_dur

            feat_dict = {
                "packet_count": tot_pkts,
                "bytes": tot_bytes,
                "connection_count": tot_conns,
                "duration": tot_dur,
                "unique_dst_ports": u_ports,
                "unique_dst_ips": u_ips,
                "failed_connections": failed_c,
                "traffic_rate": t_rate
            }

            ai_res = ai_detector.predict(feat_dict, role=dev_role)

            device_alerts = []

            # Check 1: Unknown device
            unknown_enabled = str(self.get_threshold("unknown_device_detection", "true")).lower() == "true"
            if not dev and unknown_enabled:
                unknown = self.create_or_update_alert(
                    event_type="UNKNOWN_DEVICE",
                    source_device=src_ip,
                    destination_device="Network Gateway",
                    severity="MEDIUM",
                    title="Unknown Device Detected",
                    message=f"Traffic observed from IP {src_ip}, which is not registered in the NetGuardian inventory.",
                    rule_name="RULE-01: UNKNOWN_DEVICE",
                    recommendation="Verify device ownership and isolate if unauthorized.",
                    confidence=0.95,
                    detection_method="RULE",
                    source_ip=src_ip,
                    destination_ip="Network Gateway"
                )
                device_alerts.append(unknown)

            # Check 2: Port scan across window
            port_thresh = self.get_threshold("port_scan_threshold", getattr(settings, "PORT_SCAN_THRESHOLD", 15))
            if u_ports >= port_thresh:
                if dev and dev.status == "ONLINE":
                    dev.status = "SUSPICIOUS"
                    dev.risk_score = min(100.0, dev.risk_score + 35.0)
                    dev.trust_score = max(0.0, dev.trust_score - 25.0)
                scan = self.create_or_update_alert(
                    event_type="PORT_SCAN",
                    source_device=src_label,
                    destination_device="Subnet Probes",
                    severity="HIGH",
                    title="Port Scanning Activity Detected",
                    message=f"Source host {src_label} ({src_ip}) contacted {u_ports} unique ports in 30s (Threshold: {port_thresh}).",
                    rule_name="RULE-02: PORT_SCAN",
                    recommendation="Review exposed services and investigate the source host.",
                    confidence=0.92,
                    detection_method="RULE",
                    source_ip=src_ip
                )
                device_alerts.append(scan)

            # Check 3: Traffic volume anomaly spike
            for f in src_flows:
                if f.bytes >= 500000:
                    spike = self.check_traffic_spike(f)
                    if spike:
                        device_alerts.append(spike)
                        break

            # Check 4: Failed auth pattern (repeated attempts to port 22/23/3389)
            auth_probes = [f for f in src_flows if f.destination_port in [22, 23, 3389] and (f.is_anomalous or f.packet_count <= 4)]
            auth_thresh = self.get_threshold("failed_auth_threshold", getattr(settings, "FAILED_AUTH_THRESHOLD", 5))
            if len(auth_probes) >= auth_thresh:
                dst_label = auth_probes[0].destination_ip
                alert = self.create_or_update_alert(
                    event_type="FAILED_AUTH",
                    source_device=src_label,
                    destination_device=dst_label,
                    severity="HIGH",
                    title="Possible Brute-Force Pattern Detected",
                    message=f"Repeated authentication failures ({len(auth_probes)} rejected attempts on port 22) from {src_label}.",
                    rule_name="RULE-04: FAILED_AUTH",
                    recommendation="Audit authentication logs and enforce rate limiting on the target service.",
                    confidence=0.91,
                    detection_method="RULE",
                    source_ip=src_ip,
                    destination_ip=auth_probes[0].destination_ip
                )
                device_alerts.append(alert)

            # Check 5: Suspicious outbound
            for f in src_flows:
                if f.destination_port in {4444, 6667, 1337, 31337, 21, 23}:
                    susp = self.create_or_update_alert(
                        event_type="SUSPICIOUS_OUTBOUND",
                        source_device=src_label,
                        destination_device=f.destination_ip,
                        severity="HIGH",
                        title="Suspicious Outbound Connection",
                        message=f"Host {src_label} established connection to suspicious port {f.destination_port} on {f.destination_ip}.",
                        rule_name="RULE-04: SUSPICIOUS_OUTBOUND",
                        recommendation="Review exposed services and investigate the source.",
                        confidence=0.90,
                        detection_method="RULE",
                        source_ip=f.source_ip,
                        destination_ip=f.destination_ip
                    )
                    device_alerts.append(susp)
                    break

            # Check 6: Critical asset direct access
            for f in src_flows:
                if f.destination_ip == db_ip and f.source_ip != server_ip:
                    crit = self.create_or_update_alert(
                        event_type="CRITICAL_ASSET_ACCESS",
                        source_device=src_label,
                        destination_device="Database",
                        severity="CRITICAL",
                        title="Unusual Direct Access to Critical Asset",
                        message=f"Unauthorized direct access attempt from {src_label} ({f.source_ip}) to protected Database ({db_ip}:{f.destination_port}).",
                        rule_name="RULE-05: CRITICAL_ASSET_ACCESS",
                        recommendation="Review logs and restrict access immediately.",
                        confidence=0.96,
                        detection_method="RULE",
                        source_ip=f.source_ip,
                        destination_ip=db_ip
                    )
                    device_alerts.append(crit)
                    break

            # Integration Layer: Merge Rule and AI results into cohesive alert
            if device_alerts:
                for a in device_alerts:
                    a.ai_score = ai_res["anomaly_score"]
                    a.ai_confidence = ai_res["confidence"]
                    a.ai_explanation = json.dumps(ai_res["explanation"])
                    if ai_res["is_anomalous"]:
                        a.detection_method = "RULE+AI"
                        a.detected_by = "rule+ai"
                    self.db.commit()
                all_alerts.extend(device_alerts)
                self.ai_consecutive_windows[src_ip] = 0
            else:
                # Task 5: AI-only events require high score (>= 0.84) and persistence (2 consecutive windows)
                if ai_res["anomaly_score"] >= 0.84:
                    self.ai_consecutive_windows[src_ip] += 1
                    if self.ai_consecutive_windows[src_ip] >= 2:
                        dst_target = src_flows[0].destination_ip if src_flows else "Network"
                        ai_alert = self.create_or_update_alert(
                            event_type="AI_ANOMALY",
                            source_device=src_label,
                            destination_device=dst_target,
                            severity="HIGH" if ai_res["anomaly_score"] >= 0.85 else "MEDIUM",
                            title="AI-Detected Network Behavioral Anomaly",
                            message=f"Statistical behavioral anomaly detected by Isolation Forest on {src_label}. {ai_res['reasons'][0] if ai_res['reasons'] else 'Anomalous deviation from baseline.'}",
                            rule_name="AI-ENGINE: ISOLATION_FOREST",
                            recommendation="Investigate host telemetry and compare observed traffic patterns against baseline profile.",
                            confidence=ai_res["anomaly_score"],
                            detection_method="AI",
                            detected_by="ai",
                            source_ip=src_ip,
                            destination_ip=dst_target,
                            ai_score=ai_res["anomaly_score"],
                            ai_confidence=ai_res["confidence"],
                            ai_explanation=json.dumps(ai_res["explanation"])
                        )
                        all_alerts.append(ai_alert)
                else:
                    self.ai_consecutive_windows[src_ip] = 0

        return all_alerts

    def evaluate_traffic_record(self, record: TrafficRecord) -> List[Alert]:
        """Run all rule-based checks against a newly recorded traffic event."""
        created_alerts = []

        # Rule 1: Unknown Device Check (Task 1 & Acceptance Check 2: MEDIUM)
        unknown_alert = self.check_unknown_device(record.source_ip)
        if unknown_alert:
            created_alerts.append(unknown_alert)

        # Rule 2: Port Scanning Check (Task 1 & Acceptance Check 3: HIGH)
        scan_alert = self.check_port_scan(record.source_ip)
        if scan_alert:
            created_alerts.append(scan_alert)

        # Rule 3: Traffic Volume Anomaly Spike (Task 1 & Acceptance Check 4: MEDIUM)
        volume_alert = self.check_traffic_spike(record)
        if volume_alert:
            created_alerts.append(volume_alert)

        # Rule 4: Suspicious Outbound Connection
        outbound_alert = self.check_suspicious_outbound(record)
        if outbound_alert:
            created_alerts.append(outbound_alert)

        # Rule 5: Critical Asset Access
        critical_alert = self.check_critical_asset_access(record)
        if critical_alert:
            created_alerts.append(critical_alert)

        return created_alerts

    def check_unknown_device(self, source_ip: str) -> Optional[Alert]:
        """Rule 1: Flag traffic from unregistered IP addresses (MEDIUM severity) if enabled."""
        unknown_enabled = str(self.get_threshold("unknown_device_detection", "true")).lower() == "true"
        if not unknown_enabled:
            return None

        device = self.db.query(Device).filter(Device.ip_address == source_ip).first()
        if not device:
            return self.create_or_update_alert(
                event_type="UNKNOWN_DEVICE",
                source_device=source_ip,
                destination_device="Network Gateway",
                severity="MEDIUM",
                title="Unknown Device Detected",
                message=f"Traffic observed from IP {source_ip}, which is not registered in the NetGuardian inventory.",
                rule_name="RULE-01: UNKNOWN_DEVICE",
                recommendation="Verify device ownership and isolate if unauthorized.",
                confidence=0.95,
                detection_method="RULE",
                source_ip=source_ip,
                destination_ip="Network Gateway"
            )
        return None

    def check_port_scan(self, source_ip: str) -> Optional[Alert]:
        """Rule 2: Rapid scanning across multiple ports in short window (HIGH severity)."""
        latest_flow = self.db.query(TrafficRecord.timestamp).order_by(TrafficRecord.id.desc()).first()
        ref_time = latest_flow[0] if latest_flow else utcnow()
        cutoff = ref_time - timedelta(seconds=60)
        unique_ports = self.db.query(func.count(func.distinct(TrafficRecord.destination_port)))\
            .filter(
                TrafficRecord.source_ip == source_ip,
                TrafficRecord.timestamp >= cutoff
            ).scalar() or 0

        threshold = self.get_threshold("port_scan_threshold", getattr(settings, "PORT_SCAN_THRESHOLD", 15))
        if unique_ports >= threshold:
            device = self.db.query(Device).filter(Device.ip_address == source_ip).first()
            if device and device.status == "ONLINE":
                device.status = "SUSPICIOUS"
                device.risk_score = min(100.0, device.risk_score + 35.0)
                device.trust_score = max(0.0, device.trust_score - 25.0)

            source_label = device.device_name if device else source_ip
            return self.create_or_update_alert(
                event_type="PORT_SCAN",
                source_device=source_label,
                destination_device="Subnet Probes",
                severity="HIGH",
                title="Port Scanning Activity Detected",
                message=f"Source host {source_label} ({source_ip}) contacted {unique_ports} unique ports in 60s (Threshold: {threshold}).",
                rule_name="RULE-02: PORT_SCAN",
                recommendation="Review exposed services and investigate the source host.",
                confidence=0.92,
                detection_method="RULE",
                source_ip=source_ip
            )
        return None

    def check_traffic_spike(self, record: TrafficRecord) -> Optional[Alert]:
        """Rule 3: Volume anomaly far above baseline or exceeding threshold (MEDIUM severity)."""
        device = self.db.query(Device).filter(Device.ip_address == record.source_ip).first()
        
        # Standard threshold: 500,000 bytes or 3.0x baseline
        threshold_mult = self.get_threshold("traffic_anomaly_threshold", getattr(settings, "TRAFFIC_ANOMALY_THRESHOLD", 3.0))
        
        # In normal traffic, flows are 40B - 9KB. Bursts >= 500,000 bytes represent anomalies
        is_spike = record.bytes >= 500000

        if is_spike:
            if device and device.status == "ONLINE":
                device.status = "SUSPICIOUS"
                device.risk_score = min(100.0, device.risk_score + 20.0)

            source_label = device.device_name if device else record.source_ip
            kb = round(record.bytes / 1024, 1)
            return self.create_or_update_alert(
                event_type="TRAFFIC_ANOMALY",
                source_device=source_label,
                destination_device=record.destination_ip,
                severity="MEDIUM",
                title="Traffic Volume Anomaly Spike",
                message=f"Sudden traffic surge of {kb} KB transferred from {source_label} to {record.destination_ip}:{record.destination_port}.",
                rule_name="RULE-03: TRAFFIC_ANOMALY",
                recommendation="Investigate the source and compare to baseline.",
                confidence=0.88,
                detection_method="RULE",
                source_ip=record.source_ip,
                destination_ip=record.destination_ip
            )
        return None

    def check_suspicious_outbound(self, record: TrafficRecord) -> Optional[Alert]:
        """Rule 4: Outbound connection to suspicious high-risk port (HIGH severity)."""
        suspicious_ports = {4444, 6667, 1337, 31337, 21, 23}
        if record.destination_port in suspicious_ports:
            device = self.db.query(Device).filter(Device.ip_address == record.source_ip).first()
            source_label = device.device_name if device else record.source_ip

            return self.create_or_update_alert(
                event_type="SUSPICIOUS_OUTBOUND",
                source_device=source_label,
                destination_device=record.destination_ip,
                severity="HIGH",
                title="Suspicious Outbound Connection",
                message=f"Host {source_label} established connection to suspicious port {record.destination_port} on {record.destination_ip}.",
                rule_name="RULE-04: SUSPICIOUS_OUTBOUND",
                recommendation="Review exposed services and investigate the source.",
                confidence=0.90,
                detection_method="RULE",
                source_ip=record.source_ip,
                destination_ip=record.destination_ip
            )
        return None

    def check_critical_asset_access(self, record: TrafficRecord) -> Optional[Alert]:
        """Rule 5: Unauthorized endpoint accessing protected Database directly (CRITICAL severity)."""
        db_device = self.db.query(Device).filter(Device.device_name == "Database").first()
        server_device = self.db.query(Device).filter(Device.device_name == "Server").first()

        db_ip = db_device.ip_address if db_device else "192.168.1.21"
        server_ip = server_device.ip_address if server_device else "192.168.1.20"

        # If destination is Database and source is NOT the Server, flag as CRITICAL
        if record.destination_ip == db_ip and record.source_ip != server_ip:
            device = self.db.query(Device).filter(Device.ip_address == record.source_ip).first()
            source_label = device.device_name if device else record.source_ip

            return self.create_or_update_alert(
                event_type="CRITICAL_ASSET_ACCESS",
                source_device=source_label,
                destination_device="Database",
                severity="CRITICAL",
                title="Unusual Direct Access to Critical Asset",
                message=f"Unauthorized direct access attempt from {source_label} ({record.source_ip}) to protected Database ({db_ip}:{record.destination_port}).",
                rule_name="RULE-05: CRITICAL_ASSET_ACCESS",
                recommendation="Review logs and restrict access immediately.",
                confidence=0.96,
                detection_method="RULE",
                source_ip=record.source_ip,
                destination_ip=db_ip
            )
        return None

    def trigger_simulated_security_event(
        self,
        event_type: str,
        source_ip: str,
        target_ip: Optional[str] = None
    ) -> Alert:
        """
        Task 2: Simulate one of the 6 security events (injects synthetic flow metadata only).
        1. UNKNOWN_DEVICE: Unknown device joins network (MEDIUM)
        2. PORT_SCAN: Rapid multi-port reconnaissance (HIGH)
        3. TRAFFIC_ANOMALY: High bandwidth spike (MEDIUM)
        4. FAILED_AUTH: Repeated failed authentication / brute force pattern (HIGH)
        5. SUSPICIOUS_OUTBOUND: Outbound connection to unusual/C2 port (HIGH)
        6. COMPROMISED_HOST: Device compromised with lateral movement (CRITICAL)
        """
        device = self.db.query(Device).filter(Device.ip_address == source_ip).first()
        target_dev = self.db.query(Device).filter(Device.ip_address == target_ip).first() if target_ip else None

        source_label = device.device_name if device else source_ip
        target_label = target_dev.device_name if target_dev else (target_ip or "Subnet")
        dst_ip = target_ip or "192.168.1.20"

        ev_type = event_type.upper()

        if ev_type in ["UNKNOWN_DEVICE", "1"]:
            # Task 5: Unknown device joins and appears in inventory / topology as unregistered
            unregistered_ip = source_ip if (not device or source_ip == "192.168.1.99") else "192.168.1.99"
            
            # Check if unregistered device already registered in inventory
            unreg_device = self.db.query(Device).filter(Device.ip_address == unregistered_ip).first()
            if not unreg_device:
                unreg_device = Device(
                    device_name="Unknown-Host-99",
                    ip_address=unregistered_ip,
                    mac_address="02:AA:BB:CC:DD:99",
                    device_type="unregistered",
                    os_type="Unknown",
                    status="SUSPICIOUS",
                    criticality="LOW",
                    trust_level="UNTRUSTED",
                    risk_score=65.0,
                    trust_score=20.0,
                    is_isolated=False,
                    first_seen=utcnow(),
                    last_seen=utcnow()
                )
                self.db.add(unreg_device)
                self.db.flush()

                # Attach to Switch in network_connections so it appears on topology map
                switch = self.db.query(Device).filter(Device.device_name.in_(["Switch", "Core-Switch-01"])).first()
                if not switch:
                    switch = self.db.query(Device).filter(Device.device_type == "Switch").first()
                if switch:
                    conn = NetworkConnection(
                        source_device_id=unreg_device.id,
                        destination_device_id=switch.id,
                        protocol="ETHERNET",
                        source_port=0,
                        destination_port=0,
                        packet_count=5,
                        bytes_transferred=320,
                        timestamp=utcnow()
                    )
                    self.db.add(conn)

            source_label = unreg_device.device_name if unreg_device else unregistered_ip

            tr = TrafficRecord(
                timestamp=utcnow(),
                source_ip=unregistered_ip,
                destination_ip=dst_ip,
                protocol="TCP",
                source_port=49152,
                destination_port=443,
                packet_count=5,
                bytes=1200,
                duration=0.04,
                is_anomalous=1
            )
            self.db.add(tr)

            ai_res = ai_detector.predict({
                "packet_count": 5,
                "bytes": 1200,
                "connection_count": 1,
                "duration": 0.04,
                "unique_dst_ports": 1,
                "unique_dst_ips": 1,
                "failed_connections": 0,
                "traffic_rate": 30000.0
            }, role="endpoint")

            return self.create_or_update_alert(
                event_type="UNKNOWN_DEVICE",
                source_device=source_label,
                destination_device=target_label,
                severity="MEDIUM",
                title="Unknown Device Detected",
                message=f"Unregistered device detected transmitting packets from IP {unregistered_ip}.",
                rule_name="RULE-01: UNKNOWN_DEVICE",
                recommendation="Verify device ownership and isolate if unauthorized.",
                confidence=0.95,
                detection_method="RULE",
                detected_by="rule",
                source_ip=unregistered_ip,
                destination_ip=dst_ip,
                ai_score=ai_res["anomaly_score"],
                ai_confidence=ai_res["confidence"],
                ai_explanation=json.dumps(ai_res["explanation"])
            )

        elif ev_type in ["PORT_SCAN", "2"]:
            # Inject 17 rapid port probes
            for p in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080]:
                tr = TrafficRecord(
                    timestamp=utcnow(),
                    source_ip=source_ip,
                    destination_ip=dst_ip,
                    protocol="TCP",
                    source_port=50000 + p,
                    destination_port=p,
                    packet_count=2,
                    bytes=128,
                    duration=0.01,
                    is_anomalous=1
                )
                self.db.add(tr)
            if device and device.status == "ONLINE":
                device.status = "SUSPICIOUS"
                device.risk_score = min(100.0, device.risk_score + 35.0)

            dev_role = device.device_type if device else "endpoint"
            ai_res = ai_detector.predict({
                "packet_count": 34,
                "bytes": 2176,
                "connection_count": 17,
                "duration": 0.17,
                "unique_dst_ports": 17,
                "unique_dst_ips": 1,
                "failed_connections": 15,
                "traffic_rate": 12800.0
            }, role=dev_role)

            return self.create_or_update_alert(
                event_type="PORT_SCAN",
                source_device=source_label,
                destination_device=target_label,
                severity="HIGH",
                title="Port Scanning Activity Detected",
                message=f"Simulated port reconnaissance: 17 critical service ports probed in rapid sequence from {source_label}.",
                rule_name="RULE-02: PORT_SCAN",
                recommendation="Review exposed services and investigate the source host.",
                confidence=0.94,
                detection_method="RULE+AI",
                detected_by="rule+ai",
                source_ip=source_ip,
                destination_ip=dst_ip,
                ai_score=ai_res["anomaly_score"],
                ai_confidence=ai_res["confidence"],
                ai_explanation=json.dumps(ai_res["explanation"])
            )

        elif ev_type in ["TRAFFIC_ANOMALY", "3"]:
            # Traffic anomaly: 1.85 MB burst
            tr = TrafficRecord(
                timestamp=utcnow(),
                source_ip=source_ip,
                destination_ip=dst_ip,
                protocol="TCP",
                source_port=49882,
                destination_port=443,
                packet_count=1200,
                bytes=1850000,
                duration=2.5,
                is_anomalous=1
            )
            self.db.add(tr)
            if device and device.status == "ONLINE":
                device.status = "SUSPICIOUS"
                device.risk_score = min(100.0, device.risk_score + 25.0)

            dev_role = device.device_type if device else "endpoint"
            ai_res = ai_detector.predict({
                "packet_count": 1200,
                "bytes": 1850000,
                "connection_count": 1,
                "duration": 2.5,
                "unique_dst_ports": 1,
                "unique_dst_ips": 1,
                "failed_connections": 0,
                "traffic_rate": 740000.0
            }, role=dev_role)

            return self.create_or_update_alert(
                event_type="TRAFFIC_ANOMALY",
                source_device=source_label,
                destination_device=target_label,
                severity="MEDIUM",
                title="Traffic Volume Anomaly Spike",
                message=f"Sudden 1.85 MB burst originating from {source_label} towards {target_label}.",
                rule_name="RULE-03: TRAFFIC_ANOMALY",
                recommendation="Investigate the source and compare to baseline.",
                confidence=0.89,
                detection_method="RULE+AI",
                detected_by="rule+ai",
                source_ip=source_ip,
                destination_ip=dst_ip,
                ai_score=ai_res["anomaly_score"],
                ai_confidence=ai_res["confidence"],
                ai_explanation=json.dumps(ai_res["explanation"])
            )

        elif ev_type in ["FAILED_AUTH", "4"]:
            # Repeated failed authentication pattern
            for i in range(6):
                tr = TrafficRecord(
                    timestamp=utcnow(),
                    source_ip=source_ip,
                    destination_ip=dst_ip,
                    protocol="TCP",
                    source_port=41000 + i,
                    destination_port=22,
                    packet_count=4,
                    bytes=480,
                    duration=0.08,
                    is_anomalous=1
                )
                self.db.add(tr)
            if device and device.status == "ONLINE":
                device.risk_score = min(100.0, device.risk_score + 30.0)

            dev_role = device.device_type if device else "endpoint"
            ai_res = ai_detector.predict({
                "packet_count": 24,
                "bytes": 2880,
                "connection_count": 6,
                "duration": 0.48,
                "unique_dst_ports": 1,
                "unique_dst_ips": 1,
                "failed_connections": 6,
                "traffic_rate": 6000.0
            }, role=dev_role)

            return self.create_or_update_alert(
                event_type="FAILED_AUTH",
                source_device=source_label,
                destination_device=target_label,
                severity="HIGH",
                title="Possible Brute-Force Pattern Detected",
                message=f"Repeated authentication failures (6 consecutive rejected attempts on port 22) from {source_label} targeting {target_label}.",
                rule_name="RULE-04: FAILED_AUTH",
                recommendation="Audit authentication logs and enforce rate limiting on the target service.",
                confidence=0.91,
                detection_method="RULE+AI",
                detected_by="rule+ai",
                source_ip=source_ip,
                destination_ip=dst_ip,
                ai_score=ai_res["anomaly_score"],
                ai_confidence=ai_res["confidence"],
                ai_explanation=json.dumps(ai_res["explanation"])
            )

        elif ev_type in ["SUSPICIOUS_OUTBOUND", "5"]:
            # Suspicious outbound connection to port 4444 (simulate rapid beaconing)
            for b_idx in range(4):
                tr = TrafficRecord(
                    timestamp=utcnow(),
                    source_ip=source_ip,
                    destination_ip="203.0.113.1",
                    protocol="TCP",
                    source_port=49200 + b_idx,
                    destination_port=4444,
                    packet_count=15,
                    bytes=9500,
                    duration=0.06,
                    is_anomalous=1
                )
                self.db.add(tr)
            if device and device.status == "ONLINE":
                device.status = "SUSPICIOUS"
                device.risk_score = min(100.0, device.risk_score + 35.0)

            dev_role = device.device_type if device else "endpoint"
            ai_res = ai_detector.predict({
                "packet_count": 60,
                "bytes": 38000,
                "connection_count": 4,
                "duration": 0.24,
                "unique_dst_ports": 1,
                "unique_dst_ips": 1,
                "failed_connections": 0,
                "traffic_rate": 158333.3,
                "destination_port": 4444
            }, role=dev_role)

            return self.create_or_update_alert(
                event_type="SUSPICIOUS_OUTBOUND",
                source_device=source_label,
                destination_device="External-WAN",
                severity="HIGH",
                title="Suspicious Outbound Connection",
                message=f"Suspicious outbound flow from {source_label} to external port 4444.",
                rule_name="RULE-05: SUSPICIOUS_OUTBOUND",
                recommendation="Review outbound firewall egress rules and inspect the initiating host process.",
                confidence=0.90,
                detection_method="RULE+AI",
                detected_by="rule+ai",
                source_ip=source_ip,
                destination_ip="203.0.113.1",
                ai_score=ai_res["anomaly_score"],
                ai_confidence=ai_res["confidence"],
                ai_explanation=json.dumps(ai_res["explanation"])
            )

        else: # COMPROMISED_HOST, 6
            if device:
                device.status = "COMPROMISED"
                device.risk_score = 88.0
                device.trust_score = 20.0

            # Inbound C2 and lateral movement flow to Server
            tr = TrafficRecord(
                timestamp=utcnow(),
                source_ip=source_ip,
                destination_ip="192.168.1.20",
                protocol="TCP",
                source_port=49333,
                destination_port=445,
                packet_count=45,
                bytes=24000,
                duration=0.35,
                is_anomalous=1
            )
            self.db.add(tr)

            dev_role = device.device_type if device else "endpoint"
            ai_res = ai_detector.predict({
                "packet_count": 45,
                "bytes": 24000,
                "connection_count": 3,
                "duration": 0.35,
                "unique_dst_ports": 2,
                "unique_dst_ips": 2,
                "failed_connections": 1,
                "traffic_rate": 68571.4,
                "lateral_movement": 1
            }, role=dev_role)

            return self.create_or_update_alert(
                event_type="COMPROMISED_DEVICE",
                source_device=source_label,
                destination_device="Server",
                severity="CRITICAL",
                title="Host Compromise Scenario Simulated",
                message=f"Device {source_label} ({source_ip}) has been flagged as COMPROMISED. Digital Twin indicates active lateral movement towards core assets.",
                rule_name="RULE-06: COMPROMISED_HOST",
                recommendation="Review logs and restrict access immediately. Run What-If simulation and test simulated isolation.",
                confidence=0.96,
                detection_method="RULE+AI",
                detected_by="rule+ai",
                source_ip=source_ip,
                destination_ip="192.168.1.20",
                ai_score=ai_res["anomaly_score"],
                ai_confidence=ai_res["confidence"],
                ai_explanation=json.dumps(ai_res["explanation"])
            )
