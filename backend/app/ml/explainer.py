from typing import Dict, List, Any

# Role-specific baseline averages derived from normal traffic distributions
ROLE_BASELINES: Dict[str, Dict[str, float]] = {
    "endpoint": {
        "packet_count": 22.0,
        "bytes": 14000.0,
        "connection_count": 4.0,
        "connection_duration": 1.0,
        "unique_destination_ports": 2.0,
        "unique_destination_ips": 1.5,
        "failed_connections": 0.05,
        "traffic_rate": 20000.0
    },
    "server": {
        "packet_count": 45.0,
        "bytes": 35000.0,
        "connection_count": 6.0,
        "connection_duration": 1.5,
        "unique_destination_ports": 1.2,
        "unique_destination_ips": 2.0,
        "failed_connections": 0.05,
        "traffic_rate": 25000.0
    },
    "iot": {
        "packet_count": 65.0,
        "bytes": 45000.0,
        "connection_count": 2.0,
        "connection_duration": 0.6,
        "unique_destination_ports": 1.0,
        "unique_destination_ips": 1.0,
        "failed_connections": 0.0,
        "traffic_rate": 35000.0
    },
    "network": {
        "packet_count": 40.0,
        "bytes": 30000.0,
        "connection_count": 8.0,
        "connection_duration": 0.5,
        "unique_destination_ports": 2.0,
        "unique_destination_ips": 2.8,
        "failed_connections": 0.05,
        "traffic_rate": 25000.0
    },
    "default": {
        "packet_count": 25.0,
        "bytes": 15000.0,
        "connection_count": 3.0,
        "connection_duration": 0.8,
        "unique_destination_ports": 1.5,
        "unique_destination_ips": 1.5,
        "failed_connections": 0.05,
        "traffic_rate": 15000.0
    }
}

def explain_anomaly(
    features: Dict[str, float],
    anomaly_score: float,
    role: str = "endpoint"
) -> Dict[str, Any]:
    """
    Phase 4 Task 4 Explainability ("Why was this flagged?"):
    Dynamically derives plain-language, mathematically grounded reasons from real feature numbers.
    Never returns static text — all multiples, port counts, and deviations are calculated live.
    Never states 'definitely an attack'; explicitly notes that an anomaly is not proof of malice.
    """
    clean_role = (role or "endpoint").lower()
    if clean_role not in ROLE_BASELINES:
        if clean_role in ["workstation", "laptop", "pc", "unregistered"]:
            clean_role = "endpoint"
        elif clean_role in ["database", "server", "app-server"]:
            clean_role = "server"
        elif clean_role in ["camera", "printer", "sensor", "iot"]:
            clean_role = "iot"
        elif clean_role in ["router", "switch", "gateway", "firewall", "internet"]:
            clean_role = "network"
        else:
            clean_role = "default"

    baseline = ROLE_BASELINES.get(clean_role, ROLE_BASELINES["default"])
    reasons: List[str] = []
    deviations: Dict[str, Any] = {}

    # 1. Volumetric Traffic Deviation (bytes)
    bytes_val = float(features.get("bytes", 0.0))
    base_bytes = baseline["bytes"]
    if bytes_val >= base_bytes * 2.0:
        ratio = round(bytes_val / max(1.0, base_bytes), 1)
        reasons.append(f"Traffic is {ratio}× above baseline ({int(bytes_val):,} bytes vs {int(base_bytes):,} bytes normal average)")
        deviations["bytes_multiplier"] = ratio

    # 2. Port Reconnaissance / Scanning (unique_destination_ports)
    ports_val = float(features.get("unique_destination_ports", features.get("unique_dst_ports", 1.0)))
    if ports_val >= 4.0:
        reasons.append(f"Contacted {int(ports_val)} unique ports in short window (normal baseline: 1-2 ports)")
        deviations["unique_ports"] = int(ports_val)

    # 3. Throughput Velocity Surge (traffic_rate)
    rate_val = float(features.get("traffic_rate", 0.0))
    base_rate = baseline["traffic_rate"]
    if rate_val >= base_rate * 2.5:
        rate_ratio = round(rate_val / max(1.0, base_rate), 1)
        reasons.append(f"Throughput velocity ({int(rate_val):,} B/s) is {rate_ratio}× above baseline rate")
        deviations["traffic_rate_multiplier"] = rate_ratio

    # 4. Connection Frequency / Concurrency Burst (connection_count)
    conns_val = float(features.get("connection_count", 1.0))
    base_conns = baseline["connection_count"]
    if conns_val >= max(8.0, base_conns * 2.5):
        reasons.append(f"Connection frequency increased sharply ({int(conns_val)} concurrent sessions in window)")
        deviations["connection_count"] = int(conns_val)
    elif conns_val >= 4.0 and float(features.get("failed_connections", 0.0)) >= 2.0:
        reasons.append(f"Rapid connection burst during authentication attempts: {int(conns_val)} sessions in window")
        deviations["connection_count"] = int(conns_val)

    # 5. Failed / Rejected Connection Storm (failed_connections)
    failed_val = float(features.get("failed_connections", 0.0))
    if failed_val >= 2.0:
        reasons.append(f"High connection rejection rate: observed {int(failed_val)} failed handshakes / RST responses")
        deviations["failed_connections"] = int(failed_val)

    # 6. Horizontal Host Sweep & Lateral Movement (unique_destination_ips)
    ips_val = float(features.get("unique_destination_ips", features.get("unique_dst_ips", 1.0)))
    if ips_val >= 4.0:
        reasons.append(f"Horizontal sweep: contacted {int(ips_val)} distinct destination IPs in window")
        deviations["unique_ips"] = int(ips_val)
    elif ips_val >= 2.0 and (features.get("lateral_movement") or float(features.get("packet_count", 0.0)) >= 30.0):
        reasons.append(f"Multi-host lateral movement: contacted {int(ips_val)} distinct internal IP targets in window")
        deviations["unique_ips"] = int(ips_val)

    # 7. Suspicious Non-Standard Egress Port
    dest_port = features.get("destination_port") or features.get("unusual_port")
    if dest_port and int(dest_port) in [4444, 6667, 1337, 31337, 21, 23]:
        reasons.append(f"Outbound egress to high-risk non-standard service port {int(dest_port)}")
        deviations["destination_port"] = int(dest_port)

    # 8. Dynamic multivariate fallback (never fixed text)
    if not reasons:
        ratios = {
            "bytes": bytes_val / max(1.0, baseline["bytes"]),
            "traffic_rate": rate_val / max(1.0, baseline["traffic_rate"]),
            "packet_count": float(features.get("packet_count", 0.0)) / max(1.0, baseline["packet_count"]),
            "connection_count": conns_val / max(1.0, baseline["connection_count"]),
        }
        max_feat, max_val = max(ratios.items(), key=lambda x: x[1])
        reasons.append(f"Multivariate flow divergence: {max_feat} elevated at {max_val:.1f}× baseline distribution")

    # Assessment & Confidence mapping
    is_anomalous = bool(anomaly_score >= 0.58)
    if anomaly_score >= 0.75:
        confidence = "High"
    elif anomaly_score >= 0.55:
        confidence = "Medium"
    else:
        confidence = "Low"

    assessment_label = "ANOMALOUS" if is_anomalous else "NORMAL"
    assessment_banner = f"AI Assessment: {assessment_label} · Anomaly Score {anomaly_score:.2f} · Confidence {confidence}"

    return {
        "assessment": assessment_label,
        "is_anomalous": is_anomalous,
        "anomaly_score": round(anomaly_score, 2),
        "confidence": confidence,
        "assessment_banner": assessment_banner,
        "reasons": reasons,
        "deviations": deviations,
        "disclaimer": "An anomaly represents an unexpected deviation from the learned behavioral baseline and is not proof of malicious activity or an attack.",
        "role_evaluated": clean_role
    }
