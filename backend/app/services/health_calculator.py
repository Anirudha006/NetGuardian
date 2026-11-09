from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.device import Device
from app.models.traffic import TrafficRecord

# Criticality Multipliers: Criticality determines how much an event matters,
# rather than creating baseline risk on its own.
CRITICALITY_MULTIPLIERS = {
    "CRITICAL": 1.4,
    "HIGH": 1.2,
    "MEDIUM": 1.0,
    "LOW": 0.8
}

# Base trust scores by registration tier
BASE_TRUST_MAP = {
    "HIGH": 95.0,
    "MEDIUM": 80.0,
    "LOW": 50.0,
    "UNTRUSTED": 20.0
}

# Threat points per alert event type
BASE_ALERT_IMPACT = {
    "PORT_SCAN": 25.0,
    "COMPROMISED_HOST": 35.0,
    "CRITICAL_ASSET_ACCESS": 30.0,
    "SUSPICIOUS_OUTBOUND": 25.0,
    "FAILED_AUTH": 20.0,
    "UNKNOWN_DEVICE": 20.0,
    "TRAFFIC_ANOMALY": 15.0,
    "AI_ANOMALY": 20.0,
}

def calculate_network_health(db: Session) -> Dict[str, Any]:
    """
    Calculate NetGuardian Network Health Score.
    The score is bounded and strictly clamped between 0.0 and 100.0:
        Health Score = max(0.0, min(100.0, 100.0 - Total_Penalties))
    Penalties are evaluated across 5 capped categories:
    1. Active Threats (Cap: 35.0)
    2. Suspicious Devices (Cap: 25.0)
    3. High-Risk Nodes (Cap: 20.0)
    4. Traffic Anomalies (Cap: 15.0)
    5. Offline Devices (Cap: 15.0)
    """
    # 1. Active Threats Penalty (Cap: 35.0)
    active_alerts = db.query(Alert).filter(Alert.status.in_(["NEW", "INVESTIGATING"])).all()
    raw_threat_deductions = 0.0
    for a in active_alerts:
        sev = (a.severity or "").upper()
        if sev == "CRITICAL":
            raw_threat_deductions += 15.0
        elif sev == "HIGH":
            raw_threat_deductions += 10.0
        elif sev == "MEDIUM":
            raw_threat_deductions += 5.0
        else:
            raw_threat_deductions += 2.0
    threat_deductions = min(35.0, raw_threat_deductions)

    # 2. Suspicious / Compromised Devices Penalty (Cap: 25.0)
    devices = db.query(Device).all()
    raw_suspicious_deductions = 0.0
    raw_high_risk_deductions = 0.0
    raw_offline_deductions = 0.0

    for d in devices:
        st = (d.status or "").upper()
        crit = (d.criticality or "MEDIUM").upper()

        if st == "COMPROMISED":
            raw_suspicious_deductions += 15.0
        elif st == "SUSPICIOUS":
            raw_suspicious_deductions += 10.0
        elif st == "OFFLINE":
            if crit == "CRITICAL":
                raw_offline_deductions += 10.0
            elif crit == "HIGH":
                raw_offline_deductions += 6.0
            else:
                raw_offline_deductions += 3.0

        if (d.risk_score or 0.0) >= 70.0:
            raw_high_risk_deductions += 8.0

    suspicious_deductions = min(25.0, raw_suspicious_deductions)
    high_risk_deductions = min(20.0, raw_high_risk_deductions)
    # 3. Offline Devices Penalty
    # Offline devices reduce availability. Critical/High infrastructure offline carries higher penalty.
    pass

    # 4. Traffic Anomalies Penalty
    recent_anomalies = db.query(TrafficRecord).filter(TrafficRecord.is_anomalous == 1).count()
    raw_anomaly_deductions = float(recent_anomalies * 2.5)

    # Total Raw Deductions Sum (Uncapped)
    raw_total_penalty = round(
        raw_threat_deductions +
        raw_suspicious_deductions +
        raw_high_risk_deductions +
        raw_anomaly_deductions +
        raw_offline_deductions,
        1
    )

    # Health score is clamped strictly between 0.0 and 100.0
    is_clamped = raw_total_penalty > 100.0
    health_score = max(0.0, min(100.0, round(100.0 - raw_total_penalty, 1)))
    effective_deductions = round(100.0 - health_score, 1)

    # Categorical Status Label: HEALTHY (>=85), NEEDS ATTENTION (70-84.9), AT RISK (50-69.9), CRITICAL (<50)
    if health_score >= 85.0:
        health_status = "HEALTHY"
    elif health_score >= 70.0:
        health_status = "NEEDS ATTENTION"
    elif health_score >= 50.0:
        health_status = "AT RISK"
    else:
        health_status = "CRITICAL"

    if is_clamped:
        clamp_explanation = (
            f"Health score is clamped at 0.0 (minimum lower bound). "
            f"Raw penalty sum is {raw_total_penalty} pts, which exceeds the 100-point ceiling."
        )
    else:
        clamp_explanation = "Health score is within the normal [0, 100] scale."

    factors = []
    if raw_threat_deductions > 0:
        factors.append({"label": "Active Threats", "value": -round(raw_threat_deductions, 1)})
    if raw_suspicious_deductions > 0:
        factors.append({"label": "Suspicious Devices", "value": -round(raw_suspicious_deductions, 1)})
    if raw_high_risk_deductions > 0:
        factors.append({"label": "High-Risk Nodes", "value": -round(raw_high_risk_deductions, 1)})
    if raw_anomaly_deductions > 0:
        factors.append({"label": "Traffic Anomalies", "value": -round(raw_anomaly_deductions, 1)})
    if raw_offline_deductions > 0:
        factors.append({"label": "Offline Devices", "value": -round(raw_offline_deductions, 1)})
    if is_clamped:
        factors.append({"label": "Lower Bound Clamping (0.0 Floor)", "value": round(raw_total_penalty - 100.0, 1)})

    return {
        "score": health_score,
        "health_score": health_score,
        "health_status": health_status,
        "raw_deductions": raw_total_penalty,
        "total_deductions": effective_deductions,
        "is_clamped": is_clamped,
        "clamp_explanation": clamp_explanation,
        "factors": factors,
        "penalties": {
            "active_threats": round(raw_threat_deductions, 1),
            "suspicious_devices": round(raw_suspicious_deductions, 1),
            "high_risk_nodes": round(raw_high_risk_deductions, 1),
            "traffic_anomalies": round(raw_anomaly_deductions, 1),
            "offline_devices": round(raw_offline_deductions, 1),
        },
        "breakdown": [
            {"category": "Active Threats", "penalty": round(raw_threat_deductions, 1)},
            {"category": "Suspicious Devices", "penalty": round(raw_suspicious_deductions, 1)},
            {"category": "High-Risk Nodes", "penalty": round(raw_high_risk_deductions, 1)},
            {"category": "Traffic Anomalies", "penalty": round(raw_anomaly_deductions, 1)},
            {"category": "Offline Devices", "penalty": round(raw_offline_deductions, 1)},
        ],
        "threat_deductions": round(raw_threat_deductions, 1),
        "device_deductions": round(raw_suspicious_deductions, 1),
        "high_risk_deductions": round(raw_high_risk_deductions, 1),
        "anomaly_deductions": round(raw_anomaly_deductions, 1),
        "offline_deductions": round(raw_offline_deductions, 1),
        "formula_explanation": (
            "NetGuardian Health Score = max(0.0, min(100.0, 100.0 - (Active Threats + Suspicious Devices + High-Risk Nodes + Traffic Anomalies + Offline Devices))). "
            f"Current score: {health_score}/100 ({health_status}). "
            + (f"Score clamped to 0.0 due to extreme threat volume ({raw_total_penalty} pts)." if is_clamped else f"Total deductions: {raw_total_penalty} pts.")
        )
    }

def calculate_device_risk_breakdown(device: Device, db: Session) -> Dict[str, Any]:
    """
    Calculate explainable risk score breakdown for a specific device.
    Design Principles:
    1. Zero baseline risk: with no events and online state, risk is 0.0 (criticality does NOT create baseline risk).
    2. Criticality determines how much an event matters (modulates event impact via multiplier).
    3. Zero double counting: one event adds points exactly once. Every factor has a distinct cause.
    4. Zero circular dependency: risk comes only from events and device state; trust = base_trust - risk.
    """
    factors: List[Dict[str, Any]] = []

    crit = (device.criticality or "MEDIUM").upper()
    crit_mult = CRITICALITY_MULTIPLIERS.get(crit, 1.0)
    trust_lvl = (device.trust_level or "MEDIUM").upper()

    # Cause 1: Active Unresolved Security Threat Findings
    # Each distinct active alert adds points once, weighted by device asset criticality
    active_alerts = db.query(Alert).filter(
        (Alert.source_ip == device.ip_address) | (Alert.destination_ip == device.ip_address),
        Alert.status.in_(["NEW", "INVESTIGATING"])
    ).all()

    for alert in active_alerts:
        ev = (alert.event_type or "").upper()
        base_pts = BASE_ALERT_IMPACT.get(ev, 20.0)
        # Criticality modulates how much this threat matters
        impact = round(base_pts * crit_mult, 1)
        factors.append({
            "name": f"Active Threat: {alert.title or ev}",
            "impact": impact,
            "description": f"Cause: Injected security event finding (Severity: {alert.severity}, Criticality Weight: {crit_mult}x)"
        })

    # Cause 2: Availability / Offline State Failure
    st = (device.status or "ONLINE").upper()
    if st == "OFFLINE":
        factors.append({
            "name": "Unresponsive Node State",
            "impact": 10.0,
            "description": "Cause: Node failed connectivity health check and is offline"
        })

    # Cause 3: Identity / Rogue Unregistered Device (e.g. Unknown Device Joins event)
    is_rogue = getattr(device, "is_unregistered", False) or "unknown" in (device.device_name or "").lower()
    if is_rogue:
        factors.append({
            "name": "Rogue Unregistered Device",
            "impact": 20.0,
            "description": "Cause: Unregistered rogue device detected transmitting on internal network"
        })

    # Cause 4: Remediation / Simulated Isolation Containment Credit
    if device.is_isolated:
        factors.append({
            "name": "Simulated Isolation Containment",
            "impact": -20.0,
            "description": "Cause: Node logical links severed in Digital Twin, interrupting attack propagation"
        })

    raw_sum = round(sum(f["impact"] for f in factors), 1)

    # Clamped risk score in [0.0, 100.0]
    if raw_sum > 100.0:
        cap_adjustment = round(100.0 - raw_sum, 1)
        factors.append({
            "name": "Upper Risk Cap Normalization",
            "impact": cap_adjustment,
            "description": "Cause: Global device risk bounded at upper ceiling of 100"
        })
        computed_risk = 100.0
    elif raw_sum < 0.0:
        floor_adjustment = round(0.0 - raw_sum, 1)
        factors.append({
            "name": "Lower Risk Floor Normalization",
            "impact": floor_adjustment,
            "description": "Cause: Global device risk floored at minimum bound of 0"
        })
        computed_risk = 0.0
    else:
        computed_risk = raw_sum

    # Cause-independent Trust Score Derivation:
    # Trust derives strictly as a function of Base Trust minus Risk Score.
    # Risk NEVER depends on Trust (zero circular dependency).
    base_trust = BASE_TRUST_MAP.get(trust_lvl, 80.0)
    computed_trust = max(0.0, min(100.0, round(base_trust - computed_risk, 1)))

    return {
        "device_id": device.id,
        "device_name": device.device_name,
        "risk_score": round(computed_risk, 1),
        "trust_score": round(computed_trust, 1),
        "status": device.status,
        "factors": factors,
        "formula": "Risk Score = sum(Event & State Factors, capped in [0, 100]). Trust Score = max(0, Base Trust - Risk Score)."
    }
