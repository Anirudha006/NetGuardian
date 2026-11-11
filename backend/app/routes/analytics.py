import logging
from typing import Optional
from datetime import timedelta
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, case, or_

from app.database import get_db
from app.models.traffic import TrafficRecord
from app.models.alert import Alert
from app.models.device import Device
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.services.auth_service import require_analyst_or_admin
from app.utils.time_utils import utcnow

logger = logging.getLogger("netguardian.analytics")

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])

def resolve_time_cutoff(time_range: str = "all", range_minutes: Optional[int] = None) -> Optional[object]:
    """Calculate the UTC cutoff datetime for filtering analytics queries."""
    now = utcnow()
    if isinstance(range_minutes, (int, float)) and range_minutes > 0:
        return now - timedelta(minutes=range_minutes)
    if isinstance(time_range, str):
        if time_range == "15m":
            return now - timedelta(minutes=15)
        elif time_range == "1h":
            return now - timedelta(hours=1)
    return None

@router.get("")
def get_analytics_data(
    time_range: str = Query("all", description="Time window: '15m', '1h', or 'all'"),
    range_minutes: Optional[int] = Query(None, description="Optional window in minutes"),
    data_source: str = Query("ALL", description="Telemetry source filter: 'ALL', 'SIMULATED', or 'OBSERVED'"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    Returns rich aggregated network and security telemetry formatted for analytical charts.
    All aggregations are computed entirely on the server using SQL (no raw dumps to browser).
    Requires Admin or Analyst authentication.
    """
    cutoff = resolve_time_cutoff(time_range, range_minutes)
    data_src = data_source.strip().upper()

    # 1. Traffic Over Time (binned by minute)
    traffic_q = db.query(
        func.strftime('%H:%M', TrafficRecord.timestamp).label("time_bucket"),
        func.sum(TrafficRecord.packet_count).label("packets"),
        func.sum(TrafficRecord.bytes).label("bytes"),
        func.sum(case((TrafficRecord.is_anomalous == 1, 1), else_=0)).label("anomalies")
    )
    if cutoff:
        traffic_q = traffic_q.filter(TrafficRecord.timestamp >= cutoff)
    if data_src in ["SIMULATED", "OBSERVED"]:
        traffic_q = traffic_q.filter(TrafficRecord.data_source == data_src)

    traffic_rows = traffic_q.group_by("time_bucket").order_by("time_bucket").all()
    traffic_over_time = [
        {
            "time": r[0] or "00:00",
            "packets": int(r[1] or 0),
            "bytes": int(r[2] or 0),
            "anomalies": int(r[3] or 0)
        }
        for r in traffic_rows
    ]

    # 2. Threats Over Time (binned by minute)
    threats_q = db.query(
        func.strftime('%H:%M', SecurityEvent.created_at).label("time_bucket"),
        func.count(SecurityEvent.id).label("count")
    )
    if cutoff:
        threats_q = threats_q.filter(SecurityEvent.created_at >= cutoff)

    threats_rows = threats_q.group_by("time_bucket").order_by("time_bucket").all()
    threats_over_time = [
        {"time": r[0] or "00:00", "count": int(r[1] or 0)}
        for r in threats_rows
    ]

    # 3. Threat Categories Distribution
    cat_q = db.query(
        SecurityEvent.event_type,
        func.count(SecurityEvent.id).label("count")
    )
    if cutoff:
        cat_q = cat_q.filter(SecurityEvent.created_at >= cutoff)

    cat_rows = cat_q.group_by(SecurityEvent.event_type).order_by(func.count(SecurityEvent.id).desc()).all()
    threat_categories = [
        {
            "name": (cat or "GENERAL").replace("_", " ").title(),
            "type": cat,
            "value": int(count)
        }
        for cat, count in cat_rows
    ]

    # 4. Device Risk Distribution (4 Risk Tiers)
    dev_q = db.query(
        case(
            (Device.risk_score < 30.0, "Low (0-29)"),
            ((Device.risk_score >= 30.0) & (Device.risk_score < 70.0), "Medium (30-69)"),
            ((Device.risk_score >= 70.0) & (Device.risk_score < 90.0), "High (70-89)"),
            else_="Critical (90-100)"
        ).label("risk_band"),
        func.count(Device.id).label("count")
    )
    if data_src in ["SIMULATED", "OBSERVED"]:
        dev_q = dev_q.filter(Device.device_source == data_src)

    risk_rows = dict(dev_q.group_by("risk_band").all())
    ordered_bands = [
        ("Low (0-29)", "LOW"),
        ("Medium (30-69)", "MEDIUM"),
        ("High (70-89)", "HIGH"),
        ("Critical (90-100)", "CRITICAL")
    ]
    device_risk_distribution = [
        {"range": b_name, "count": int(risk_rows.get(b_name, 0)), "severity": b_sev}
        for b_name, b_sev in ordered_bands
    ]

    # 5. Protocol Usage
    proto_q = db.query(
        TrafficRecord.protocol,
        func.count(TrafficRecord.id).label("count"),
        func.sum(TrafficRecord.bytes).label("bytes"),
        func.sum(TrafficRecord.packet_count).label("packets")
    )
    if cutoff:
        proto_q = proto_q.filter(TrafficRecord.timestamp >= cutoff)
    if data_src in ["SIMULATED", "OBSERVED"]:
        proto_q = proto_q.filter(TrafficRecord.data_source == data_src)

    proto_rows = proto_q.group_by(TrafficRecord.protocol).order_by(func.sum(TrafficRecord.bytes).desc()).all()
    protocol_usage = [
        {
            "protocol": r[0] or "OTHER",
            "count": int(r[1] or 0),
            "bytes": int(r[2] or 0),
            "packets": int(r[3] or 0)
        }
        for r in proto_rows
    ]

    # 6. Top Communicating Devices
    top_q = db.query(
        TrafficRecord.source_ip,
        func.sum(TrafficRecord.bytes).label("total_bytes"),
        func.sum(TrafficRecord.packet_count).label("total_packets"),
        func.count(TrafficRecord.id).label("flow_count")
    )
    if cutoff:
        top_q = top_q.filter(TrafficRecord.timestamp >= cutoff)
    if data_src in ["SIMULATED", "OBSERVED"]:
        top_q = top_q.filter(TrafficRecord.data_source == data_src)

    top_rows = top_q.group_by(TrafficRecord.source_ip).order_by(func.sum(TrafficRecord.bytes).desc()).limit(10).all()

    devices = db.query(Device.ip_address, Device.device_name).all()
    dev_map = {d.ip_address: d.device_name for d in devices}

    top_communicating = [
        {
            "ip": r[0],
            "name": dev_map.get(r[0], r[0]),
            "bytes": int(r[1] or 0),
            "packets": int(r[2] or 0),
            "flows": int(r[3] or 0)
        }
        for r in top_rows
    ]

    # 7. Anomalies Timeline
    alert_q = db.query(Alert).filter(
        or_(
            Alert.ai_score != None,
            Alert.detection_method.in_(["AI", "RULE+AI", "ML"]),
            Alert.event_type == "TRAFFIC_ANOMALY"
        )
    )
    if cutoff:
        alert_q = alert_q.filter(Alert.created_at >= cutoff)

    anom_alerts = alert_q.order_by(Alert.created_at.desc()).limit(25).all()

    anomalies_timeline = [
        {
            "id": a.id,
            "device": dev_map.get(a.source_ip, a.source_ip or "Network Subnet"),
            "ip": a.source_ip or "N/A",
            "score": round(float(a.ai_score or 0.85), 2),
            "confidence": a.ai_confidence or "High",
            "reasons": a.ai_explanation or a.title or a.message,
            "time": a.created_at.strftime("%H:%M:%S") if a.created_at else "00:00:00",
            "timestamp": a.created_at.isoformat() if a.created_at else ""
        }
        for a in anom_alerts
    ]

    # 8. Summary Metrics (derived directly from aggregated SQL results - zero extra table scans)
    tot_packets = sum(t["packets"] for t in traffic_over_time)
    tot_bytes = sum(t["bytes"] for t in traffic_over_time)
    tot_anomalies = sum(t["anomalies"] for t in traffic_over_time)

    threats_count_q = db.query(func.count(SecurityEvent.id))
    if cutoff:
        threats_count_q = threats_count_q.filter(SecurityEvent.created_at >= cutoff)

    dev_count_q = db.query(func.count(Device.id))
    if data_src in ["SIMULATED", "OBSERVED"]:
        dev_count_q = dev_count_q.filter(Device.device_source == data_src)

    summary_metrics = {
        "total_bytes": int(tot_bytes),
        "total_packets": int(tot_packets),
        "total_threats": int(threats_count_q.scalar() or 0),
        "total_anomalies": int(tot_anomalies),
        "total_devices": int(dev_count_q.scalar() or 0),
        "time_range": time_range,
        "data_source": data_src
    }

    return {
        "traffic_over_time": traffic_over_time,
        "threats_over_time": threats_over_time,
        "threat_categories": threat_categories,
        "device_risk_distribution": device_risk_distribution,
        "protocol_usage": protocol_usage,
        "top_communicating_devices": top_communicating,
        "anomalies_timeline": anomalies_timeline,
        "summary": summary_metrics
    }
