from datetime import datetime
from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.device import Device
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.models.traffic import TrafficRecord
from app.models.simulation import SimulationRun
from app.services.health_calculator import calculate_network_health
from app.utils.time_utils import utcnow

router = APIRouter(prefix="/api/reports", tags=["Reports"])

@router.get("/summary")
def get_security_report(db: Session = Depends(get_db)):
    """Generate comprehensive NetGuardian Security Report object matching Section 35."""
    health = calculate_network_health(db)
    devices = db.query(Device).all()
    critical_assets = [d.device_name for d in devices if d.criticality in ["HIGH", "CRITICAL"]]
    high_risk_devices = [
        {"name": d.device_name, "ip": d.ip_address, "risk": d.risk_score, "status": d.status}
        for d in devices if d.risk_score >= 50.0
    ]

    total_traffic_bytes = db.query(func.sum(TrafficRecord.bytes)).scalar() or 0
    total_traffic_pkts = db.query(func.sum(TrafficRecord.packet_count)).scalar() or 0
    anomalies_count = db.query(TrafficRecord).filter(TrafficRecord.is_anomalous == 1).count()

    alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(10).all()
    sim_runs = db.query(SimulationRun).order_by(SimulationRun.created_at.desc()).limit(5).all()

    return {
        "report_title": "NetGuardian Network Security & Digital Twin Audit Report",
        "generated_at": utcnow().isoformat(),
        "reporting_period": "Real-time Operational Session",
        "network_health_score": health["health_score"],
        "network_health_status": health["health_status"],
        "devices_monitored_count": len(devices),
        "critical_assets": critical_assets,
        "high_risk_devices": high_risk_devices,
        "traffic_summary": {
            "total_bytes": int(total_traffic_bytes),
            "total_packets": int(total_traffic_pkts),
            "ai_anomalies_detected": anomalies_count
        },
        "recent_security_events": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "source": a.source_ip,
                "rule": a.rule_name,
                "ai_score": a.ai_score,
                "recommendation": a.recommendation
            }
            for a in alerts
        ],
        "simulated_attack_paths": [
            {
                "id": s.id,
                "target": s.target_device,
                "risk_level": s.risk_level,
                "path_risk_score": s.path_risk_score,
                "result": s.result
            }
            for s in sim_runs
        ],
        "recommendations": [
            "Maintain strict zero-trust segmentation between user workstations and internal database nodes.",
            "Continue periodic automated What-If simulations to identify latent lateral traversal paths.",
            "Verify all unfamiliar MAC/IP addresses against authorized college/organization equipment inventory.",
            "Quarantine high-risk endpoints using Digital Twin Simulated Isolation before applying physical port shutdown."
        ],
        "conclusion": (
            "The NetGuardian Digital Twin architecture successfully maintains real-time behavioral visibility "
            "and enables proactive, non-destructive threat modeling. Network risks are transparently scored and mitigated."
        )
    }

@router.get("/export-html", response_class=HTMLResponse)
def export_report_html(db: Session = Depends(get_db)):
    """Generate professional printable HTML audit report."""
    rep = get_security_report(db)
    
    rows_alerts = "".join([
        f"<tr><td>{a['id']}</td><td><b>{a['title']}</b></td><td><span class='badge {a['severity'].lower()}'>{a['severity']}</span></td><td>{a['source']}</td><td>{a['recommendation']}</td></tr>"
        for a in rep["recent_security_events"]
    ]) or "<tr><td colspan='5'>No security alerts recorded.</td></tr>"

    rows_high_risk = "".join([
        f"<tr><td>{d['name']}</td><td>{d['ip']}</td><td>{d['risk']}/100</td><td>{d['status']}</td></tr>"
        for d in rep["high_risk_devices"]
    ]) or "<tr><td colspan='4'>No high-risk devices present.</td></tr>"

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>NetGuardian Security Audit Report</title>
<style>
  body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; color: #1e293b; background: #ffffff; }}
  .header {{ border-bottom: 3px solid #0284c7; padding-bottom: 20px; margin-bottom: 30px; }}
  .header h1 {{ color: #0f172a; margin: 0; font-size: 26px; }}
  .meta {{ color: #64748b; font-size: 14px; margin-top: 6px; }}
  .kpi-row {{ display: flex; gap: 20px; margin-bottom: 30px; }}
  .kpi-card {{ flex: 1; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; background: #f8fafc; }}
  .kpi-val {{ font-size: 24px; font-weight: bold; color: #0284c7; }}
  .kpi-lbl {{ font-size: 12px; text-transform: uppercase; color: #64748b; margin-top: 4px; }}
  h2 {{ color: #0f172a; font-size: 18px; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; margin-top: 30px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 14px; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 10px; text-align: left; }}
  th {{ background: #f1f5f9; color: #334155; }}
  .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #fff; }}
  .badge.critical {{ background: #ef4444; }}
  .badge.high {{ background: #f97316; }}
  .badge.medium {{ background: #eab308; }}
  .badge.low {{ background: #3b82f6; }}
  .print-btn {{ background: #0284c7; color: #fff; border: none; padding: 10px 18px; border-radius: 6px; cursor: pointer; font-size: 14px; margin-bottom: 20px; }}
  @media print {{ .print-btn {{ display: none; }} body {{ margin: 10px; }} }}
</style>
</head>
<body>
<button class="print-btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
<div class="header">
  <h1>NetGuardian: Network Security & Digital Twin Audit Report</h1>
  <div class="meta">Generated: {rep['generated_at']} | Scope: {rep['reporting_period']} | System Mode: SIMULATION</div>
</div>

<div class="kpi-row">
  <div class="kpi-card">
    <div class="kpi-val">{rep['network_health_score']}%</div>
    <div class="kpi-lbl">Network Health ({rep['network_health_status']})</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-val">{rep['devices_monitored_count']}</div>
    <div class="kpi-lbl">Devices in Digital Twin</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-val">{len(rep['recent_security_events'])}</div>
    <div class="kpi-lbl">Total Security Alerts</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-val">{rep['traffic_summary']['ai_anomalies_detected']}</div>
    <div class="kpi-lbl">AI Anomalies Flagged</div>
  </div>
</div>

<h2>High-Risk Network Devices</h2>
<table>
  <tr><th>Device Name</th><th>IP Address</th><th>Simulated Risk Score</th><th>Status</th></tr>
  {rows_high_risk}
</table>

<h2>Security Alerts & Detected Threats</h2>
<table>
  <tr><th>ID</th><th>Alert Title</th><th>Severity</th><th>Source</th><th>Recommendation</th></tr>
  {rows_alerts}
</table>

<h2>Recommendations & Mitigations</h2>
<ul>
  {''.join([f'<li>{r}</li>' for r in rep['recommendations']])}
</ul>

<h2>Conclusion</h2>
<p>{rep['conclusion']}</p>
</body>
</html>
"""
    return HTMLResponse(content=html)
