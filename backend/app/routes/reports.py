import io
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_, case

from app.database import get_db
from app.models.device import Device
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.models.traffic import TrafficRecord
from app.models.simulation import SimulationRun, AttackPath
from app.models.user import User
from app.services.health_calculator import calculate_network_health
from app.services.auth_service import require_analyst_or_admin
from app.services.audit_service import record_audit_event
from app.config import settings
from app.utils.time_utils import utcnow

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfgen import canvas

logger = logging.getLogger("netguardian.reports")

router = APIRouter(prefix="/api/reports", tags=["Reports"])

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that dynamically calculates the total page count
    and renders consistent running headers and footers with 'Page X of Y'.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Header (Pages 2+)
        if self._pageNumber > 1:
            self.drawString(40, 755, "NetGuardian: Network Security & Digital Twin Audit Report")
            self.drawRightString(612 - 40, 755, "CONFIDENTIAL · DEFENSIVE CYBERSECURITY")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.6)
            self.line(40, 747, 612 - 40, 747)

        # Footer (All Pages)
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.6)
        self.line(40, 44, 612 - 40, 44)
        self.drawString(40, 31, "NetGuardian AI-Powered Digital Twin Engine · Automated Security Report")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 40, 31, page_text)
        self.restoreState()


def resolve_report_period(time_range: str = "all", range_minutes: Optional[int] = None):
    now = utcnow()
    if range_minutes is not None and range_minutes > 0:
        start_time = now - timedelta(minutes=range_minutes)
        label = f"Last {range_minutes} Minutes ({start_time.strftime('%H:%M')} – {now.strftime('%H:%M')} UTC)"
        return start_time, label
    if time_range == "15m":
        start_time = now - timedelta(minutes=15)
        label = f"Last 15 Minutes ({start_time.strftime('%H:%M')} – {now.strftime('%H:%M')} UTC)"
        return start_time, label
    elif time_range == "1h":
        start_time = now - timedelta(hours=1)
        label = f"Last 1 Hour ({start_time.strftime('%H:%M')} – {now.strftime('%H:%M')} UTC)"
        return start_time, label
    return None, "All Time / Full Operational Session"


def build_report_data(
    db: Session,
    time_range: str = "all",
    range_minutes: Optional[int] = None,
    data_source: str = "ALL"
) -> Dict[str, Any]:
    """Compile comprehensive report data dictionary from real SQLite tables."""
    cutoff, period_label = resolve_report_period(time_range, range_minutes)
    data_src = data_source.strip().upper()

    # 1. Health calculation
    health = calculate_network_health(db)

    # 2. Devices query
    dev_query = db.query(Device)
    if data_src in ["SIMULATED", "OBSERVED"]:
        dev_query = dev_query.filter(Device.device_source == data_src)
    devices = dev_query.order_by(Device.risk_score.desc()).all()
    dev_map = {d.ip_address: d.device_name for d in devices}

    critical_assets = [
        {
            "name": d.device_name,
            "ip": d.ip_address,
            "type": d.device_type,
            "criticality": d.criticality,
            "risk_score": d.risk_score,
            "status": d.status
        }
        for d in devices if d.criticality in ["HIGH", "CRITICAL"]
    ]

    high_risk_devices = [
        {
            "name": d.device_name,
            "ip": d.ip_address,
            "risk_score": d.risk_score,
            "criticality": d.criticality,
            "status": d.status,
            "is_isolated": bool(getattr(d, "is_isolated", False))
        }
        for d in devices if d.risk_score >= 50.0 or getattr(d, "is_isolated", False)
    ]

    # 3. Traffic summary
    tr_query = db.query(TrafficRecord)
    if cutoff:
        tr_query = tr_query.filter(TrafficRecord.timestamp >= cutoff)
    if data_src in ["SIMULATED", "OBSERVED"]:
        tr_query = tr_query.filter(TrafficRecord.data_source == data_src)

    tr_agg = tr_query.with_entities(
        func.sum(TrafficRecord.bytes),
        func.sum(TrafficRecord.packet_count),
        func.sum(case((TrafficRecord.is_anomalous == 1, 1), else_=0))
    ).first()
    total_bytes = int(tr_agg[0] or 0) if tr_agg else 0
    total_packets = int(tr_agg[1] or 0) if tr_agg else 0
    anomalous_flows = int(tr_agg[2] or 0) if tr_agg else 0

    proto_counts = (
        tr_query.with_entities(
            TrafficRecord.protocol,
            func.count(TrafficRecord.id),
            func.sum(TrafficRecord.bytes)
        )
        .group_by(TrafficRecord.protocol)
        .all()
    )
    protocols_summary = [
        {"protocol": p[0], "count": int(p[1]), "bytes": int(p[2] or 0)}
        for p in proto_counts
    ]

    # 4. Security Events & Alerts
    alert_query = db.query(Alert)
    if cutoff:
        alert_query = alert_query.filter(Alert.created_at >= cutoff)
    alerts = alert_query.order_by(Alert.created_at.desc()).limit(20).all()

    security_events = [
        {
            "id": a.id,
            "title": a.title,
            "event_type": a.event_type or a.title,
            "severity": a.severity,
            "source_ip": a.source_ip or "N/A",
            "destination_ip": a.destination_ip or "N/A",
            "rule_name": a.rule_name or "N/A",
            "detection_method": a.detection_method or "RULE",
            "ai_score": a.ai_score,
            "created_at": a.created_at.strftime("%Y-%m-%d %H:%M:%S") if a.created_at else "",
            "recommendation": a.recommendation or "Investigate source device."
        }
        for a in alerts
    ]

    # 5. AI Anomalies
    ai_anomalies = [
        {
            "id": a.id,
            "source_ip": a.source_ip or "N/A",
            "device_name": dev_map.get(a.source_ip, a.source_ip or "Network Host"),
            "score": round(float(a.ai_score or 0.85), 2),
            "confidence": a.ai_confidence or "High",
            "explanation": a.ai_explanation or a.title or "Unusual packet volume and port frequency deviation.",
            "created_at": a.created_at.strftime("%Y-%m-%d %H:%M:%S") if a.created_at else ""
        }
        for a in alerts
        if a.ai_score is not None or a.detection_method in ["AI", "RULE+AI"] or a.event_type == "TRAFFIC_ANOMALY"
    ]

    # 6. Simulated Attack Paths (HYPOTHETICAL)
    sim_runs = db.query(SimulationRun).order_by(SimulationRun.created_at.desc()).limit(10).all()
    simulated_attack_paths = []
    for s in sim_runs:
        attack_paths = db.query(AttackPath).filter(AttackPath.simulation_id == s.id).all()
        paths_repr = [ap.path for ap in attack_paths] if attack_paths else []
        simulated_attack_paths.append({
            "id": s.id,
            "simulation_type": s.simulation_type,
            "target_device": s.target_device,
            "risk_level": s.risk_level,
            "path_risk_score": s.path_risk_score,
            "critical_assets_reached": s.critical_assets_reached,
            "paths": paths_repr,
            "result": s.result,
            "label": "HYPOTHETICAL"
        })

    # 7. Actionable Recommendations
    recommendations = []
    if high_risk_devices:
        isolated_names = [d["name"] for d in high_risk_devices if d["is_isolated"]]
        active_high_names = [d["name"] for d in high_risk_devices if not d["is_isolated"]]
        if active_high_names:
            recommendations.append(
                f"Quarantine high-risk endpoints ({', '.join(active_high_names)}) using Digital Twin Simulated Isolation before applying physical port shutdown."
            )
        if isolated_names:
            recommendations.append(
                f"Maintain network isolation on {', '.join(isolated_names)} until comprehensive forensic root-cause analysis is concluded."
            )

    if simulated_attack_paths:
        recommendations.append(
            "Enforce strict zero-trust network segmentation to interrupt lateral attack paths reaching Crown Jewel Database nodes."
        )

    if anomalous_flows > 0:
        recommendations.append(
            f"Review {anomalous_flows} flagged anomalous traffic flows for signs of unauthorized outbound exfiltration or internal port reconnaissance."
        )

    recommendations.extend([
        "Maintain zero-trust access control lists (ACLs) between general workstation subnets and sensitive database servers.",
        "Verify all newly observed MAC/IP addresses against authorized organizational IT inventory prior to registration.",
        "Perform scheduled What-If lateral movement simulations to validate proactive containment policies."
    ])

    conclusion = (
        "The NetGuardian defensive security architecture successfully maintains continuous behavioral visibility, "
        "combining deterministic rule detection with Isolation Forest Machine Learning anomaly scoring. "
        "The graph-based Digital Twin model accurately maps lateral traversal blast radiuses, enabling non-destructive "
        "threat isolation and measurable risk reduction."
    )

    limitations_paragraph = (
        "LIMITATIONS & DISCLAIMER: Machine Learning anomaly detections and Isolation Forest outlier scores reflect "
        "statistical deviation from established baseline telemetry; anomalies are not proof of attacks. "
        "Anomaly flags require corroboration through rule signatures, log correlation, and forensic verification "
        "by a qualified security analyst."
    )

    simulated_notice = (
        "SIMULATED DATA NOTICE: All network telemetry, topology nodes, traffic flows, and security alerts in this "
        "report are generated via the NetGuardian Simulation Engine for defensive cybersecurity research and training."
    )

    penalties = health.get("penalties", {})
    threat_pen = penalties.get("active_threats", 0.0)
    anomaly_pen = penalties.get("traffic_anomalies", 0.0)
    suspicious_pen = penalties.get("suspicious_devices", 0.0)
    high_risk_pen = penalties.get("high_risk_nodes", 0.0)
    offline_pen = penalties.get("offline_devices", 0.0)
    return {
        "report_title": "NetGuardian Network Security & Digital Twin Audit Report",
        "generated_at": utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "reporting_period": period_label,
        "system_mode": settings.SYSTEM_MODE.upper(),
        "simulated_data_notice": simulated_notice,
        "limitations_paragraph": limitations_paragraph,
        "network_health": {
            "score": health["health_score"],
            "status": health["health_status"],
            "breakdown": {
                "baseline_score": 100.0,
                "threat_penalty": threat_pen,
                "anomaly_penalty": anomaly_pen,
                "suspicious_penalty": suspicious_pen,
                "unregistered_device_penalty": suspicious_pen,
                "high_risk_penalty": high_risk_pen,
                "offline_penalty": offline_pen,
                "containment_credit": health.get("containment_credit", 0.0),
                "total_deductions": health.get("total_deductions", 0.0),
                "formula": "Health = max(0, 100 - Active Threats - Suspicious Devices - High-Risk Nodes - Anomalies - Offline Devices + Credit)"
            }
        },
        "network_overview": {
            "total_devices": len(devices),
            "online_devices": sum(1 for d in devices if d.status == "ONLINE"),
            "suspicious_devices": sum(1 for d in devices if d.status == "SUSPICIOUS"),
            "isolated_devices": sum(1 for d in devices if getattr(d, "is_isolated", False)),
            "total_events": len(alerts),
            "active_threats": sum(1 for a in alerts if a.status in ["NEW", "INVESTIGATING"]),
            "ai_anomalies": len(ai_anomalies),
            "simulations_run": len(sim_runs),
            "total_bytes": int(total_bytes),
            "total_packets": int(total_packets),
            "anomalous_flows": anomalous_flows
        },
        "devices": [
            {
                "name": d.device_name,
                "ip": d.ip_address,
                "mac": d.mac_address or "N/A",
                "type": d.device_type,
                "criticality": d.criticality,
                "risk_score": d.risk_score,
                "status": d.status,
                "trust_level": getattr(d, "trust_level", "MEDIUM"),
                "device_source": getattr(d, "device_source", "SIMULATED"),
                "is_isolated": bool(getattr(d, "is_isolated", False))
            }
            for d in devices
        ],
        "traffic_summary": {
            "total_bytes": int(total_bytes),
            "total_packets": int(total_packets),
            "anomalous_flows": anomalous_flows,
            "protocols": protocols_summary
        },
        "security_events": security_events,
        "ai_anomalies": ai_anomalies,
        "high_risk_devices": high_risk_devices,
        "critical_assets": critical_assets,
        "simulated_attack_paths": simulated_attack_paths,
        "recommendations": recommendations,
        "conclusion": conclusion
    }


def generate_security_report_pdf(rep: Dict[str, Any]) -> bytes:
    """Generate professional, multi-page PDF document using ReportLab."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=45,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor('#475569'),
        spaceAfter=12
    )
    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor('#334155')
    )
    bold_body_style = ParagraphStyle(
        'BoldBody',
        parent=body_style,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#0f172a')
    )
    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor('#1e293b')
    )
    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=table_cell,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#0f172a')
    )
    notice_style = ParagraphStyle(
        'NoticeBox',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#1e40af'),
        backColor=colors.HexColor('#eff6ff'),
        borderColor=colors.HexColor('#bfdbfe'),
        borderWidth=0.8,
        borderPadding=6,
        spaceAfter=10
    )
    limitation_style = ParagraphStyle(
        'LimitationBox',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10.5,
        textColor=colors.HexColor('#7c2d12'),
        backColor=colors.HexColor('#fff7ed'),
        borderColor=colors.HexColor('#fed7aa'),
        borderWidth=0.8,
        borderPadding=6,
        spaceBefore=8,
        spaceAfter=10
    )

    story = []

    # Document Header
    story.append(Paragraph("NetGuardian Security Report", title_style))
    story.append(Spacer(1, 4))

    # 1. Reporting Period
    story.append(Paragraph("1. Reporting Period", h2_style))
    story.append(Paragraph(
        f"<b>Reporting Period:</b> {rep['reporting_period']} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Generated At:</b> {rep['generated_at']} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>System Mode:</b> {rep['system_mode']}",
        body_style
    ))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"<b>{rep['simulated_data_notice']}</b>", notice_style))
    story.append(Spacer(1, 6))

    # 2. Network Overview
    story.append(Paragraph("2. Network Overview", h2_style))
    ov = rep["network_overview"]
    nh = rep["network_health"]
    hb = nh["breakdown"]

    kpi_data = [
        [
            Paragraph(f"<b>Network Health:</b> {nh['score']}% ({nh['status']})", table_cell),
            Paragraph(f"<b>Devices Monitored:</b> {ov['total_devices']}", table_cell),
            Paragraph(f"<b>Devices Online:</b> {ov['online_devices']}", table_cell)
        ],
        [
            Paragraph(f"<b>Active Threats:</b> {ov['active_threats']}", table_cell),
            Paragraph(f"<b>AI Anomalies Flagged:</b> {ov['ai_anomalies']}", table_cell),
            Paragraph(f"<b>Isolated Devices:</b> {ov['isolated_devices']}", table_cell)
        ]
    ]
    kpi_table = Table(kpi_data, colWidths=[175, 175, 180])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 6))

    # Health Breakdown Table
    hb_data = [
        [
            Paragraph("<b>Formula Component</b>", table_cell_bold),
            Paragraph("<b>Impact</b>", table_cell_bold),
            Paragraph("<b>Description</b>", table_cell_bold)
        ],
        [Paragraph("Baseline Health", table_cell), Paragraph("100.0 pts", table_cell), Paragraph("Clean network baseline standard.", table_cell)],
        [Paragraph("Active Threat Penalty", table_cell), Paragraph(f"-{hb['threat_penalty']} pts", table_cell), Paragraph("Penalty applied for uncontained alerts and open threats.", table_cell)],
        [Paragraph("AI Anomaly Penalty", table_cell), Paragraph(f"-{hb['anomaly_penalty']} pts", table_cell), Paragraph("Penalty applied for active Isolation Forest behavioral outliers.", table_cell)],
        [Paragraph("Unregistered Device Penalty", table_cell), Paragraph(f"-{hb['unregistered_device_penalty']} pts", table_cell), Paragraph("Penalty applied for rogue / unregistered network devices.", table_cell)],
        [Paragraph("Containment Credit", table_cell), Paragraph(f"+{hb['containment_credit']} pts", table_cell), Paragraph("Credit awarded for isolated endpoints mitigating lateral risk.", table_cell)],
        [Paragraph("<b>Effective Network Health</b>", table_cell_bold), Paragraph(f"<b>{nh['score']}% ({nh['status']})</b>", table_cell_bold), Paragraph(f"<b>{hb['formula']}</b>", table_cell)]
    ]
    hb_table = Table(hb_data, colWidths=[130, 80, 320])
    hb_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(hb_table)
    story.append(Spacer(1, 8))

    # 3. Devices
    story.append(Paragraph("3. Devices", h2_style))
    if rep["devices"]:
        dev_rows = [
            [
                Paragraph("<b>Name</b>", table_cell_bold),
                Paragraph("<b>IP Address</b>", table_cell_bold),
                Paragraph("<b>Type</b>", table_cell_bold),
                Paragraph("<b>Criticality</b>", table_cell_bold),
                Paragraph("<b>Risk</b>", table_cell_bold),
                Paragraph("<b>Status</b>", table_cell_bold)
            ]
        ]
        for d in rep["devices"][:12]:
            dev_rows.append([
                Paragraph(d["name"], table_cell),
                Paragraph(d["ip"], table_cell),
                Paragraph(d["type"], table_cell),
                Paragraph(d["criticality"], table_cell),
                Paragraph(f"{d['risk_score']:.1f}", table_cell),
                Paragraph(f"{'ISOLATED' if d['is_isolated'] else d['status']}", table_cell)
            ])
        dev_table = Table(dev_rows, colWidths=[110, 95, 85, 80, 60, 100])
        dev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(dev_table)
    else:
        story.append(Paragraph("No devices currently enrolled in network inventory.", body_style))

    story.append(PageBreak())

    # 4. Traffic Summary
    story.append(Paragraph("4. Traffic Summary", h2_style))
    ts = rep["traffic_summary"]
    tr_text = f"Total Packets Monitored: <b>{ts['total_packets']:,}</b> | Total Bytes: <b>{ts['total_bytes']:,}</b> | Anomalous Flows: <b>{ts['anomalous_flows']}</b>"
    story.append(Paragraph(tr_text, body_style))
    story.append(Spacer(1, 4))
    if ts["protocols"]:
        proto_data = [[
            Paragraph("<b>Protocol</b>", table_cell_bold),
            Paragraph("<b>Flow Count</b>", table_cell_bold),
            Paragraph("<b>Total Volume (Bytes)</b>", table_cell_bold)
        ]]
        for p in ts["protocols"]:
            proto_data.append([
                Paragraph(p["protocol"], table_cell),
                Paragraph(str(p["count"]), table_cell),
                Paragraph(f"{p['bytes']:,} bytes", table_cell)
            ])
        proto_table = Table(proto_data, colWidths=[120, 150, 260])
        proto_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(proto_table)
    story.append(Spacer(1, 8))

    # 5. Security Events
    story.append(Paragraph("5. Security Events", h2_style))
    if rep["security_events"]:
        ev_rows = [
            [
                Paragraph("<b>Alert Title</b>", table_cell_bold),
                Paragraph("<b>Severity</b>", table_cell_bold),
                Paragraph("<b>Source</b>", table_cell_bold),
                Paragraph("<b>Method</b>", table_cell_bold),
                Paragraph("<b>Recommendation</b>", table_cell_bold)
            ]
        ]
        for e in rep["security_events"][:8]:
            ev_rows.append([
                Paragraph(e["title"], table_cell),
                Paragraph(e["severity"], table_cell),
                Paragraph(e["source_ip"], table_cell),
                Paragraph(e["detection_method"], table_cell),
                Paragraph(e["recommendation"], table_cell)
            ])
        ev_table = Table(ev_rows, colWidths=[120, 55, 80, 65, 210])
        ev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(ev_table)
    else:
        story.append(Paragraph("No events in reporting period.", body_style))
    story.append(Spacer(1, 8))

    # 6. AI Anomalies
    story.append(Paragraph("6. AI Anomalies", h2_style))
    if rep["ai_anomalies"]:
        an_rows = [
            [
                Paragraph("<b>Source Device / IP</b>", table_cell_bold),
                Paragraph("<b>Score</b>", table_cell_bold),
                Paragraph("<b>Confidence</b>", table_cell_bold),
                Paragraph("<b>Explainable AI Contributing Factors</b>", table_cell_bold)
            ]
        ]
        for a in rep["ai_anomalies"][:6]:
            an_rows.append([
                Paragraph(f"{a['device_name']} ({a['source_ip']})", table_cell),
                Paragraph(f"{a['score']}", table_cell),
                Paragraph(a['confidence'], table_cell),
                Paragraph(a['explanation'], table_cell)
            ])
        an_table = Table(an_rows, colWidths=[140, 45, 65, 280])
        an_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(an_table)
    else:
        story.append(Paragraph("No AI anomalies detected in this reporting period.", body_style))

    story.append(PageBreak())

    # 7. High-Risk Devices
    story.append(Paragraph("7. High-Risk Devices", h2_style))
    if rep["high_risk_devices"]:
        hr_data = [
            [
                Paragraph("<b>Device Name</b>", table_cell_bold),
                Paragraph("<b>IP Address</b>", table_cell_bold),
                Paragraph("<b>Risk Score</b>", table_cell_bold),
                Paragraph("<b>Criticality</b>", table_cell_bold),
                Paragraph("<b>Containment Status</b>", table_cell_bold)
            ]
        ]
        for hr in rep["high_risk_devices"][:5]:
            c_status = "ISOLATED (Simulated Quarantine)" if hr["is_isolated"] else f"Active ({hr['status']})"
            hr_data.append([
                Paragraph(hr["name"], table_cell),
                Paragraph(hr["ip"], table_cell),
                Paragraph(f"{hr['risk_score']:.1f}/100", table_cell),
                Paragraph(hr["criticality"], table_cell),
                Paragraph(c_status, table_cell)
            ])
        hr_table = Table(hr_data, colWidths=[120, 100, 70, 80, 160])
        hr_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#fef2f2')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#fca5a5')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#fee2e2')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(hr_table)
    else:
        story.append(Paragraph("No high-risk endpoints identified.", body_style))
    story.append(Spacer(1, 8))

    # 8. Critical Assets
    story.append(Paragraph("8. Critical Assets", h2_style))
    if rep.get("critical_assets"):
        ca_data = [
            [
                Paragraph("<b>Asset Name</b>", table_cell_bold),
                Paragraph("<b>IP Address</b>", table_cell_bold),
                Paragraph("<b>Role</b>", table_cell_bold),
                Paragraph("<b>Criticality</b>", table_cell_bold),
                Paragraph("<b>Risk Score</b>", table_cell_bold)
            ]
        ]
        for ca in rep["critical_assets"][:5]:
            ca_data.append([
                Paragraph(ca["name"], table_cell),
                Paragraph(ca["ip"], table_cell),
                Paragraph(ca["type"], table_cell),
                Paragraph(ca["criticality"], table_cell),
                Paragraph(f"{ca['risk_score']:.1f}/100", table_cell)
            ])
        ca_table = Table(ca_data, colWidths=[120, 100, 100, 80, 130])
        ca_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(ca_table)
    else:
        story.append(Paragraph("No critical infrastructure assets recorded.", body_style))
    story.append(Spacer(1, 8))

    # 9. Simulated Attack Paths (HYPOTHETICAL)
    story.append(Paragraph("9. Simulated Attack Paths (HYPOTHETICAL)", h2_style))
    if rep["simulated_attack_paths"]:
        sim_data = [
            [
                Paragraph("<b>Simulation Type</b>", table_cell_bold),
                Paragraph("<b>Target Asset</b>", table_cell_bold),
                Paragraph("<b>Risk Level</b>", table_cell_bold),
                Paragraph("<b>Path Score</b>", table_cell_bold),
                Paragraph("<b>Result & Traversal Summary</b>", table_cell_bold)
            ]
        ]
        for sp in rep["simulated_attack_paths"][:5]:
            sim_data.append([
                Paragraph(f"{sp['simulation_type']} [HYPOTHETICAL]", table_cell),
                Paragraph(sp["target_device"], table_cell),
                Paragraph(sp["risk_level"], table_cell),
                Paragraph(f"{sp['path_risk_score']:.1f}", table_cell),
                Paragraph(sp["result"][:120], table_cell)
            ])
        sim_table = Table(sim_data, colWidths=[120, 90, 60, 60, 200])
        sim_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(sim_table)
    else:
        story.append(Paragraph("No hypothetical attack paths simulated in this reporting period.", body_style))
    story.append(Spacer(1, 8))

    # 10. Recommendations
    story.append(Paragraph("10. Recommendations", h2_style))
    for i, rec in enumerate(rep["recommendations"][:5], 1):
        story.append(Paragraph(f"<b>{i}.</b> {rec}", body_style))
        story.append(Spacer(1, 2))
    story.append(Spacer(1, 6))

    # 11. Conclusion
    story.append(Paragraph("11. Conclusion", h2_style))
    story.append(Paragraph(rep["conclusion"], body_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(rep["limitations_paragraph"], limitation_style))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()


@router.get("/summary")
def get_security_report_summary(
    time_range: str = Query("all", description="Reporting time window: '15m', '1h', or 'all'"),
    range_minutes: Optional[int] = Query(None, description="Optional window in minutes"),
    data_source: str = Query("ALL", description="Data source filter: 'ALL', 'SIMULATED', or 'OBSERVED'"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    Generate comprehensive structured NetGuardian Security Report object.
    Audit logged on generation. Requires Analyst or Admin role.
    """
    rep = build_report_data(db, time_range, range_minutes, data_source)
    record_audit_event(
        db=db,
        action="GENERATE_REPORT",
        user_id=current_user.id if current_user else None,
        username=current_user.username if current_user else "anonymous",
        details=f"Generated JSON security report for period '{rep['reporting_period']}' (mode: {rep['system_mode']}, source: {data_source})"
    )
    return rep


@router.get("/export-html", response_class=HTMLResponse)
def export_report_html(
    time_range: str = Query("all", description="Reporting time window: '15m', '1h', or 'all'"),
    range_minutes: Optional[int] = Query(None, description="Optional window in minutes"),
    data_source: str = Query("ALL", description="Data source filter: 'ALL', 'SIMULATED', or 'OBSERVED'"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    Generate professional printable HTML audit report.
    Audit logged on generation. Requires Analyst or Admin role.
    """
    rep = build_report_data(db, time_range, range_minutes, data_source)
    record_audit_event(
        db=db,
        action="GENERATE_REPORT",
        user_id=current_user.id if current_user else None,
        username=current_user.username if current_user else "anonymous",
        details=f"Generated HTML printable security report for period '{rep['reporting_period']}' (source: {data_source})"
    )

    rows_alerts = "".join([
        f"<tr><td>{a['id']}</td><td><b>{a['title']}</b></td><td><span class='badge {a['severity'].lower()}'>{a['severity']}</span></td><td>{a['source_ip']}</td><td>{a['recommendation']}</td></tr>"
        for a in rep["security_events"]
    ]) or "<tr><td colspan='5'>No events in reporting period.</td></tr>"

    rows_high_risk = "".join([
        f"<tr><td>{d['name']}</td><td>{d['ip']}</td><td>{d['risk_score']:.1f}/100</td><td>{'ISOLATED' if d['is_isolated'] else d['status']}</td></tr>"
        for d in rep["high_risk_devices"]
    ]) or "<tr><td colspan='4'>No high-risk devices present.</td></tr>"

    rows_sim = "".join([
        f"<tr><td>{s['simulation_type']} [HYPOTHETICAL]</td><td>{s['target_device']}</td><td>{s['path_risk_score']:.1f}</td><td>{s['result'][:120]}</td></tr>"
        for s in rep["simulated_attack_paths"]
    ]) or "<tr><td colspan='4'>No hypothetical attack paths simulated in this reporting period.</td></tr>"

    rows_devices = "".join([
        f"<tr><td><b>{d['name']}</b></td><td>{d['ip']}</td><td>{d['type']}</td><td>{d['criticality']}</td><td>{d['risk_score']:.1f}/100</td><td>{'ISOLATED' if d['is_isolated'] else d['status']}</td></tr>"
        for d in rep["devices"]
    ]) or "<tr><td colspan='6'>No devices in network inventory.</td></tr>"

    rows_critical = "".join([
        f"<tr><td><b>{c['name']}</b></td><td>{c['ip']}</td><td>{c['type']}</td><td>{c['criticality']}</td><td>{c['risk_score']:.1f}/100</td><td>{c['status']}</td></tr>"
        for c in rep.get("critical_assets", [])
    ]) or "<tr><td colspan='6'>No designated critical assets.</td></tr>"

    rows_anomalies = "".join([
        f"<tr><td><b>{a['device_name']}</b> ({a['source_ip']})</td><td>{a['score']}</td><td>{a['confidence']}</td><td>{a['explanation']}</td></tr>"
        for a in rep["ai_anomalies"]
    ]) or "<tr><td colspan='4'>No AI anomalies detected in this reporting period.</td></tr>"

    rows_protocols = "".join([
        f"<tr><td><b>{p['protocol']}</b></td><td>{p['count']}</td><td>{p['bytes']:,} bytes</td></tr>"
        for p in rep["traffic_summary"].get("protocols", [])
    ]) or "<tr><td colspan='3'>No protocol data recorded.</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NetGuardian Security Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 40px; color: #0f172a; background: #ffffff; line-height: 1.5; }}
  .header {{ border-bottom: 2px solid #0284c7; padding-bottom: 16px; margin-bottom: 24px; }}
  .header h1 {{ color: #0f172a; margin: 0 0 6px 0; font-size: 24px; font-weight: 800; }}
  .meta {{ color: #64748b; font-size: 13px; }}
  .notice-banner {{ background: #eff6ff; border: 1px solid #bfdbfe; color: #1e40af; border-radius: 6px; padding: 12px 16px; font-size: 12px; margin-bottom: 24px; font-weight: 600; }}
  .kpi-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
  .kpi-card {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px 16px; background: #f8fafc; }}
  .kpi-val {{ font-size: 22px; font-weight: 800; color: #0284c7; }}
  .kpi-lbl {{ font-size: 11px; text-transform: uppercase; color: #64748b; margin-top: 4px; font-weight: 600; }}
  h2 {{ color: #0f172a; font-size: 16px; font-weight: 700; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-top: 28px; margin-bottom: 12px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; }}
  th {{ background: #f1f5f9; color: #334155; font-weight: 700; font-size: 12px; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #fff; }}
  .badge.critical {{ background: #ef4444; }}
  .badge.high {{ background: #f97316; }}
  .badge.medium {{ background: #eab308; }}
  .badge.low {{ background: #3b82f6; }}
  .limitation-box {{ background: #fff7ed; border: 1px solid #fed7aa; color: #9a3412; border-radius: 6px; padding: 12px 16px; font-size: 12px; margin-top: 24px; }}
  .print-btn {{ background: #0284c7; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; margin-bottom: 16px; }}
  @media print {{ .print-btn {{ display: none; }} body {{ margin: 15px; }} }}
</style>
</head>
<body>
<button class="print-btn" onclick="window.print()">🖨️ Print / Save as PDF</button>

<div class="header">
  <h1>NetGuardian: Network Security & Digital Twin Audit Report</h1>
</div>

<h2>1. Reporting Period</h2>
<div class="meta" style="margin-bottom: 10px;">
  <b>Period:</b> {rep['reporting_period']} &nbsp;|&nbsp; <b>Generated:</b> {rep['generated_at']} &nbsp;|&nbsp; <b>System Mode:</b> {rep['system_mode']}
</div>
<div class="notice-banner">
  {rep['simulated_data_notice']}
</div>

<h2>2. Network Overview</h2>
<div class="kpi-row">
  <div class="kpi-card">
    <div class="kpi-val">{rep['network_health']['score']}%</div>
    <div class="kpi-lbl">Network Health ({rep['network_health']['status']})</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-val">{rep['network_overview']['total_devices']}</div>
    <div class="kpi-lbl">Devices Monitored</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-val">{rep['network_overview']['active_threats']}</div>
    <div class="kpi-lbl">Active Threats</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-val">{rep['network_overview']['ai_anomalies']}</div>
    <div class="kpi-lbl">AI Anomalies Flagged</div>
  </div>
</div>
<table>
  <tr><th>Metric</th><th>Score / Impact</th><th>Breakdown Detail</th></tr>
  <tr><td>Baseline Standard</td><td>100.0 pts</td><td>Baseline clean network operation</td></tr>
  <tr><td>Threat Penalty</td><td>-{rep['network_health']['breakdown']['threat_penalty']} pts</td><td>Active security alerts penalty</td></tr>
  <tr><td>Anomaly Penalty</td><td>-{rep['network_health']['breakdown']['anomaly_penalty']} pts</td><td>Behavioral anomaly penalty</td></tr>
  <tr><td>Unregistered Penalty</td><td>-{rep['network_health']['breakdown']['unregistered_device_penalty']} pts</td><td>Rogue host deduction</td></tr>
  <tr><td>Containment Credit</td><td>+{rep['network_health']['breakdown']['containment_credit']} pts</td><td>Isolated endpoints risk reduction</td></tr>
  <tr><td><b>Effective Health</b></td><td><b>{rep['network_health']['score']}%</b></td><td><b>{rep['network_health']['status']}</b></td></tr>
</table>

<h2>3. Devices</h2>
<table>
  <tr><th>Device Name</th><th>IP Address</th><th>Type</th><th>Criticality</th><th>Risk Score</th><th>Status</th></tr>
  {rows_devices}
</table>

<h2>4. Traffic Summary</h2>
<p>Total Packets: <b>{rep['traffic_summary']['total_packets']:,}</b> | Total Bytes: <b>{rep['traffic_summary']['total_bytes']:,}</b> | Anomalies: <b>{rep['traffic_summary']['anomalous_flows']}</b></p>
<table>
  <tr><th>Protocol</th><th>Flow Count</th><th>Volume (Bytes)</th></tr>
  {rows_protocols}
</table>

<h2>5. Security Events</h2>
<table>
  <tr><th>ID</th><th>Alert Title</th><th>Severity</th><th>Source</th><th>Recommendation</th></tr>
  {rows_alerts}
</table>

<h2>6. AI Anomalies</h2>
<table>
  <tr><th>Source Device</th><th>Score</th><th>Confidence</th><th>Contributing Factors</th></tr>
  {rows_anomalies}
</table>

<h2>7. High-Risk Devices</h2>
<table>
  <tr><th>Device Name</th><th>IP Address</th><th>Simulated Risk Score</th><th>Status</th></tr>
  {rows_high_risk}
</table>

<h2>8. Critical Assets</h2>
<table>
  <tr><th>Asset Name</th><th>IP Address</th><th>Role</th><th>Criticality</th><th>Risk Score</th><th>Status</th></tr>
  {rows_critical}
</table>

<h2>9. Simulated Attack Paths</h2>
<table>
  <tr><th>Simulation Type</th><th>Target Asset</th><th>Path Risk Score</th><th>Result</th></tr>
  {rows_sim}
</table>

<h2>10. Recommendations</h2>
<ul>
  {''.join([f'<li>{r}</li>' for r in rep['recommendations']])}
</ul>

<h2>11. Conclusion</h2>
<p>{rep['conclusion']}</p>

<div class="limitation-box">
  {rep['limitations_paragraph']}
</div>
</body>
</html>
"""
    return HTMLResponse(content=html)


@router.get("/export-pdf")
def export_report_pdf(
    time_range: str = Query("all", description="Reporting time window: '15m', '1h', or 'all'"),
    range_minutes: Optional[int] = Query(None, description="Optional window in minutes"),
    data_source: str = Query("ALL", description="Data source filter: 'ALL', 'SIMULATED', or 'OBSERVED'"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    Generate professional multi-page downloadable PDF security report.
    Audit logged on generation. Requires Analyst or Admin role.
    """
    rep = build_report_data(db, time_range, range_minutes, data_source)
    record_audit_event(
        db=db,
        action="GENERATE_REPORT",
        user_id=current_user.id if current_user else None,
        username=current_user.username if current_user else "anonymous",
        details=f"Generated downloadable PDF report for period '{rep['reporting_period']}' (source: {data_source})"
    )

    pdf_bytes = generate_security_report_pdf(rep)
    filename = f"NetGuardian_Security_Report_{time_range}_{data_source.lower()}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Type": "application/pdf"
        }
    )
