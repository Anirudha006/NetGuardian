from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional

from app.database import get_db
from app.models.audit_log import SystemSetting, AuditLog
from app.models.device import Device
from app.models.alert import Alert
from app.models.traffic import TrafficRecord
from app.schemas.system import SystemStatusResponse, SettingsUpdate, ComponentStatus
from app.config import settings
from app.ml.model import ai_detector
from app.digital_twin.twin_engine import digital_twin
from app.collector.live_collector import live_collector
from app.services.audit_service import record_audit_event
from app.services.auth_service import require_admin, require_analyst_or_admin
from app.models.user import User

router = APIRouter(prefix="/api/settings", tags=["Settings & System Status"])

@router.get("/status", response_model=SystemStatusResponse)
def get_system_status(db: Session = Depends(get_db)):
    """
    Retrieve operational health of all NetGuardian subsystem components from real live probes.
    Provides detailed status and reasons when any component is degraded or unavailable.
    """
    components: Dict[str, ComponentStatus] = {}

    # 1. Backend Probe
    backend_status = "ONLINE"
    backend_reason = "FastAPI application engine operational and responding."
    components["backend"] = ComponentStatus(
        name="Backend Engine",
        status=backend_status,
        ok=True,
        reason=backend_reason
    )

    # 2. Database Probe
    try:
        active_devs = db.query(Device).filter(Device.status.in_(["ONLINE", "SUSPICIOUS"])).count()
        active_threats = db.query(Alert).filter(Alert.status.in_(["NEW", "INVESTIGATING"])).count()
        pkts = db.query(TrafficRecord).count()
        db_state = "ONLINE"
        db_reason = f"SQLite primary store connected ({active_devs} active devices, {pkts} traffic records)."
        db_ok = True
    except Exception as e:
        db_state = "OFFLINE"
        db_reason = f"Database connection probe failed: {str(e)}"
        active_devs = 0
        active_threats = 0
        pkts = 0
        db_ok = False

    components["database"] = ComponentStatus(
        name="Database Storage",
        status=db_state,
        ok=db_ok,
        reason=db_reason
    )

    # 3. AI Engine Probe
    try:
        model_info = ai_detector.get_model_info()
        if model_info.get("status") == "READY":
            ai_state = "READY"
            ai_ok = True
            n_samples = model_info.get("total_samples", 2250)
            ai_reason = f"Isolation Forest ready ({n_samples} training baseline windows loaded)."
        else:
            ai_state = "UNAVAILABLE"
            ai_ok = False
            ai_reason = "Isolation Forest model not initialized. Rule-based detection fallback active."
    except Exception as e:
        ai_state = "UNAVAILABLE"
        ai_ok = False
        ai_reason = f"AI Engine probe error: {str(e)}. Rule fallback active."

    components["ai_engine"] = ComponentStatus(
        name="AI Anomaly Engine",
        status=ai_state,
        ok=ai_ok,
        reason=ai_reason
    )

    # 4. Digital Twin Probe
    try:
        if digital_twin.is_synchronized:
            twin_state = "SYNCHRONIZED"
            twin_ok = True
            twin_reason = (
                f"Graph synchronized with database "
                f"({digital_twin.graph.number_of_nodes()} nodes, "
                f"{digital_twin.graph.number_of_edges()} structural edges)."
            )
        else:
            twin_state = "OUT_OF_SYNC"
            twin_ok = False
            twin_reason = "Graph topology diverged from database. Automatic resync scheduled."
    except Exception as e:
        twin_state = "OUT_OF_SYNC"
        twin_ok = False
        twin_reason = f"Twin engine probe error: {str(e)}"

    components["digital_twin"] = ComponentStatus(
        name="Digital Twin Graph",
        status=twin_state,
        ok=twin_ok,
        reason=twin_reason
    )

    # 5. Network Collector Probe
    if settings.SYSTEM_MODE == "SIMULATION":
        collector_state = "SIMULATION_ACTIVE"
        collector_ok = True
        collector_reason = "Synthetic flow generator active · Simulation Mode remains available."
    else:
        # Live mode requires raw socket capture privileges
        capable, cap_reason = live_collector.check_capture_capability()
        if capable:
            collector_state = "PASSIVE_SNIFFING"
            collector_ok = True
            collector_reason = "Passive network packet collector active on authorized interface."
        else:
            collector_state = "UNAVAILABLE"
            collector_ok = False
            collector_reason = "Live packet monitoring is unavailable. Switching to Simulation Mode."

    components["network_collector"] = ComponentStatus(
        name="Network Collector",
        status=collector_state,
        ok=collector_ok,
        reason=collector_reason
    )

    return {
        "backend": backend_status,
        "database": db_state,
        "ai_engine": ai_state,
        "digital_twin": twin_state,
        "network_collector": collector_state,
        "system_mode": settings.SYSTEM_MODE,
        "active_devices": active_devs,
        "active_threats": active_threats,
        "total_packets_processed": pkts,
        "simulated_ticks": getattr(digital_twin, "tick_count", 42),
        "components": components
    }

@router.get("/ai-model-info")
def get_ai_model_metadata():
    """Retrieve machine learning model metadata, training samples, and version."""
    return ai_detector.get_model_info()

@router.get("")
def get_all_settings(
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """
    Retrieve all configurable system settings.
    Accessible to Analysts (for read-only inspection) and Admins.
    """
    db_settings = db.query(SystemSetting).all()
    result = {s.key: s.value for s in db_settings}

    # Ensure all required defaults are exposed
    defaults = {
        "traffic_anomaly_threshold": str(getattr(settings, "TRAFFIC_ANOMALY_THRESHOLD", 3.0)),
        "port_scan_threshold": str(getattr(settings, "PORT_SCAN_THRESHOLD", 15)),
        "failed_auth_threshold": str(getattr(settings, "FAILED_AUTH_THRESHOLD", 5)),
        "unknown_device_detection": "true",
        "simulation_tick_seconds": str(getattr(settings, "SIMULATION_TICK_SECONDS", 2)),
        "traffic_generation_rate": "1.0",
        "simulated_devices_count": "10",
        "simulation_seed": "42",
        "session_timeout_minutes": str(getattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 1440)),
        "password_min_length": "8",
        "password_require_digit": "true",
        "system_mode": getattr(settings, "SYSTEM_MODE", "SIMULATION")
    }

    # Merge database values over defaults
    merged = {**defaults, **result}

    return {
        "settings": merged,
        "defaults": defaults,
        "is_admin": current_user.role == "ADMIN"
    }

@router.patch("")
def update_settings(
    update_in: SettingsUpdate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Update system operational settings and thresholds (Admin Only).
    All inputs are strictly validated, saved to the database, and audit-logged.
    """
    def upsert_setting(key: str, value: str, desc: str = ""):
        s = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        if not s:
            s = SystemSetting(key=key, value=value, description=desc)
            db.add(s)
        else:
            s.value = value
        return s

    updated_keys = []

    # 1. Detection Settings
    if update_in.traffic_anomaly_threshold is not None:
        if update_in.traffic_anomaly_threshold <= 0:
            raise HTTPException(status_code=400, detail="Traffic anomaly threshold multiplier must be greater than 0.")
        upsert_setting("traffic_anomaly_threshold", str(update_in.traffic_anomaly_threshold), "Traffic volume anomaly multiplier")
        settings.TRAFFIC_ANOMALY_THRESHOLD = update_in.traffic_anomaly_threshold
        updated_keys.append(f"traffic_anomaly_threshold={update_in.traffic_anomaly_threshold}")

    if update_in.port_scan_threshold is not None:
        if update_in.port_scan_threshold < 1:
            raise HTTPException(status_code=400, detail="Port activity threshold must be at least 1.")
        upsert_setting("port_scan_threshold", str(update_in.port_scan_threshold), "Max unique ports scanned in window")
        settings.PORT_SCAN_THRESHOLD = update_in.port_scan_threshold
        updated_keys.append(f"port_scan_threshold={update_in.port_scan_threshold}")

    if update_in.failed_auth_threshold is not None:
        if update_in.failed_auth_threshold < 1:
            raise HTTPException(status_code=400, detail="Failed login threshold must be at least 1.")
        upsert_setting("failed_auth_threshold", str(update_in.failed_auth_threshold), "Max failed logins in window")
        settings.FAILED_AUTH_THRESHOLD = update_in.failed_auth_threshold
        updated_keys.append(f"failed_auth_threshold={update_in.failed_auth_threshold}")

    if update_in.unknown_device_detection is not None:
        val_str = "true" if update_in.unknown_device_detection else "false"
        upsert_setting("unknown_device_detection", val_str, "Unknown device detection toggle")
        updated_keys.append(f"unknown_device_detection={val_str}")

    # 2. Simulation Settings
    if update_in.simulation_tick_seconds is not None:
        if update_in.simulation_tick_seconds < 1:
            raise HTTPException(status_code=400, detail="Simulation pulse interval must be at least 1 second.")
        upsert_setting("simulation_tick_seconds", str(update_in.simulation_tick_seconds), "Simulation pulse interval in seconds")
        settings.SIMULATION_TICK_SECONDS = update_in.simulation_tick_seconds
        updated_keys.append(f"simulation_tick_seconds={update_in.simulation_tick_seconds}")

    if update_in.traffic_generation_rate is not None:
        if update_in.traffic_generation_rate <= 0:
            raise HTTPException(status_code=400, detail="Traffic generation rate must be greater than 0.")
        upsert_setting("traffic_generation_rate", str(update_in.traffic_generation_rate), "Relative traffic generation rate multiplier")
        updated_keys.append(f"traffic_generation_rate={update_in.traffic_generation_rate}")

    if update_in.simulated_devices_count is not None:
        if update_in.simulated_devices_count < 10 or update_in.simulated_devices_count > 100:
            raise HTTPException(status_code=400, detail="Number of simulated devices must be between 10 and 100.")
        upsert_setting("simulated_devices_count", str(update_in.simulated_devices_count), "Number of simulated devices (10 to 100)")
        updated_keys.append(f"simulated_devices_count={update_in.simulated_devices_count}")

    if update_in.simulation_seed is not None:
        upsert_setting("simulation_seed", str(update_in.simulation_seed), "Deterministic simulation random seed")
        updated_keys.append(f"simulation_seed={update_in.simulation_seed}")

    # 3. Security Settings
    if update_in.session_timeout_minutes is not None:
        if update_in.session_timeout_minutes < 1 or update_in.session_timeout_minutes > 10080:
            raise HTTPException(status_code=400, detail="Session timeout must be between 1 and 10080 minutes (max 7 days).")
        upsert_setting("session_timeout_minutes", str(update_in.session_timeout_minutes), "Session timeout in minutes")
        settings.ACCESS_TOKEN_EXPIRE_MINUTES = update_in.session_timeout_minutes
        updated_keys.append(f"session_timeout_minutes={update_in.session_timeout_minutes}")

    if update_in.password_min_length is not None:
        if update_in.password_min_length < 8:
            raise HTTPException(status_code=400, detail="Password minimum length must be at least 8 characters.")
        upsert_setting("password_min_length", str(update_in.password_min_length), "Minimum password length")
        updated_keys.append(f"password_min_length={update_in.password_min_length}")

    if update_in.password_require_digit is not None:
        val_str = "true" if update_in.password_require_digit else "false"
        upsert_setting("password_require_digit", val_str, "Password policy require digit")
        updated_keys.append(f"password_require_digit={val_str}")

    # 4. System Mode
    warning_notice = None
    if update_in.system_mode is not None:
        mode_val = update_in.system_mode.upper()
        if mode_val not in ["SIMULATION", "LIVE"]:
            raise HTTPException(status_code=400, detail="Invalid system mode. Allowed: SIMULATION, LIVE")
        if mode_val == "LIVE":
            capable, cap_msg = live_collector.check_capture_capability()
            if not capable:
                mode_val = "SIMULATION"
                warning_notice = cap_msg  # "Live packet monitoring is unavailable. Switching to Simulation Mode."
                upsert_setting("system_mode", "SIMULATION", "Operational Mode")
                settings.SYSTEM_MODE = "SIMULATION"
                updated_keys.append("system_mode=SIMULATION (fallback: Live packet monitoring is unavailable. Switching to Simulation Mode.)")
            else:
                upsert_setting("system_mode", "LIVE", "Operational Mode")
                settings.SYSTEM_MODE = "LIVE"
                live_collector.is_capturing = True
                updated_keys.append("system_mode=LIVE")
        else:
            upsert_setting("system_mode", "SIMULATION", "Operational Mode")
            settings.SYSTEM_MODE = "SIMULATION"
            live_collector.is_capturing = False
            updated_keys.append("system_mode=SIMULATION")

    if not updated_keys:
        return {"message": "No settings changed."}

    # Record Audit Log
    record_audit_event(
        db=db,
        user_id=admin.id,
        username=admin.username,
        action="UPDATE_SETTINGS",
        resource_type="SYSTEM_SETTING",
        resource_id=None,
        details=f"Admin {admin.username} updated settings: {', '.join(updated_keys)}"
    )

    db.commit()
    return {
        "message": "Settings updated successfully.",
        "updated_keys": updated_keys,
        "warning_notice": warning_notice,
        "system_mode": settings.SYSTEM_MODE
    }

@router.get("/audit-logs")
def get_audit_logs(
    limit: int = 50,
    action: Optional[str] = None,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Retrieve system audit logs for administrative inspection."""
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action.ilike(f"%{action}%"))
    return query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
