from typing import List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.device import Device
from app.models.user import User
from app.models.simulation import SimulationRun
from app.schemas.simulation import (
    WhatIfRequest, WhatIfResponse,
    IsolationRequest, IsolationResponse,
    ScenarioStepRequest, ScenarioStepResponse
)
from app.digital_twin.twin_engine import digital_twin, sync_state_on_change
from app.detection.rule_engine import RuleDetectionEngine
from app.simulation.scenario_manager import demo_manager
from app.simulation.traffic_generator import traffic_generator
from app.services.auth_service import require_analyst_or_admin, require_admin

router = APIRouter(prefix="/api/simulation", tags=["Simulation & What-If Studio"])

@router.post("/what-if", response_model=WhatIfResponse)
def run_what_if_simulation(
    req: WhatIfRequest,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """
    Execute graph-based What-If attack-path simulation.
    Answers: 'What could happen if this device becomes compromised?'
    Evaluates reachability, critical node proximity, and simulated path risk.
    """
    device = db.query(Device).filter(Device.id == req.target_device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Target device not found")

    if not digital_twin.is_synchronized:
        digital_twin.sync_from_database(db)

    result = digital_twin.simulate_what_if_compromise(
        source_device_name=device.device_name,
        db=db,
        scenario=req.scenario
    )
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return result

@router.post("/isolate", response_model=IsolationResponse)
def execute_simulated_isolation(
    req: IsolationRequest,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """
    Execute simulated isolation of a target device in the Digital Twin graph.
    Demonstrates path severance without impacting physical network operations.
    """
    device = db.query(Device).filter(Device.id == req.target_device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Target device not found")

    result = digital_twin.simulate_isolation(device.device_name, db)
    return result

@router.post("/restore/{device_id}")
def restore_isolated_device(
    device_id: int,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Restore an isolated device back to online operational state."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    return digital_twin.restore_isolation(device.device_name, db)

class TriggerEventRequest(BaseModel):
    event_type: str
    source_ip: str
    target_ip: Optional[str] = None

@router.post("/trigger-event")
def trigger_security_event(
    payload: TriggerEventRequest,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """
    Task 2: Trigger one of 6 simulated security events.
    Strictly accepts a JSON body payload only (query parameters not accepted).
    1 UNKNOWN_DEVICE, 2 PORT_SCAN, 3 TRAFFIC_ANOMALY, 4 FAILED_AUTH, 5 SUSPICIOUS_OUTBOUND, 6 COMPROMISED_HOST.
    """
    ev_type = payload.event_type.upper()
    src_ip = payload.source_ip
    dst_ip = payload.target_ip

    rule_engine = RuleDetectionEngine(db)
    alert = rule_engine.trigger_simulated_security_event(
        event_type=ev_type,
        source_ip=src_ip,
        target_ip=dst_ip
    )
    sync_state_on_change(
        db=db,
        affected_device_ips=[ip for ip in [src_ip, dst_ip] if ip],
        action="SIMULATE_SECURITY_EVENT",
        details=f"Simulated event '{ev_type}' triggered on {src_ip} by {current_user.username}",
        username=current_user.username,
        user_id=current_user.id
    )
    return {
        "status": "SUCCESS",
        "message": f"Simulated security event '{ev_type}' executed.",
        "alert_id": alert.id,
        "severity": alert.severity,
        "occurrence_count": alert.occurrence_count
    }

@router.post("/demo/step", response_model=ScenarioStepResponse)
def execute_demo_step(
    step_in: ScenarioStepRequest,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Execute or navigate to a specific step in the 12-step guided demo scenario."""
    if step_in.step_number < 1 or step_in.step_number > 12:
        raise HTTPException(status_code=400, detail="Step number must be between 1 and 12")

    result = demo_manager.execute_step(step_in.step_number, db, user=current_user)
    return {
        "step_number": result["step_number"],
        "title": result["title"],
        "description": result["description"],
        "narration": result.get("narration"),
        "target_page": result.get("target_page", "dashboard"),
        "action": result.get("action"),
        "affected_device": result["affected_device"],
        "event_generated": f"Step {step_in.step_number} event",
        "alert_created": step_in.step_number in [4, 5, 6, 7],
        "digital_twin_state": result["digital_twin_state"],
        "next_step": result["next_step"]
    }

@router.post("/demo/reset")
def reset_demo_scenario(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Reset the demonstration network, traffic, alerts, and topology back to baseline.
    Requires Administrator privileges (Analyst receives 403 Forbidden).
    """
    return demo_manager.reset_demo(db, admin_user=current_user)

@router.get("/runs")
@router.get("/history")
def list_simulation_runs(db: Session = Depends(get_db)):
    """Retrieve history of What-If simulation runs and attack path findings."""
    runs = db.query(SimulationRun).order_by(SimulationRun.created_at.desc()).limit(20).all()
    return [
        {
            "id": r.id,
            "simulation_type": r.simulation_type,
            "target_device": r.target_device,
            "result": r.result,
            "risk_level": r.risk_level,
            "path_risk_score": r.path_risk_score,
            "critical_assets_reached": r.critical_assets_reached,
            "label": "HYPOTHETICAL",
            "created_at": r.created_at.isoformat() if r.created_at else None
        }
        for r in runs
    ]

@router.get("/traffic/control")
def get_simulation_traffic_control():
    """Retrieve current simulation traffic control state (pause/running)."""
    return {
        "status": "PAUSED" if traffic_generator.is_paused else "RUNNING",
        "is_paused": traffic_generator.is_paused,
        "tick_counter": traffic_generator.tick_counter,
        "current_seed": traffic_generator.current_seed
    }

@router.post("/traffic/pause")
def pause_simulation_traffic(current_user: User = Depends(require_analyst_or_admin)):
    """Pause synthetic traffic generation."""
    traffic_generator.pause()
    return {
        "status": "PAUSED",
        "is_paused": True,
        "message": "Simulation traffic paused."
    }

@router.post("/traffic/resume")
def resume_simulation_traffic(current_user: User = Depends(require_analyst_or_admin)):
    """Resume synthetic traffic generation."""
    traffic_generator.resume()
    return {
        "status": "RUNNING",
        "is_paused": False,
        "message": "Simulation traffic resumed."
    }

@router.post("/traffic/step")
def step_simulation_traffic(
    count: Optional[int] = None,
    scenario: str = "NORMAL",
    seed: Optional[int] = None,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Execute single simulation step (tick) even when paused."""
    recs = traffic_generator.step(db, count=count, scenario=scenario, seed=seed)
    return {
        "status": "SUCCESS",
        "records_generated": len(recs),
        "tick_counter": traffic_generator.tick_counter
    }
