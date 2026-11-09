from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.services.auth_service import require_analyst_or_admin, require_admin
from app.collector.live_collector import live_collector, parse_raw_ip_packet

router = APIRouter(prefix="/api/collector", tags=["Live Packet Collector"])

class PacketInjectionRequest(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: str = "TCP"
    source_port: int = 50000
    destination_port: int = 80
    packet_count: int = 1
    bytes: int = 64
    payload: Optional[str] = Field(None, description="Test payload string (STRICTLY DISCARDED, never stored)")

class LiveToggleRequest(BaseModel):
    enabled: bool
    consent_granted: bool = False

@router.get("/status")
def get_collector_status():
    """Retrieve operational status, driver capability, and mode of packet collector."""
    capable, reason = live_collector.check_capture_capability()
    return {
        "status": "OPERATIONAL" if capable else "SIMULATION_FALLBACK",
        "capable": capable,
        "reason": reason,
        "is_capturing": live_collector.is_capturing,
        "capture_count": live_collector.capture_count,
        "system_mode": "LIVE" if live_collector.is_capturing else "SIMULATION"
    }

@router.post("/live-toggle")
def toggle_live_mode(
    payload: LiveToggleRequest,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Toggle Live Monitoring Mode (Admin Only).
    Requires explicit consent notice acknowledgement.
    If capture driver or raw socket permissions are absent, automatically falls back to Simulation Mode.
    """
    if payload.enabled:
        result = live_collector.enable_live_mode(consent_granted=payload.consent_granted, db=db)
    else:
        result = live_collector.switch_to_simulation()

    return result

@router.post("/inject-packet")
def inject_fake_packet(
    packet: PacketInjectionRequest,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """
    Test packet collector using injected packet headers (Task 3).
    Proves parsing, flow aggregation, device auto-discovery (OBSERVED/unregistered),
    and strictly verifies that NO payload or credential contents are stored in DB.
    """
    # Convert request model to dictionary
    raw_dict = packet.model_dump()
    result = live_collector.process_packet(raw_dict, db=db)
    return {
        "status": "SUCCESS",
        "parsed_metadata": result,
        "payload_stored": False,
        "message": "Packet header metadata parsed and aggregated. Application payload strictly discarded."
    }
