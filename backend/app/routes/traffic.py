from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, case

from app.database import get_db
from app.models.traffic import TrafficRecord
from app.models.connection import NetworkConnection
from app.models.user import User
from app.schemas.traffic import TrafficRecordResponse, TrafficStatsResponse
from app.simulation.traffic_generator import traffic_generator
from app.services.auth_service import require_analyst_or_admin

router = APIRouter(prefix="/api/traffic", tags=["Traffic Monitoring"])

@router.get("", response_model=List[TrafficRecordResponse])
def get_traffic_records(
    limit: int = Query(50, ge=1, le=500),
    anomalies_only: bool = False,
    data_source: Optional[str] = Query(None, description="Filter by SIMULATED or OBSERVED"),
    db: Session = Depends(get_db)
):
    """Retrieve recent traffic stream records."""
    query = db.query(TrafficRecord)
    if anomalies_only:
        query = query.filter(TrafficRecord.is_anomalous == 1)
    if data_source:
        query = query.filter(TrafficRecord.data_source == data_source.upper())
    return query.order_by(TrafficRecord.timestamp.desc()).limit(limit).all()

@router.get("/control")
def get_traffic_control():
    """Retrieve current simulation traffic control state (pause/running)."""
    return {
        "status": "PAUSED" if traffic_generator.is_paused else "RUNNING",
        "is_paused": traffic_generator.is_paused,
        "tick_counter": traffic_generator.tick_counter,
        "current_seed": traffic_generator.current_seed
    }

@router.post("/pause")
def pause_traffic(current_user: User = Depends(require_analyst_or_admin)):
    """Pause synthetic traffic generation."""
    traffic_generator.pause()
    return {
        "status": "PAUSED",
        "is_paused": True,
        "message": "Traffic generation paused."
    }

@router.post("/resume")
def resume_traffic(current_user: User = Depends(require_analyst_or_admin)):
    """Resume synthetic traffic generation."""
    traffic_generator.resume()
    return {
        "status": "RUNNING",
        "is_paused": False,
        "message": "Traffic generation resumed."
    }

@router.post("/step", response_model=List[TrafficRecordResponse])
def step_traffic(
    count: Optional[int] = None,
    scenario: str = Query("NORMAL"),
    seed: Optional[int] = Query(None),
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Execute exactly one simulation step (tick) even when paused."""
    return traffic_generator.step(db, count=count, scenario=scenario, seed=seed)

@router.post("/pulse", response_model=List[TrafficRecordResponse])
def trigger_traffic_pulse(
    count: Optional[int] = None,
    scenario: str = Query("NORMAL", description="Traffic scenario: NORMAL, LIGHT, BUSY, SUSPICIOUS_ACTIVITY, SECURITY_INCIDENT"),
    seed: Optional[int] = Query(None, description="Deterministic integer seed for repeatable traffic simulation"),
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Generate a batch of synthetic traffic flows across active network nodes with seed and scenario options."""
    return traffic_generator.generate_tick(db, count=count, scenario=scenario, seed=seed)

@router.get("/baseline")
def get_traffic_baseline():
    """Retrieve learned baseline traffic profiles per device."""
    return traffic_generator.get_baseline_summary()

@router.post("/baseline/learn")
def learn_traffic_baseline(
    warm_up_ticks: int = Query(5, ge=1, le=50),
    seed: Optional[int] = Query(42),
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Execute warm-up ticks of normal traffic to compute per-device baselines (bytes, connections, peers)."""
    return traffic_generator.learn_baseline(db, warm_up_ticks=warm_up_ticks, seed=seed)

@router.get("/stats", response_model=TrafficStatsResponse)
def get_traffic_stats(db: Session = Depends(get_db)):
    """Aggregate traffic volume, packet totals, and protocol distribution."""
    # Single-pass aggregated scan over traffic records for high performance with 50,000+ rows
    agg_row = db.query(
        func.sum(TrafficRecord.packet_count),
        func.sum(TrafficRecord.bytes),
        func.sum(case((TrafficRecord.is_anomalous == 1, 1), else_=0))
    ).first()

    total_pkts = agg_row[0] or 0
    total_bytes = agg_row[1] or 0
    anom_count = agg_row[2] or 0
    conns = db.query(NetworkConnection).count()

    # Protocol breakdown
    proto_rows = db.query(TrafficRecord.protocol, func.count(TrafficRecord.id))\
        .group_by(TrafficRecord.protocol).all()
    proto_dist = {r[0]: r[1] for r in proto_rows}

    return {
        "total_packets": int(total_pkts),
        "total_bytes": int(total_bytes),
        "active_connections": conns,
        "anomalous_records": int(anom_count),
        "protocol_distribution": proto_dist
    }
