from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, JSON
from app.database import Base
from app.utils.time_utils import utcnow

class SimulationRun(Base):
    __tablename__ = "simulation_runs"

    id = Column(Integer, primary_key=True, index=True)
    simulation_type = Column(String(50), nullable=False)          # WHAT_IF_COMPROMISE, ISOLATION_TEST, SCENARIO_WALKTHROUGH
    target_device = Column(String(100), nullable=False)
    result = Column(Text, nullable=False)
    risk_level = Column(String(20), default="MEDIUM")             # LOW, MEDIUM, HIGH, CRITICAL
    path_risk_score = Column(Float, default=0.0)                  # 0 - 100
    critical_assets_reached = Column(Integer, default=0)
    created_at = Column(DateTime, default=utcnow)

class AttackPath(Base):
    __tablename__ = "attack_paths"

    id = Column(Integer, primary_key=True, index=True)
    simulation_id = Column(Integer, ForeignKey("simulation_runs.id", ondelete="CASCADE"), nullable=False)
    source_node = Column(String(100), nullable=False)
    destination_node = Column(String(100), nullable=False)
    path = Column(JSON, nullable=False)                           # e.g. ["Rogue Laptop", "Switch-01", "App Server", "Crown Jewel DB"]
    hop_count = Column(Integer, default=1)
    risk = Column(Float, default=50.0)                            # 0 - 100
