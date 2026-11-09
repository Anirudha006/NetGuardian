from sqlalchemy import Column, Integer, String, BigInteger, DateTime, Float
from app.database import Base
from app.utils.time_utils import utcnow

class TrafficRecord(Base):
    __tablename__ = "traffic_records"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False, index=True)
    protocol = Column(String(20), default="TCP")
    source_port = Column(Integer, default=0)
    destination_port = Column(Integer, default=80)
    packet_count = Column(Integer, default=1)
    bytes = Column(BigInteger, default=0)
    duration = Column(Float, default=0.1)
    is_anomalous = Column(Integer, default=0)  # 0: normal, 1: anomalous
    data_source = Column(String(20), default="SIMULATED", index=True)  # SIMULATED, OBSERVED
