from sqlalchemy import Column, Integer, String, BigInteger, DateTime, Float, Index
from app.database import Base
from app.utils.time_utils import utcnow

class TrafficRecord(Base):
    __tablename__ = "traffic_records"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False, index=True)
    protocol = Column(String(20), default="TCP", index=True)
    source_port = Column(Integer, default=0)
    destination_port = Column(Integer, default=80)
    packet_count = Column(Integer, default=1)
    bytes = Column(BigInteger, default=0)
    duration = Column(Float, default=0.1)
    is_anomalous = Column(Integer, default=0)  # 0: normal, 1: anomalous
    data_source = Column(String(20), default="SIMULATED", index=True)  # SIMULATED, OBSERVED

    __table_args__ = (
        Index("idx_tr_data_source_ts", "data_source", "timestamp"),
        Index("idx_tr_src_bytes", "source_ip", "bytes"),
        Index("idx_tr_ts_agg", "timestamp", "packet_count", "bytes", "is_anomalous"),
        Index("idx_tr_proto_agg", "protocol", "bytes", "packet_count"),
        Index("idx_tr_src_agg", "source_ip", "bytes", "packet_count"),
    )
