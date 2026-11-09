from sqlalchemy import Column, Integer, String, Float, DateTime
from app.database import Base
from app.utils.time_utils import utcnow

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(100), nullable=False, index=True)  # PORT_SCAN, TRAFFIC_ANOMALY, UNKNOWN_DEVICE, BRUTE_FORCE, SUSPICIOUS_OUTBOUND, COMPROMISED_HOST
    severity = Column(String(20), default="MEDIUM")               # INFO, LOW, MEDIUM, HIGH, CRITICAL
    source_device = Column(String(100), nullable=False)           # IP or Device Name
    destination_device = Column(String(100), nullable=True)       # IP or Device Name
    description = Column(String(500), nullable=False)
    confidence = Column(Float, default=0.85)                      # 0.0 - 1.0
    status = Column(String(30), default="NEW")                    # NEW, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
    detection_method = Column(String(30), default="RULE")         # RULE, ML, HYBRID
    occurrence_count = Column(Integer, default=1)
    last_seen = Column(DateTime, default=utcnow)
    created_at = Column(DateTime, default=utcnow, index=True)
