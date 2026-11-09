from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from app.database import Base
from app.utils.time_utils import utcnow

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("security_events.id", ondelete="SET NULL"), nullable=True)
    event_type = Column(String(100), nullable=True)
    title = Column(String(200), nullable=False)
    severity = Column(String(20), default="MEDIUM")               # INFO, LOW, MEDIUM, HIGH, CRITICAL
    message = Column(Text, nullable=False)
    source_ip = Column(String(45), nullable=True)
    destination_ip = Column(String(45), nullable=True)
    rule_name = Column(String(100), nullable=True)
    detection_method = Column(String(30), default="RULE")         # RULE, AI, RULE+AI
    detected_by = Column(String(30), default="rule")              # rule, ai, rule+ai
    ai_score = Column(Float, nullable=True)                       # e.g. 0.87
    ai_confidence = Column(String(20), nullable=True)             # High, Medium, Low
    ai_explanation = Column(Text, nullable=True)                  # Detailed bullets / explanation (JSON or text)
    recommendation = Column(Text, nullable=False)
    status = Column(String(30), default="NEW")                    # NEW, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
    occurrence_count = Column(Integer, default=1)
    last_seen = Column(DateTime, default=utcnow)
    created_at = Column(DateTime, default=utcnow, index=True)

class UserNotificationRead(Base):
    """Tracks read status of security alerts per user on the server (Task 6)."""
    __tablename__ = "user_notifications_read"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    read_at = Column(DateTime, default=utcnow)
