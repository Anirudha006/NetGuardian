from sqlalchemy import Column, Integer, String, DateTime, Text
from app.database import Base
from app.utils.time_utils import utcnow

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    username = Column(String(50), nullable=True)
    action = Column(String(100), nullable=False)                  # LOGIN, LOGOUT, SIMULATION_TRIGGER, DEVICE_ISOLATE, ALERT_UPDATE, CONFIG_CHANGE
    ip_address = Column(String(45), default="127.0.0.1")
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=utcnow, index=True)

class SystemSetting(Base):
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, index=True, nullable=False)
    value = Column(String(255), nullable=False)
    description = Column(String(255), nullable=True)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
