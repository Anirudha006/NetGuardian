from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean
from app.database import Base
from app.utils.time_utils import utcnow

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    device_name = Column(String(100), unique=True, index=True, nullable=False)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    mac_address = Column(String(50), unique=True, nullable=False)
    device_type = Column(String(50), default="Workstation")  # Router, Switch, Server, Database, Workstation, Laptop, IoT, Mobile
    os_type = Column(String(50), default="Linux")           # Linux, Windows, macOS, Embedded, NetworkOS
    status = Column(String(20), default="ONLINE")           # ONLINE, OFFLINE, SUSPICIOUS, COMPROMISED, ISOLATED
    criticality = Column(String(20), default="MEDIUM")      # LOW, MEDIUM, HIGH, CRITICAL
    trust_level = Column(String(20), default="MEDIUM")      # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, default=0.0)                 # 0 - 100
    trust_score = Column(Float, default=100.0)              # 0 - 100
    is_isolated = Column(Boolean, default=False)
    device_source = Column(String(20), default="SIMULATED")  # SIMULATED, OBSERVED
    is_registered = Column(Boolean, default=True)           # True: known inventory, False: unknown/observed
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
