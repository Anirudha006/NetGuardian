from sqlalchemy import Column, Integer, String, BigInteger, DateTime, ForeignKey
from app.database import Base
from app.utils.time_utils import utcnow

class NetworkConnection(Base):
    __tablename__ = "network_connections"

    id = Column(Integer, primary_key=True, index=True)
    source_device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    destination_device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    protocol = Column(String(20), default="TCP")
    source_port = Column(Integer, default=0)
    destination_port = Column(Integer, default=80)
    packet_count = Column(Integer, default=1)
    bytes_transferred = Column(BigInteger, default=0)
    timestamp = Column(DateTime, default=utcnow)
