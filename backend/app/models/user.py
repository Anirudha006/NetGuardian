from sqlalchemy import Column, Integer, String, DateTime
from app.database import Base
from app.utils.time_utils import utcnow

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="ANALYST", nullable=False)  # ADMIN or ANALYST
    created_at = Column(DateTime, default=utcnow)
    last_login = Column(DateTime, nullable=True)
