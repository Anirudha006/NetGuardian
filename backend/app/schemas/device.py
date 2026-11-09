from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime

class DeviceCreate(BaseModel):
    device_name: str
    ip_address: str
    mac_address: str
    device_type: str = "Workstation"
    os_type: str = "Linux"
    criticality: str = "MEDIUM"
    trust_level: str = "MEDIUM"
    status: str = "ONLINE"
    trust_score: float = 100.0

class DeviceUpdate(BaseModel):
    device_name: Optional[str] = None
    criticality: Optional[str] = None
    trust_level: Optional[str] = None
    status: Optional[str] = None
    trust_score: Optional[float] = None
    is_isolated: Optional[bool] = None

class RiskFactor(BaseModel):
    name: str
    impact: float
    description: str

class RiskBreakdownResponse(BaseModel):
    device_id: int
    device_name: str
    risk_score: float
    trust_score: float
    status: str
    factors: List[RiskFactor]
    formula: str

class DeviceResponse(BaseModel):
    id: int
    device_name: str
    ip_address: str
    mac_address: str
    device_type: str
    os_type: str
    status: str
    criticality: str
    trust_level: Optional[str] = "MEDIUM"
    risk_score: float
    trust_score: float
    is_isolated: bool
    device_source: Optional[str] = "SIMULATED"
    is_registered: Optional[bool] = True
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}
