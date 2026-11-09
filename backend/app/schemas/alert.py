from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class AlertUpdate(BaseModel):
    status: str  # NEW, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE

class AlertResponse(BaseModel):
    id: int
    event_id: Optional[int] = None
    event_type: Optional[str] = None
    title: str
    severity: str
    message: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    rule_name: Optional[str] = None
    detection_method: Optional[str] = "RULE"
    detected_by: Optional[str] = "rule"
    ai_score: Optional[float] = None
    ai_confidence: Optional[str] = None
    ai_explanation: Optional[str] = None
    recommendation: str
    status: str
    occurrence_count: Optional[int] = 1
    last_seen: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}

class SecurityEventResponse(BaseModel):
    id: int
    event_type: str
    severity: str
    source_device: str
    destination_device: Optional[str] = None
    description: str
    confidence: float
    status: str
    detection_method: str
    occurrence_count: Optional[int] = 1
    last_seen: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}
