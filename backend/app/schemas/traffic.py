from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class TrafficRecordCreate(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: str = "TCP"
    source_port: int = 0
    destination_port: int = 80
    packet_count: int = 1
    bytes: int = 0
    duration: float = 0.1

class TrafficRecordResponse(BaseModel):
    id: int
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int
    destination_port: int
    packet_count: int
    bytes: int
    duration: float
    is_anomalous: int
    data_source: Optional[str] = "SIMULATED"

    model_config = {"from_attributes": True}

class TrafficStatsResponse(BaseModel):
    total_packets: int
    total_bytes: int
    active_connections: int
    anomalous_records: int
    protocol_distribution: dict
