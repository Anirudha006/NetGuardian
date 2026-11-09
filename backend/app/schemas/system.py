from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any

class ComponentStatus(BaseModel):
    name: str
    status: str
    ok: bool
    reason: Optional[str] = None

class SystemStatusResponse(BaseModel):
    backend: str = "ONLINE"
    database: str = "ONLINE"
    ai_engine: str = "READY"
    digital_twin: str = "SYNCHRONIZED"
    network_collector: str = "SIMULATION_ACTIVE"
    system_mode: str = "SIMULATION"
    active_devices: int
    active_threats: int
    total_packets_processed: int
    simulated_ticks: int
    components: Optional[Dict[str, ComponentStatus]] = None

class HealthScoreResponse(BaseModel):
    health_score: float
    health_status: str  # HEALTHY, ELEVATED_RISK, COMPROMISED
    threat_deductions: float
    device_risk_deductions: float
    anomaly_deductions: float
    formula_explanation: str

class SettingsUpdate(BaseModel):
    # Detection
    traffic_anomaly_threshold: Optional[float] = None
    port_scan_threshold: Optional[int] = None
    failed_auth_threshold: Optional[int] = None
    unknown_device_detection: Optional[bool] = None

    # Simulation
    simulation_tick_seconds: Optional[int] = None
    traffic_generation_rate: Optional[float] = None
    simulated_devices_count: Optional[int] = None
    simulation_seed: Optional[int] = None

    # Security
    session_timeout_minutes: Optional[int] = None
    password_min_length: Optional[int] = None
    password_require_digit: Optional[bool] = None

    # System Mode
    system_mode: Optional[str] = None
