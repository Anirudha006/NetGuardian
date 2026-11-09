from pydantic import BaseModel, ConfigDict
from typing import List, Dict, Any, Optional
from datetime import datetime

class WhatIfRequest(BaseModel):
    target_device_id: int
    scenario: str = "COMPROMISED_HOST"  # COMPROMISED_HOST, INSIDER_THREAT, LATERAL_MOVEMENT

class AttackPathSchema(BaseModel):
    model_config = ConfigDict(extra="allow")
    source_node: str
    destination_node: str
    path: List[str]
    hop_count: int
    risk: float
    simulated_risk_level: Optional[str] = "MEDIUM"
    target_criticality: Optional[str] = "MEDIUM"
    target_criticality_val: Optional[float] = 45.0
    hop_factor: Optional[float] = 60.0
    average_trust: Optional[float] = 80.0
    score_breakdown: Optional[Dict[str, float]] = None
    breakdown: Optional[Dict[str, Any]] = None
    contains_critical_asset: bool = False

class WhatIfResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    simulation_id: int
    target_device: str
    source_device: Optional[str] = None
    target_ip: str
    scenario: str
    scenario_text: Optional[str] = None
    potential_reach_path: Optional[List[str]] = None
    path_display: Optional[str] = None
    reachable_systems: Optional[List[str]] = None
    reachable_nodes: List[str]
    reachable_nodes_count: int
    reachable_count: Optional[int] = None
    hop_count: int
    path_length: Optional[int] = None
    critical_asset_reached: Optional[str] = "NO"
    is_critical_asset_reached: Optional[bool] = False
    critical_assets_at_risk: List[str]
    attack_paths: List[AttackPathSchema]
    attack_path: Optional[List[Any]] = None
    path_risk_score: float
    max_path_risk: float
    simulated_risk_score: Optional[float] = None
    simulated_risk_level: str
    recommended_controls: Optional[List[str]] = None
    recommendations: List[str]
    score_breakdown: Optional[Dict[str, float]] = None
    breakdown: Optional[Dict[str, Any]] = None
    is_hypothetical: Optional[bool] = True
    label: Optional[str] = "HYPOTHETICAL"
    execution_time_ms: float

class IsolationRequest(BaseModel):
    target_device_id: int
    reason: Optional[str] = "Manual isolation triggered from What-If simulation"

class IsolationResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    target_device_id: int
    device_name: str
    ip_address: str
    is_isolated: bool
    status: str
    edges_severed: int
    reachability_before: int
    reachability_after: int
    simulated_risk_before: Optional[float] = 0.0
    simulated_risk_after: Optional[float] = 0.0
    risk_reduction_percentage: float
    health_score_after: Optional[float] = None
    message: str
    before_after_comparison: Optional[Dict[str, Any]] = None

class ScenarioStepRequest(BaseModel):
    step_number: int

class ScenarioStepResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    step_number: int
    title: str
    description: str
    narration: Optional[str] = None
    target_page: Optional[str] = "dashboard"
    action: Optional[str] = None
    affected_device: Optional[str] = None
    event_generated: Optional[str] = None
    alert_created: bool
    digital_twin_state: str
    next_step: Optional[int] = None
