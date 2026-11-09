from typing import Dict, List, Any
import numpy as np

# Phase 4 Task 2 Standardized 8 Feature Names
FEATURE_NAMES: List[str] = [
    "packet_count",
    "bytes",
    "connection_count",
    "connection_duration",
    "unique_destination_ports",
    "unique_destination_ips",
    "failed_connections",
    "traffic_rate"
]

def extract_features(traffic_dict: Dict[str, Any]) -> np.ndarray:
    """
    Extract standardized 8-dimensional numerical feature vector from raw traffic/connection record.
    Gracefully resolves aliases for connection duration, destination ports, and destination IPs.
    """
    packet_count = float(traffic_dict.get("packet_count", 1))
    bytes_count = float(traffic_dict.get("bytes", 0))
    connection_count = float(traffic_dict.get("connection_count", 1))

    # Duration with alias fallback
    duration = float(traffic_dict.get("connection_duration", traffic_dict.get("duration", 0.1)))
    duration = max(0.001, duration)

    # Unique ports with alias fallback
    unique_dst_ports = float(traffic_dict.get("unique_destination_ports", traffic_dict.get("unique_dst_ports", 1)))

    # Unique IPs with alias fallback
    unique_dst_ips = float(traffic_dict.get("unique_destination_ips", traffic_dict.get("unique_dst_ips", 1)))

    # Failed connections
    failed_connections = float(traffic_dict.get("failed_connections", 0))

    # Traffic rate (computed if not provided)
    if "traffic_rate" in traffic_dict and traffic_dict["traffic_rate"] is not None:
        traffic_rate = float(traffic_dict["traffic_rate"])
    else:
        traffic_rate = bytes_count / duration

    return np.array([
        packet_count,
        bytes_count,
        connection_count,
        duration,
        unique_dst_ports,
        unique_dst_ips,
        failed_connections,
        traffic_rate
    ], dtype=np.float32)

def get_feature_dict(vector: np.ndarray) -> Dict[str, float]:
    """Convert a numpy feature vector into a labeled dictionary keyed by FEATURE_NAMES."""
    return {name: float(vector[i]) for i, name in enumerate(FEATURE_NAMES)}
