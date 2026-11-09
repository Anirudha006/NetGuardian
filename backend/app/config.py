import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "NetGuardian"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DATABASE_URL: str = "sqlite:///./netguardian.db"
    SECRET_KEY: str = "netguardian-super-secure-jwt-secret-key-change-in-production-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000,http://localhost:5175,http://127.0.0.1:5175"

    # Security & Network Settings
    TRUSTED_PROXIES: str = ""               # Comma-separated list of trusted proxy IPs (empty by default)
    MAX_TRAFFIC_RECORDS: int = 50000        # Maximum historical traffic records to retain

    # Detection Engine Thresholds
    TRAFFIC_ANOMALY_THRESHOLD: float = 3.0  # multiplier over baseline
    PORT_SCAN_THRESHOLD: int = 15           # unique ports in 60s
    FAILED_AUTH_THRESHOLD: int = 5          # failed logins in 30s
    SIMULATION_TICK_SECONDS: int = 2

    # Demo User Credentials (DEMO ONLY)
    DEMO_ADMIN_PASSWORD: str = "admin123"
    DEMO_ANALYST_PASSWORD: str = "analyst123"

    # Mode: "SIMULATION" or "LIVE"
    SYSTEM_MODE: str = "SIMULATION"

    model_config = {"env_file": ".env", "extra": "allow"}

settings = Settings()
