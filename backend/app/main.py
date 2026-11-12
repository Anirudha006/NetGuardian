import logging
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("netguardian.core")

from app.config import settings
from app.database import engine, Base, SessionLocal
from app.utils.seed_data import seed_database
from app.digital_twin.twin_engine import digital_twin

# Import all routers
from app.routes.auth import router as auth_router
from app.routes.dashboard import router as dashboard_router
from app.routes.devices import router as devices_router
from app.routes.traffic import router as traffic_router
from app.routes.alerts import router as alerts_router
from app.routes.digital_twin import router as digital_twin_router
from app.routes.simulation import router as simulation_router
from app.routes.analytics import router as analytics_router
from app.routes.reports import router as reports_router
from app.routes.settings import router as settings_router
from app.routes.collector import router as collector_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Production startup safeguard: refuse startup if demo passwords or default keys are present
    if settings.ENVIRONMENT.lower() == "production":
        insecure_keys = [
            "netguardian-super-secure-jwt-secret-key-change-in-production-2026",
            "secret",
            "changeme",
            "default",
            "secretkey",
        ]
        insecure_passwords = ["admin123", "analyst123", "admin", "analyst", "password", "default", ""]
        if settings.SECRET_KEY in insecure_keys or len(settings.SECRET_KEY) < 32:
            raise RuntimeError(
                "Production mode startup refused: Insecure or default SECRET_KEY in use. "
                "Set a high-entropy SECRET_KEY via environment variable before running in production."
            )
        if settings.DEMO_ADMIN_PASSWORD.lower() in insecure_passwords or settings.DEMO_ANALYST_PASSWORD.lower() in insecure_passwords:
            raise RuntimeError(
                "Production mode startup refused: Insecure or default demo credentials in use. "
                "Change DEMO_ADMIN_PASSWORD and DEMO_ANALYST_PASSWORD via environment variables before running in production."
            )

    logger.info("Initializing NetGuardian Security Engine & Database...")
    # 1. Initialize DB schema and run backwards-compatible column migrations
    Base.metadata.create_all(bind=engine)
    from sqlalchemy import text
    with engine.connect() as conn:
        for mig_sql in [
            "ALTER TABLE devices ADD COLUMN trust_level VARCHAR(20) DEFAULT 'MEDIUM'",
            "ALTER TABLE security_events ADD COLUMN occurrence_count INTEGER DEFAULT 1",
            "ALTER TABLE security_events ADD COLUMN last_seen DATETIME",
            "ALTER TABLE alerts ADD COLUMN occurrence_count INTEGER DEFAULT 1",
            "ALTER TABLE alerts ADD COLUMN last_seen DATETIME",
            "ALTER TABLE alerts ADD COLUMN event_type VARCHAR(100)",
            "ALTER TABLE alerts ADD COLUMN detection_method VARCHAR(30) DEFAULT 'RULE'",
            "ALTER TABLE alerts ADD COLUMN detected_by VARCHAR(30) DEFAULT 'rule'",
            "ALTER TABLE traffic_records ADD COLUMN data_source VARCHAR(20) DEFAULT 'SIMULATED'",
            "ALTER TABLE devices ADD COLUMN device_source VARCHAR(20) DEFAULT 'SIMULATED'",
            "ALTER TABLE devices ADD COLUMN is_registered BOOLEAN DEFAULT 1",
            "CREATE INDEX IF NOT EXISTS idx_tr_timestamp ON traffic_records (timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_tr_data_source ON traffic_records (data_source)",
            "CREATE INDEX IF NOT EXISTS idx_tr_protocol ON traffic_records (protocol)",
            "CREATE INDEX IF NOT EXISTS idx_tr_source_ip ON traffic_records (source_ip)",
            "CREATE INDEX IF NOT EXISTS idx_tr_ds_ts ON traffic_records (data_source, timestamp)",
            """
            CREATE TRIGGER IF NOT EXISTS audit_logs_prevent_update
            BEFORE UPDATE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'audit_logs entries are immutable: UPDATE not permitted');
            END;
            """,
            """
            CREATE TRIGGER IF NOT EXISTS audit_logs_prevent_delete
            BEFORE DELETE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'audit_logs entries are immutable: DELETE not permitted');
            END;
            """
        ]:
            try:
                conn.execute(text(mig_sql))
                conn.commit()
            except Exception:
                pass  # column already exists

    # 2. Seed default users, devices, settings
    db = SessionLocal()
    try:
        seed_database(db)
        # 3. Synchronize Digital Twin Graph
        digital_twin.sync_from_database(db)
        logger.info("Database and Digital Twin synchronization complete.")
    except Exception as e:
        logger.error(f"Error during startup synchronization: {e}", exc_info=True)
    finally:
        db.close()

    yield
    logger.info("NetGuardian Engine shutting down gracefully.")

app = FastAPI(
    title="NetGuardian: AI-Powered Digital Twin for Network Security",
    description=(
        "Production-grade defensive cybersecurity prototype combining real-time/simulated network monitoring, "
        "rule-based security detection, Machine Learning anomaly scoring (Isolation Forest), "
        "graph-based Digital Twin modeling (NetworkX), and safe 'What-If' attack-path simulation."
    ),
    version=settings.VERSION,
    lifespan=lifespan
)

# Configure CORS (tightened to specific methods and headers)
origins = [origin.strip() for origin in settings.CORS_ORIGINS.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token", "Accept"],
)

# Enforce HTTP Security Headers across all responses
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# Global Friendly Error Handlers (never leak raw stack traces)
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.warning(f"HTTP {exc.status_code} on {request.method} {request.url.path}: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "status_code": exc.status_code},
        headers=exc.headers
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Internal server error on {request.method} {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal server error occurred. Please contact the system administrator.",
            "status_code": 500
        }
    )

# Register API Routers
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(devices_router)
app.include_router(traffic_router)
app.include_router(alerts_router)
app.include_router(digital_twin_router)
app.include_router(simulation_router)
app.include_router(analytics_router)
app.include_router(reports_router)
app.include_router(settings_router)
app.include_router(collector_router)

@app.get("/")
def root():
    return {
        "project": "NetGuardian",
        "tagline": "See your network. Understand the risk. Simulate the threat. Protect the system.",
        "version": settings.VERSION,
        "status": "ONLINE",
        "system_mode": settings.SYSTEM_MODE,
        "docs_url": "/docs",
        "redoc_url": "/redoc"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
