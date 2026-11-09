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

__all__ = [
    "auth_router",
    "dashboard_router",
    "devices_router",
    "traffic_router",
    "alerts_router",
    "digital_twin_router",
    "simulation_router",
    "analytics_router",
    "reports_router",
    "settings_router"
]
