from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.digital_twin.twin_engine import digital_twin
from app.services.auth_service import require_analyst_or_admin

router = APIRouter(prefix="/api/digital-twin", tags=["Digital Twin"])

@router.get("/topology")
def get_digital_twin_topology(db: Session = Depends(get_db)):
    """Retrieve full in-memory Digital Twin network graph state."""
    if not digital_twin.is_synchronized:
        digital_twin.sync_from_database(db)
    return digital_twin.get_topology(db)

@router.post("/sync")
def trigger_digital_twin_sync(
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Trigger explicit re-synchronization of Digital Twin with database (Task 3 & 6)."""
    digital_twin.sync_from_database(db)
    return {
        "status": "SUCCESS",
        "message": "Digital Twin graph synchronized with database state.",
        "nodes_count": len(digital_twin.graph.nodes),
        "edges_count": len(digital_twin.graph.edges),
        "state": digital_twin.check_sync_status(db)
    }
