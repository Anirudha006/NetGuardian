import logging
from typing import List, Optional, Any, Union
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc

from app.database import get_db
from app.models.alert import Alert, UserNotificationRead
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.schemas.alert import AlertResponse, AlertUpdate, SecurityEventResponse
from app.services.auth_service import get_current_user
from app.services.audit_service import log_audit_event
from app.digital_twin.twin_engine import sync_state_on_change

logger = logging.getLogger("netguardian.alerts")

router = APIRouter(prefix="/api/alerts", tags=["Threats & Alerts"])

VALID_STATUSES = {
    "NEW": "NEW",
    "INVESTIGATING": "INVESTIGATING",
    "CONTAINED": "CONTAINED",
    "RESOLVED": "RESOLVED",
    "FALSE_POSITIVE": "FALSE_POSITIVE",
    "FALSE POSITIVE": "FALSE_POSITIVE",
    "FALSEPOSITIVE": "FALSE_POSITIVE",
}

class AlertListResponse(BaseModel):
    items: List[AlertResponse]
    total: int
    skip: int
    limit: int

@router.get("", response_model=Union[AlertListResponse, List[AlertResponse]])
def get_alerts(
    response: Response,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    event_type: Optional[str] = None,
    search: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    paged: bool = Query(False),
    db: Session = Depends(get_db)
) -> Any:
    """
    Retrieve security alerts with filtering by severity, status, event_type, date, and search.
    Supports pagination and returns total counts in headers or paged wrapper.
    """
    query = db.query(Alert)

    # 1. Severity filter
    if severity and severity.strip():
        query = query.filter(Alert.severity == severity.strip().upper())

    # 2. Status filter (flexible normalization)
    if status and status.strip():
        norm_status = status.strip().upper().replace(" ", "_")
        query = query.filter(
            or_(
                Alert.status == norm_status,
                Alert.status.ilike(status.strip())
            )
        )

    # 3. Event Type filter
    if event_type and event_type.strip():
        et = event_type.strip().upper().replace(" ", "_")
        query = query.filter(
            or_(
                Alert.event_type == et,
                Alert.rule_name.ilike(f"%{event_type.strip()}%"),
                Alert.title.ilike(f"%{event_type.strip()}%")
            )
        )

    # 4. Search query
    if search and search.strip():
        term = search.strip()
        # If user searched '#12' or '12', search ID as well
        clean_id = term.lstrip("#")
        id_filter = Alert.id == int(clean_id) if clean_id.isdigit() else False
        s = f"%{term}%"
        query = query.filter(
            or_(
                id_filter,
                Alert.title.ilike(s),
                Alert.message.ilike(s),
                Alert.source_ip.ilike(s),
                Alert.destination_ip.ilike(s),
                Alert.rule_name.ilike(s),
                Alert.event_type.ilike(s),
                Alert.recommendation.ilike(s)
            )
        )

    # 5. Date filtering
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from.replace("Z", "+00:00"))
            query = query.filter(Alert.created_at >= dt_from)
        except Exception:
            pass
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to.replace("Z", "+00:00"))
            query = query.filter(Alert.created_at <= dt_to)
        except Exception:
            pass

    total = query.count()
    response.headers["X-Total-Count"] = str(total)

    alerts = query.order_by(desc(Alert.created_at)).offset(skip).limit(limit).all()

    if paged:
        return {
            "items": alerts,
            "total": total,
            "skip": skip,
            "limit": limit
        }
    return alerts

@router.get("/summary")
def get_alerts_summary(db: Session = Depends(get_db)):
    """Retrieve counts and unread breakdown of security alerts."""
    total = db.query(Alert).count()
    new_alerts = db.query(Alert).filter(Alert.status.in_(["NEW", "New"])).count()
    investigating = db.query(Alert).filter(Alert.status.in_(["INVESTIGATING", "Investigating"])).count()
    critical = db.query(Alert).filter(Alert.severity == "CRITICAL").count()
    high = db.query(Alert).filter(Alert.severity == "HIGH").count()
    return {
        "total": total,
        "new": new_alerts,
        "investigating": investigating,
        "critical": critical,
        "high": high
    }

class MarkReadRequest(BaseModel):
    alert_id: Optional[int] = None
    alert_ids: Optional[List[int]] = None

@router.get("/read-state")
def get_user_read_notifications(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve list of alert IDs marked as read by the authenticated user on the server (Task 6)."""
    reads = db.query(UserNotificationRead.alert_id).filter(UserNotificationRead.user_id == current_user.id).all()
    return {"read_alert_ids": [r[0] for r in reads]}

@router.post("/read-state")
def mark_notification_read(
    payload: MarkReadRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Mark specific alert(s) as read on the server for the authenticated user (Task 6)."""
    to_mark = []
    if payload.alert_id is not None:
        to_mark.append(payload.alert_id)
    if payload.alert_ids:
        to_mark.extend(payload.alert_ids)

    existing = set(
        r[0] for r in db.query(UserNotificationRead.alert_id)
        .filter(UserNotificationRead.user_id == current_user.id)
        .all()
    )

    for aid in to_mark:
        if aid not in existing:
            db.add(UserNotificationRead(user_id=current_user.id, alert_id=aid))
            existing.add(aid)

    db.commit()
    return {"read_alert_ids": sorted(list(existing))}

@router.post("/read-all")
def mark_all_notifications_read(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Mark all current alerts as read on the server for the authenticated user (Task 6)."""
    all_alert_ids = [r[0] for r in db.query(Alert.id).all()]
    existing = set(
        r[0] for r in db.query(UserNotificationRead.alert_id)
        .filter(UserNotificationRead.user_id == current_user.id)
        .all()
    )
    for aid in all_alert_ids:
        if aid not in existing:
            db.add(UserNotificationRead(user_id=current_user.id, alert_id=aid))
            existing.add(aid)

    db.commit()
    return {"read_alert_ids": sorted(list(existing))}

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Retrieve complete detail and explanation for a specific alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert_status(
    alert_id: int,
    alert_update: AlertUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update lifecycle status of an alert (NEW, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE).
    Requires authentication (Analyst or Admin). Unauthenticated requests receive 401.
    All status transitions are persisted and recorded in the audit log.
    """
    # 1. Enforce Role: Admin and Analyst are authorized
    user_role = (current_user.role or "").upper()
    if user_role not in ["ADMIN", "ANALYST", "OPERATOR"]:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Only Analysts and Administrators can modify alert status."
        )

    # 2. Fetch Alert
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # 3. Validate Status
    raw_status = alert_update.status.strip().upper()
    normalized_status = VALID_STATUSES.get(raw_status)
    if not normalized_status:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{alert_update.status}'. Allowed: New, Investigating, Contained, Resolved, False Positive"
        )

    old_status = alert.status
    alert.status = normalized_status

    # 4. Sync linked SecurityEvent if present
    if alert.event_id:
        event = db.query(SecurityEvent).filter(SecurityEvent.id == alert.event_id).first()
        if event:
            event.status = normalized_status

    # 5. Core Task 3 Synchronization Rule:
    # Recalculate affected device risk/trust, recover device status if threats resolved,
    # update Digital Twin graph, recompute health, and persist audit log.
    client_ip = request.client.host if request.client else "127.0.0.1"
    affected_ips = [ip for ip in [alert.source_ip, alert.destination_ip] if ip]
    sync_state_on_change(
        db=db,
        affected_device_ips=affected_ips,
        action="UPDATE_ALERT_STATUS",
        details=f"Alert #{alert.id} ('{alert.title}') status transitioned from {old_status} to {normalized_status} by {current_user.username}",
        username=current_user.username,
        user_id=current_user.id,
        ip_address=client_ip
    )

    db.refresh(alert)
    return alert

@router.get("/threats/events", response_model=List[SecurityEventResponse])
@router.get("/events", response_model=List[SecurityEventResponse])
def get_security_events(
    status: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Retrieve underlying raw security events detected by Rule and AI engines."""
    query = db.query(SecurityEvent)
    if status:
        query = query.filter(SecurityEvent.status.ilike(status))
    if event_type:
        query = query.filter(SecurityEvent.event_type.ilike(event_type))
    return query.order_by(SecurityEvent.created_at.desc()).limit(limit).all()
