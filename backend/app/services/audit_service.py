from sqlalchemy.orm import Session
from app.models.audit_log import AuditLog
from typing import Optional, Any

def log_audit_event(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_address: str = "127.0.0.1",
    details: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[Any] = None
) -> AuditLog:
    """Record an audit trail event."""
    log_entry = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        ip_address=ip_address,
        details=details
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry

def record_audit_event(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_address: str = "127.0.0.1",
    details: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[Any] = None
) -> AuditLog:
    """Alias for log_audit_event."""
    return log_audit_event(
        db=db,
        action=action,
        user_id=user_id,
        username=username,
        ip_address=ip_address,
        details=details,
        resource_type=resource_type,
        resource_id=resource_id
    )
