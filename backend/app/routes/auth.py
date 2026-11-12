import logging
import secrets
from datetime import datetime, timedelta
from typing import List, Dict
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, Token, UserResponse, UserCreate
from app.config import settings
from app.services.auth_service import (
    verify_password, hash_password, needs_rehash, create_access_token,
    get_current_user, require_admin, set_auth_cookies, clear_auth_cookies,
    get_session_timeout_minutes, PBKDF2_ITERATIONS
)
from app.services.audit_service import log_audit_event
from app.utils.time_utils import utcnow

logger = logging.getLogger("netguardian.auth")

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# In-memory rate limiting: 5 failed attempts per 5 minutes per (normalized username + client IP)
_failed_attempts: Dict[str, List[datetime]] = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 5

def normalize_username(username: str) -> str:
    """Normalize username by stripping leading/trailing whitespace and lowercasing."""
    return username.strip().lower() if username else ""

def get_rate_limit_key(clean_username: str, request: Request) -> str:
    """Rate limit keyed on normalized username plus client IP address.
    Do NOT trust X-Forwarded-For by default. Use real connection address (request.client.host).
    Only read X-Forwarded-For when connecting address is explicitly in TRUSTED_PROXIES.
    """
    real_ip = request.client.host if (request and request.client) else "127.0.0.1"
    trusted_raw = getattr(settings, "TRUSTED_PROXIES", "") or ""
    trusted_proxies = {ip.strip() for ip in trusted_raw.split(",") if ip.strip()}

    client_ip = real_ip
    if real_ip in trusted_proxies and request:
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            client_ip = xff.split(",")[0].strip()

    return f"{clean_username}:{client_ip}"

def check_login_rate_limit(rate_key: str):
    """Check if user+IP bucket has exceeded max failed login attempts in the lockout window."""
    now = utcnow()
    window_start = now - timedelta(minutes=LOCKOUT_MINUTES)
    
    if rate_key in _failed_attempts:
        _failed_attempts[rate_key] = [t for t in _failed_attempts[rate_key] if t > window_start]
        if len(_failed_attempts[rate_key]) >= MAX_FAILED_ATTEMPTS:
            logger.warning(f"Rate limit triggered for key: {rate_key} (>= {MAX_FAILED_ATTEMPTS} failed attempts)")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Please wait 5 minutes before trying again."
            )

def record_failed_attempt(rate_key: str):
    """Record timestamp for a failed login attempt under user+IP bucket."""
    now = utcnow()
    if rate_key not in _failed_attempts:
        _failed_attempts[rate_key] = []
    _failed_attempts[rate_key].append(now)

def clear_failed_attempts(rate_key: str):
    """Clear recorded failed login attempts on successful authentication."""
    if rate_key in _failed_attempts:
        del _failed_attempts[rate_key]

def clear_all_failed_attempts():
    """Reset all rate limiting state (for testing and administrative reset)."""
    _failed_attempts.clear()

@router.post("/login", response_model=Token)
def login(creds: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    """
    Authenticate user, enforce rate limiting (keyed on username + IP),
    set HttpOnly SameSite=Strict session cookie + CSRF token,
    and automatically rehash legacy passwords to >= 600,000 iterations.
    """
    clean_username = normalize_username(creds.username)
    rate_key = get_rate_limit_key(clean_username, request)
    check_login_rate_limit(rate_key)

    # Production mode safeguard: refuse default credentials in production mode
    if getattr(settings, "ENVIRONMENT", "").lower() == "production":
        insecure_passwords = ["admin123", "analyst123", "password", "default", "admin", "analyst"]
        if creds.password.lower() in insecure_passwords:
            logger.error(f"Login rejected: Default credentials used in production environment for '{clean_username}'.")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Production mode refuses default credentials. Default passwords must be updated before production access is permitted."
            )

    # Casing and whitespace normalized lookup
    user = db.query(User).filter(func.lower(User.username) == clean_username).first()
    if not user or not verify_password(creds.password, user.password_hash):
        record_failed_attempt(rate_key)
        logger.warning(f"Failed authentication attempt for username: {creds.username} (normalized: {clean_username}, key: {rate_key})")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Automatic rehashing for existing users if hash uses < 600,000 iterations or legacy format
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(creds.password)
        logger.info(f"Upgraded password hash to {PBKDF2_ITERATIONS} iterations for user '{user.username}'.")

    # Clear rate limit attempts on success
    clear_failed_attempts(rate_key)

    user.last_login = utcnow()
    db.commit()

    # Dynamic session timeout from DB settings
    timeout_mins = get_session_timeout_minutes(db)
    token = create_access_token(
        data={"sub": user.username, "role": user.role},
        timeout_minutes=timeout_mins
    )

    # Generate CSRF token for double-submit cookie protection
    csrf_token = secrets.token_hex(32)
    set_auth_cookies(response, token=token, csrf_token=csrf_token, max_age_seconds=timeout_mins * 60)

    log_audit_event(db, action="LOGIN", user_id=user.id, username=user.username, details=f"User {user.username} logged in successfully.")
    logger.info(f"User {user.username} ({user.role}) authenticated successfully. Session timeout: {timeout_mins}m.")

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user.role,
        "username": user.username,
        "csrf_token": csrf_token
    }

@router.post("/logout")
def logout(response: Response, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Log out authenticated user, clear HttpOnly & CSRF cookies, and record audit log."""
    clear_auth_cookies(response)
    log_audit_event(db, action="LOGOUT", user_id=current_user.id, username=current_user.username, details="User logged out.")
    logger.info(f"User {current_user.username} logged out and cookies cleared.")
    return {"message": "Successfully logged out."}

@router.get("/me", response_model=UserResponse)
def get_current_profile(current_user: User = Depends(get_current_user)):
    """Return authenticated user profile."""
    return current_user

@router.get("/users", response_model=List[UserResponse])
def list_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Admin-only endpoint: list all system users. Enforces 403 for non-admin."""
    return db.query(User).all()

@router.post("/users", response_model=UserResponse)
def create_user(user_in: UserCreate, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Admin-only endpoint: register a new user account with 600,000-iteration PBKDF2 hash."""
    clean_username = normalize_username(user_in.username)
    if db.query(User).filter(func.lower(User.username) == clean_username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(func.lower(User.email) == user_in.email.strip().lower()).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    new_user = User(
        username=user_in.username.strip(),
        email=user_in.email.strip().lower(),
        password_hash=hash_password(user_in.password),
        role=user_in.role.upper()
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    log_audit_event(db, action="CREATE_USER", user_id=admin.id, username=admin.username, details=f"Created user {new_user.username} with role {new_user.role}")
    return new_user
