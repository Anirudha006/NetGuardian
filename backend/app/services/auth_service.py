import hashlib
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional
try:
    import jwt
    from jwt.exceptions import PyJWTError as JWTError
except ImportError:
    from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.models.audit_log import SystemSetting
from app.schemas.auth import TokenPayload
from app.utils.time_utils import utcnow

PBKDF2_ITERATIONS = 600000

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Hash password using salted PBKDF2-HMAC-SHA256 with at least 600,000 iterations."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${key.hex()}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against salted PBKDF2 hash (supports 600k iterations and legacy 100k)."""
    try:
        parts = hashed_password.split("$")
        if len(parts) == 4 and parts[0] == "pbkdf2_sha256":
            iters = int(parts[1])
            salt = parts[2]
            key_hex = parts[3]
            check_key = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt.encode('utf-8'), iters)
            return secrets.compare_digest(key_hex, check_key.hex())
        elif len(parts) == 2:
            # Legacy format: salt$key (100,000 iterations)
            salt, key_hex = parts
            check_key = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt.encode('utf-8'), 100000)
            return secrets.compare_digest(key_hex, check_key.hex())
        return False
    except Exception:
        return False

def needs_rehash(hashed_password: str) -> bool:
    """Check if hash uses fewer than 600,000 iterations or legacy format."""
    if not hashed_password:
        return True
    parts = hashed_password.split("$")
    if len(parts) == 4 and parts[0] == "pbkdf2_sha256":
        try:
            return int(parts[1]) < PBKDF2_ITERATIONS
        except ValueError:
            return True
    return True

def get_session_timeout_minutes(db: Optional[Session] = None) -> int:
    """Retrieve session timeout in minutes from DB SystemSetting or config fallback."""
    if db is not None:
        try:
            setting = db.query(SystemSetting).filter(SystemSetting.key == "session_timeout_minutes").first()
            if setting and setting.value:
                return int(setting.value)
        except Exception:
            pass
    return settings.ACCESS_TOKEN_EXPIRE_MINUTES

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None, timeout_minutes: Optional[int] = None) -> str:
    """Create signed JWT access token with dynamic expiration."""
    to_encode = data.copy()
    now = utcnow()
    if expires_delta:
        expire = now + expires_delta
    elif timeout_minutes is not None:
        expire = now + timedelta(minutes=timeout_minutes)
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def set_auth_cookies(response: Response, token: str, csrf_token: str, max_age_seconds: int = 86400):
    """Set secure HttpOnly authentication cookie and CSRF token cookie."""
    is_prod = settings.ENVIRONMENT.lower() == "production"
    # HttpOnly JWT session cookie
    response.set_cookie(
        key="ng_session",
        value=token,
        httponly=True,
        samesite="strict",
        secure=is_prod,
        max_age=max_age_seconds,
        path="/"
    )
    # JS-readable CSRF token cookie (Double-submit pattern)
    response.set_cookie(
        key="ng_csrf",
        value=csrf_token,
        httponly=False,
        samesite="strict",
        secure=is_prod,
        max_age=max_age_seconds,
        path="/"
    )

def clear_auth_cookies(response: Response):
    """Clear authentication and CSRF cookies on logout."""
    response.delete_cookie(key="ng_session", path="/")
    response.delete_cookie(key="ng_csrf", path="/")

def get_current_user(request: Request, token: Optional[str] = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """Validate JWT token from HttpOnly cookie or Authorization header, enforcing CSRF on state-changing cookie requests."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # 1. Resolve JWT token: Authorization header takes precedence (API client), then HttpOnly cookie (Browser session)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        resolved_token = token or auth_header.split(" ", 1)[1].strip()
        is_cookie_auth = False
    elif request.cookies.get("ng_session"):
        resolved_token = request.cookies.get("ng_session")
        is_cookie_auth = True
    else:
        resolved_token = token
        is_cookie_auth = False

    if not resolved_token:
        raise credentials_exception

    # 2. CSRF protection for cookie-based state-changing requests
    if is_cookie_auth and request.method in ["POST", "PUT", "PATCH", "DELETE"]:
        csrf_header = request.headers.get("X-CSRF-Token")
        csrf_cookie = request.cookies.get("ng_csrf")
        if not csrf_header or not csrf_cookie or not secrets.compare_digest(csrf_header, csrf_cookie):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token validation failed."
            )

    try:
        payload = jwt.decode(resolved_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Ensure authenticated user has ADMIN role."""
    if current_user.role.upper() != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required for this action."
        )
    return current_user

def require_analyst_or_admin(current_user: User = Depends(get_current_user)) -> User:
    """Ensure authenticated user has ANALYST or ADMIN role."""
    if current_user.role.upper() not in ["ADMIN", "ANALYST", "OPERATOR"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst or administrative privileges required for this action."
        )
    return current_user
