import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .database import get_db
from .models import User
from .security import decode_token
from .utils import lock_remaining

bearer = HTTPBearer(auto_error=False)


def _payload(creds, scope: str) -> dict:
    if not creds:
        raise HTTPException(401, "Missing token")
    try:
        payload = decode_token(creds.credentials)
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    if payload.get("scope") != scope:
        raise HTTPException(401, "Wrong token type")
    return payload


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(get_db)) -> User:
    payload = _payload(creds, "access")
    user = db.get(User, payload.get("id"))
    if not user or user.token_version != payload.get("tv"):
        raise HTTPException(401, "Session terminated. Please log in again.")
    if user.is_frozen:
        raise HTTPException(403, "Account frozen by an administrator")
    remaining = lock_remaining(user)
    if remaining:
        raise HTTPException(423, {"status": "LOCKED", "seconds": remaining})
    return user


def get_mfa_user(creds: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(get_db)) -> User:
    payload = _payload(creds, "mfa")
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if not user:
        raise HTTPException(401, "Unknown user")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role not in ("admin", "superuser"):
        raise HTTPException(403, "Administrator privileges required")
    return user
