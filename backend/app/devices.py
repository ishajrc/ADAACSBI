"""Managed-device trust. A device is 'managed' only if it holds a valid signed token from enrollment."""
import hashlib

import jwt
from fastapi import Request

from . import config
from .models import Device
from .security import decode_token


def hash_code(code: str) -> str:
    return hashlib.sha256(code.strip().upper().encode()).hexdigest()


def resolve_device(db, user, request: Request):
    """Returns (device_type, fingerprint, is_managed)."""
    token = request.headers.get("x-device-token")
    if token:
        try:
            p = decode_token(token)
            if p.get("scope") == "device" and p.get("uid") == user.id:
                dev = db.get(Device, p.get("did"))
                if dev and dev.user_id == user.id and dev.status == "active":
                    return dev.device_type, f"dev-{dev.id}", True
        except jwt.PyJWTError:
            pass
    ua = request.headers.get("user-agent", "")
    if config.ENABLE_SIMULATION and request.headers.get("x-device-type"):
        device_type = request.headers["x-device-type"][:40]  # demo only
    else:
        device_type = "Unmanaged"
    fingerprint = hashlib.sha256(f"{ua}|{device_type}".encode()).hexdigest()[:16]
    return device_type, fingerprint, False
