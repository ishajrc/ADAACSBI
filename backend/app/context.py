import hashlib
import ipaddress

import httpx
from fastapi import Request

from . import config
from .utils import now_ist


def client_ip(request: Request) -> str:
    if config.ENABLE_SIMULATION and request.headers.get("x-simulated-ip"):
        return request.headers["x-simulated-ip"]
    return request.client.host if request.client else "0.0.0.0"


def is_trusted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


async def get_country(ip: str, request: Request) -> str:
    if config.ENABLE_SIMULATION:
        if request.headers.get("x-simulated-country"):
            return request.headers["x-simulated-country"].upper()
        if request.headers.get("x-simulated-ip"):
            return config.DEFAULT_COUNTRY
    if is_trusted(ip):
        return config.DEFAULT_COUNTRY
    try:
        async with httpx.AsyncClient(timeout=2) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}", params={"fields": "countryCode"})
            return r.json().get("countryCode", "")
    except Exception:
        return ""


async def build_context(request: Request, user) -> dict:
    ip = client_ip(request)
    device_type = request.headers.get("x-device-type", "Unknown")[:40]
    ua = request.headers.get("user-agent", "")
    fingerprint = hashlib.sha256(f"{ua}|{device_type}".encode()).hexdigest()[:16]
    first_login = user.last_login_at is None  # first login establishes the baseline
    known_devices = set(filter(None, (user.known_devices or "").split(",")))
    known_ips = set(filter(None, (user.known_ips or "").split(",")))
    now = now_ist()
    return {
        "ip": ip,
        "country": await get_country(ip, request),
        "device_type": device_type,
        "fingerprint": fingerprint,
        "hour": now.hour,
        "weekday": now.weekday(),
        "trusted_network": is_trusted(ip),
        "is_new_device": (not first_login) and fingerprint not in known_devices,
        "is_new_ip": (not first_login) and ip not in known_ips,
    }
