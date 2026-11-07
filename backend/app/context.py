import ipaddress

from fastapi import Request

from . import config
from .devices import resolve_device
from .geo import lookup_country
from .netutil import in_list
from .utils import now_ist


def client_ip(request: Request) -> str:
    """Real client IP. X-Forwarded-For is only believed when the direct peer is a trusted proxy,
    and we take the right-most address that is not itself a trusted proxy (hard to spoof)."""
    if config.ENABLE_SIMULATION and request.headers.get("x-simulated-ip"):
        return request.headers["x-simulated-ip"]
    peer = request.client.host if request.client else "0.0.0.0"
    if config.TRUSTED_PROXIES and in_list(peer, config.TRUSTED_PROXIES):
        hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
        for hop in reversed(hops):
            if not in_list(hop, config.TRUSTED_PROXIES):
                return hop
        if hops:
            return hops[0]
    return peer


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
    return await lookup_country(ip)


async def build_context(request: Request, user, db) -> dict:
    ip = client_ip(request)
    device_type, fingerprint, managed = resolve_device(db, user, request)
    first_login = user.last_login_at is None  # first login establishes the baseline
    known_devices = set(filter(None, (user.known_devices or "").split(",")))
    known_ips = set(filter(None, (user.known_ips or "").split(",")))
    now = now_ist()
    return {
        "ip": ip,
        "country": await get_country(ip, request),
        "device_type": device_type,
        "managed_device": managed,
        "fingerprint": fingerprint,
        "hour": now.hour,
        "weekday": now.weekday(),
        "trusted_network": is_trusted(ip),
        "is_new_device": (not first_login) and fingerprint not in known_devices,
        "is_new_ip": (not first_login) and ip not in known_ips,
    }
