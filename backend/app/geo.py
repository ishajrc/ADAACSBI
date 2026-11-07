"""IP -> country. Local GeoLite2 database first, then an HTTPS lookup, results cached."""
import os
import time

import httpx

from . import config

_reader = None
_reader_tried = False
_cache: dict = {}  # ip -> (country, expires_at)
TTL = 3600


def _local_reader():
    global _reader, _reader_tried
    if _reader_tried:
        return _reader
    _reader_tried = True
    path = os.path.abspath(config.GEOIP_DB_PATH)
    if os.path.exists(path):
        try:
            import geoip2.database
            _reader = geoip2.database.Reader(path)
            print(f"[geo] using local GeoIP database {path}")
        except Exception as exc:
            print(f"[geo] could not open GeoIP database: {exc}")
    else:
        print("[geo] no local GeoIP database found" + (" - using online fallback" if config.GEO_ONLINE_FALLBACK else ""))
    return _reader


async def lookup_country(ip: str) -> str:
    hit = _cache.get(ip)
    if hit and hit[1] > time.time():
        return hit[0]
    country = ""
    reader = _local_reader()
    if reader:
        try:
            country = reader.country(ip).country.iso_code or ""
        except Exception:
            country = ""
    elif config.GEO_ONLINE_FALLBACK:
        try:
            async with httpx.AsyncClient(timeout=2) as client:
                r = await client.get(f"https://ipwho.is/{ip}", params={"fields": "success,country_code"})
                data = r.json()
                country = data.get("country_code", "") if data.get("success") else ""
        except Exception:
            country = ""
    if len(_cache) > 5000:
        _cache.clear()
    _cache[ip] = (country, time.time() + TTL)
    return country
