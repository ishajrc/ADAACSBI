"""Smoke test: python test_flow.py  (uses a throwaway SQLite DB)"""
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_tmp.db"
from fastapi.testclient import TestClient
from app.main import app
from app import ml

H = {"X-Simulated-IP": "127.0.0.1", "X-Device-Type": "Corporate Laptop"}
def login(u, extra=None):
    return c.post("/api/auth/login", json={"username": u, "password": "Passw0rd!"}, headers={**H, **(extra or {})})
def auth(tok, extra=None): return {**H, **(extra or {}), "Authorization": f"Bearer {tok}"}

with TestClient(app) as c:
    # ML sanity
    assert not ml.predict([10, 2, 1, 1, 1, 1, 0, 0, 0, 3])["is_anomaly"], "normal vector flagged"
    assert ml.predict([3, 6, 3, -2, 0, 0, 1, 1, 4, 25])["is_anomaly"], "attack vector missed"
    print("ML sanity OK")

    r = login("devuser"); assert r.json()["status"] == "ALLOW", r.text
    tok = r.json()["access_token"]; print("first login ALLOW")

    r = login("devuser", {"X-Simulated-IP": "203.0.113.66"}); assert r.status_code == 403
    print("blacklisted IP ->", r.json()["detail"]["risk_level"])
    r = login("devuser", {"X-Simulated-Country": "KP"}); assert r.status_code == 403; print("restricted country blocked")
    r = login("devuser", {"X-Simulated-Country": "US"}); assert r.status_code == 403
    print("impossible travel ->", r.json()["detail"]["reasons"][0])

    r = login("devuser", {"X-Device-Type": "Personal Phone"}); print("new device ->", r.json()["status"])
    assert r.json()["status"] in ("ALLOW", "MFA_REQUIRED", "MFA_SETUP_REQUIRED")

    # Department violation: devuser (Engineering) -> Finance 101
    r = c.post("/api/resources/101/access", headers=auth(tok)); print("dept rule ->", r.json()["reason"])
    assert r.json()["decision"] == "DENIED"
    # Engineering resource: GRANTED unless ML flags the hour
    r = c.post("/api/resources/103/access", headers=auth(tok)); print("103 ->", r.json()["decision"], r.json()["reason"])

    # 5 violations -> lockout + forced logout
    for _ in range(5): r = c.post("/api/resources/101/access", headers=auth(tok))
    print("after spam ->", r.json())
    assert r.json().get("forced_logout") or r.status_code in (401, 423, 429)
    r = c.get("/api/me", headers=auth(tok)); assert r.status_code in (401, 423); print("old token dead:", r.status_code)

    # Admin MFA flow
    import pyotp
    r = login("manager"); assert r.json()["status"] == "MFA_SETUP_REQUIRED"
    mt = r.json()["mfa_token"]
    s = c.post("/api/auth/mfa/setup", headers=auth(mt)).json(); assert s["qr"].startswith("data:image/png")
    r = c.post("/api/auth/mfa/verify", json={"code": "000000"}, headers=auth(mt)); assert r.status_code == 401
    r = c.post("/api/auth/mfa/verify", json={"code": pyotp.TOTP(s["secret"]).now()}, headers=auth(mt))
    assert r.status_code == 200, r.text; atok = r.json()["access_token"]; print("admin MFA OK")
    print("stats:", c.get("/api/admin/stats", headers=auth(atok)).json())
    r = c.post("/api/resources/101/access", headers=auth(atok)); print("admin cross-dept ->", r.json()["decision"])
    assert c.get("/api/admin/stats", headers=auth(tok)).status_code in (401, 403, 423)

    # password lockout
    for _ in range(5): c.post("/api/auth/login", json={"username": "bob", "password": "wrong"}, headers=H)
    assert login("bob").status_code == 423; print("15-min login lockout OK")
print("ALL TESTS PASSED")
