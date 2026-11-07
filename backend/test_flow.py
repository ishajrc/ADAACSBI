"""Smoke test: python test_flow.py  (uses a throwaway SQLite DB)"""
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_tmp.db"
if os.path.exists("test_tmp.db"): os.remove("test_tmp.db")
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
    # ---------- real-network features ----------
    from app import config
    from app.context import client_ip

    class FakeReq:
        def __init__(self, peer, xff=None):
            self.client = type("C", (), {"host": peer})()
            self.headers = {"x-forwarded-for": xff} if xff else {}

    old_sim, old_prox = config.ENABLE_SIMULATION, config.TRUSTED_PROXIES
    config.ENABLE_SIMULATION, config.TRUSTED_PROXIES = False, {"10.0.0.0/8", "testclient"}
    assert client_ip(FakeReq("10.0.0.5", "203.0.113.9, 10.0.0.7")) == "203.0.113.9"
    assert client_ip(FakeReq("10.0.0.5", "1.2.3.4, 203.0.113.9")) == "203.0.113.9", "spoofed hop must be ignored"
    assert client_ip(FakeReq("198.51.100.20", "1.2.3.4")) == "198.51.100.20", "XFF from untrusted peer must be ignored"
    config.ENABLE_SIMULATION, config.TRUSTED_PROXIES = old_sim, old_prox
    print("proxy-aware client IP OK")

    # admin-managed blacklist with CIDR
    r = c.post("/api/admin/blacklist", json={"cidr": "198.51.100.0/24", "reason": "test"}, headers=auth(atok)); assert r.status_code == 201, r.text
    ent = [e for e in c.get("/api/admin/blacklist", headers=auth(atok)).json() if e["cidr"] == "198.51.100.0/24"][0]
    r = login("alice", {"X-Simulated-IP": "198.51.100.9"}); assert r.status_code == 403 and r.json()["detail"]["risk_level"] == "CRITICAL"
    print("CIDR blacklist blocks 198.51.100.9")
    c.delete(f"/api/admin/blacklist/{ent['id']}", headers=auth(atok))

    # credential stuffing from one IP
    stuffing = {"X-Simulated-IP": "198.51.100.77"}
    codes = [c.post("/api/auth/login", json={"username": f"ghost{i}", "password": "x"}, headers={**H, **stuffing}).status_code for i in range(12)]
    assert codes[-1] == 429 and codes[0] == 401, codes
    print("credential stuffing -> 429 after", codes.count(401), "failures")

    # managed device enrollment (real trust, not a header)
    assert c.post("/api/auth/register", json={"username": "carol", "password": "Passw0rd!", "department": "Engineering"}).status_code == 201
    users = c.get("/api/admin/users", headers=auth(atok)).json(); cid = [u for u in users if u["username"] == "carol"][0]["id"]
    c.patch(f"/api/admin/users/{cid}/attributes", json={"work_start": 0, "work_end": 24, "allowed_days": "0,1,2,3,4,5,6"}, headers=auth(atok))
    code = c.post("/api/admin/devices/enrollment", json={"user_id": cid, "device_type": "Corporate Laptop"}, headers=auth(atok)).json()["code"]
    bad = c.post("/api/devices/enroll", json={"username": "carol", "password": "Passw0rd!", "code": "WRONG123"}); assert bad.status_code == 401
    ok = c.post("/api/devices/enroll", json={"username": "carol", "password": "Passw0rd!", "code": code}); assert ok.status_code == 200, ok.text
    dtok = ok.json()["device_token"]
    assert c.post("/api/devices/enroll", json={"username": "carol", "password": "Passw0rd!", "code": code}).status_code == 401, "code is single use"
    r = c.post("/api/auth/login", json={"username": "carol", "password": "Passw0rd!"}, headers={**H, "X-Device-Token": dtok})
    assert r.json()["status"] == "ALLOW", r.text; ctok = r.json()["access_token"]
    config.ENABLE_SIMULATION = False   # header claims must now be ignored
    me_claim = c.get("/api/me", headers={"Authorization": f"Bearer {ctok}", "X-Device-Type": "Corporate Laptop"}).json()
    me_tok = c.get("/api/me", headers={"Authorization": f"Bearer {ctok}", "X-Device-Token": dtok}).json()
    assert me_claim["device_type"] == "Unmanaged" and not me_claim["managed_device"], me_claim
    assert me_tok["device_type"] == "Corporate Laptop" and me_tok["managed_device"], me_tok
    dev_id = [d for d in c.get("/api/admin/devices", headers=auth(atok)).json() if d["username"] == "carol"][0]["id"]
    c.post(f"/api/admin/devices/{dev_id}/revoke", headers=auth(atok))
    me_rev = c.get("/api/me", headers={"Authorization": f"Bearer {ctok}", "X-Device-Token": dtok}).json()
    assert me_rev["device_type"] == "Unmanaged", me_rev
    config.ENABLE_SIMULATION = old_sim
    print("device enrollment: header claim ignored, token trusted, revoke works")
print("ALL TESTS PASSED")
