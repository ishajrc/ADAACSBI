import ipaddress
import secrets
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from . import config, ml
from .abac import check_abac
from .audit import audit
from .context import build_context, client_ip
from .devices import hash_code, resolve_device
from .database import Base, SessionLocal, engine, get_db
from .deps import get_current_user, get_mfa_user, require_admin
from .models import AccessRequest, BlacklistEntry, Device, User
from .risk import advanced_risk, basic_risk, record_ip_failure, too_many_failures
from .security import (DUMMY_HASH, create_token, hash_password, new_totp_secret, qr_data_uri,
                       totp_uri, verify_password, verify_totp)
from .utils import lock_remaining, utcnow


# ---------- startup ----------
def seed_demo_users(db: Session):
    if db.query(User).count():
        return
    pw = hash_password("Passw0rd!")
    allday = dict(work_start=0, work_end=24, allowed_days="0,1,2,3,4,5,6")
    demo = [
        User(username="alice", password_hash=pw, department="Engineering", clearance_level=2),
        User(username="bob", password_hash=pw, department="Finance", clearance_level=3),
        User(username="devuser", password_hash=pw, department="Engineering", clearance_level=3, **allday),
        User(username="manager", password_hash=pw, role="admin", department="Management", clearance_level=3, **allday),
        User(username="admin2", password_hash=pw, role="admin", department="Engineering", clearance_level=3, **allday),
        User(username="superadmin", password_hash=pw, role="superuser", department="Management", clearance_level=3, **allday),
    ]
    db.add_all(demo)
    db.commit()


def startup_checks():
    if config.ENABLE_SIMULATION:
        print("[WARN] ENABLE_SIMULATION=1: clients can fake IP/country/device headers. Demo only.")
    elif config.SECRET_KEY == config.DEFAULT_SECRET:
        raise RuntimeError("Set a real SECRET_KEY in backend/.env before running with ENABLE_SIMULATION=0")


@asynccontextmanager
async def lifespan(app: FastAPI):
    startup_checks()
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_demo_users(db)
    ml.get_models()
    yield


app = FastAPI(title="AI-Driven Adaptive Access Control", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3005"], allow_methods=["*"], allow_headers=["*"])


# ---------- schemas ----------
class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=128)
    department: str = "General"


class LoginIn(BaseModel):
    username: str
    password: str


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class AttrIn(BaseModel):
    department: Optional[str] = None
    clearance_level: Optional[int] = Field(default=None, ge=1, le=3)
    work_start: Optional[int] = Field(default=None, ge=0, le=24)
    work_end: Optional[int] = Field(default=None, ge=0, le=24)
    allowed_days: Optional[str] = None


# ---------- helpers ----------
def _add_known(csv: str, value: str) -> str:
    items = set(filter(None, (csv or "").split(",")))
    items.add(value)
    return ",".join(sorted(items))


def finalize_login(db: Session, user: User, ctx: dict, score: float):
    user.known_devices = _add_known(user.known_devices, ctx["fingerprint"])
    user.known_ips = _add_known(user.known_ips, ctx["ip"])
    user.last_login_at = utcnow()
    user.last_login_country = ctx["country"] or user.last_login_country
    user.login_risk_score = score
    user.failed_attempts = 0
    user.violation_count = 0
    user.request_burst_count = 0
    db.commit()


def access_token_for(user: User) -> str:
    return create_token({
        "sub": user.username, "role": user.role, "id": user.id, "department": user.department,
        "work_start": user.work_start, "work_end": user.work_end,
        "clearance": user.clearance_level, "tv": user.token_version,
    }, config.ACCESS_TOKEN_MINUTES)


def register_failure(db: Session, user: User):
    user.failed_attempts += 1
    if user.failed_attempts >= config.MAX_FAILED_LOGINS:
        user.locked_until = utcnow() + timedelta(minutes=config.LOGIN_LOCKOUT_MINUTES)
        user.failed_attempts = 0
    db.commit()


def apply_rate_limit(db: Session, user: User):
    now = utcnow()
    if user.burst_window_start is None or (now - user.burst_window_start).total_seconds() >= 60:
        user.burst_window_start, user.request_burst_count = now, 0
    risk = user.login_risk_score or 0.0
    limit = 2 if risk >= 0.8 else 10 if risk >= 0.5 else 30
    user.request_burst_count += 1
    db.commit()
    if user.request_burst_count > limit:
        raise HTTPException(429, "ADAPTIVE RATE LIMIT EXCEEDED")


# ---------- auth ----------
@app.post("/api/auth/register", status_code=201)
def register(body: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(409, "Username already taken")
    # Prototype: self-registered users get the lowest clearance. Admins can raise it.
    db.add(User(username=body.username, password_hash=hash_password(body.password),
                department=body.department, clearance_level=1))
    db.commit()
    audit.log("register", body.username)
    return {"message": "Account created"}


@app.post("/api/auth/login")
async def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    if too_many_failures(ip):
        audit.log("login_blocked", body.username, ip=ip, reason="credential stuffing: too many failures from IP")
        raise HTTPException(429, "Too many failed attempts from this network. Try again later.")
    user = db.query(User).filter(User.username == body.username).first()
    if not user:
        verify_password(body.password, DUMMY_HASH)  # keep timing similar
        record_ip_failure(ip)
        audit.log("login_failed", body.username, ip=ip, reason="unknown user")
        raise HTTPException(401, "Invalid credentials")
    if user.is_frozen:
        raise HTTPException(403, {"status": "FROZEN", "message": "Account frozen by an administrator"})
    remaining = lock_remaining(user)
    if remaining:
        raise HTTPException(423, {"status": "LOCKED", "seconds": remaining,
                                  "message": "Account locked - too many violations"})
    if not verify_password(body.password, user.password_hash):
        register_failure(db, user)
        record_ip_failure(ip)
        audit.log("login_failed", user.username, ip=ip, reason="bad password")
        raise HTTPException(401, "Invalid credentials")

    prior_failed = user.failed_attempts
    ctx = await build_context(request, user, db)
    score, reasons = basic_risk(user, ctx, prior_failed)
    adv = advanced_risk(ctx, user, db)
    ev = dict(ip=ctx["ip"], device=ctx["device_type"], country=ctx["country"], risk=score)

    if adv["action"] == "BLOCKED" or score >= config.RISK_BLOCK:
        level = adv["risk_level"] if adv["action"] == "BLOCKED" else "HIGH"
        if adv["reason"]:
            reasons = [adv["reason"]] + reasons
        user.login_risk_score = 1.0
        db.commit()
        audit.log("login", user.username, decision="BLOCKED", reasons=reasons, **ev)
        raise HTTPException(403, {"status": "BLOCKED", "risk_level": level, "reasons": reasons})

    needs_mfa = score >= config.RISK_MFA or user.role in ("admin", "superuser")
    if needs_mfa:
        if user.role in ("admin", "superuser") and not reasons:
            reasons = ["Privileged account: MFA always required"]
        status = "MFA_REQUIRED" if user.totp_enabled else "MFA_SETUP_REQUIRED"
        audit.log("login", user.username, decision=status, reasons=reasons, **ev)
        return {"status": status, "mfa_token": create_token({"sub": user.username}, config.MFA_TOKEN_MINUTES, "mfa"),
                "risk_score": score, "reasons": reasons}

    finalize_login(db, user, ctx, score)
    audit.log("login", user.username, decision="ALLOW", reasons=reasons, **ev)
    return {"status": "ALLOW", "access_token": access_token_for(user), "risk_score": score, "reasons": reasons}


@app.post("/api/auth/mfa/setup")
def mfa_setup(user: User = Depends(get_mfa_user), db: Session = Depends(get_db)):
    if user.totp_enabled:
        raise HTTPException(400, "MFA already enabled")
    user.totp_secret = new_totp_secret()
    db.commit()
    uri = totp_uri(user.totp_secret, user.username)
    return {"secret": user.totp_secret, "qr": qr_data_uri(uri)}


@app.post("/api/auth/mfa/verify")
async def mfa_verify(body: CodeIn, request: Request, user: User = Depends(get_mfa_user), db: Session = Depends(get_db)):
    if lock_remaining(user):
        raise HTTPException(423, {"status": "LOCKED", "seconds": lock_remaining(user)})
    if not user.totp_secret or not verify_totp(user.totp_secret, body.code):
        register_failure(db, user)
        audit.log("mfa_failed", user.username)
        raise HTTPException(401, "Invalid authenticator code")
    user.totp_enabled = True
    ctx = await build_context(request, user, db)
    finalize_login(db, user, ctx, user.login_risk_score or 0.0)
    audit.log("mfa_success", user.username, ip=ctx["ip"])
    return {"status": "ALLOW", "access_token": access_token_for(user)}


@app.get("/api/me")
def me(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    device_type, _, managed = resolve_device(db, user, request)
    return {"device_type": device_type, "managed_device": managed, **{"id": user.id, "username": user.username, "role": user.role, "department": user.department,
            "clearance_level": user.clearance_level, "risk_score": user.login_risk_score,
            "work_start": user.work_start, "work_end": user.work_end, "allowed_days": user.allowed_days}}


# ---------- resources ----------
@app.get("/api/resources")
def list_resources(user: User = Depends(get_current_user)):
    return [{"id": rid, **r} for rid, r in config.RESOURCES.items()]


@app.post("/api/resources/{rid}/access")
async def access_resource(rid: int, request: Request, user: User = Depends(get_current_user),
                          db: Session = Depends(get_db)):
    res = config.RESOURCES.get(rid)
    if not res:
        raise HTTPException(404, "Unknown resource")
    apply_rate_limit(db, user)
    ctx = await build_context(request, user, db)
    approved = (db.query(AccessRequest)
                .filter_by(requester_id=user.id, resource_id=rid, status="approved").first())

    ml_out = ml.predict(ml.build_features(user, res, ctx))
    verdict = check_abac(user, res, ctx, dual_auth_approved=bool(approved))
    if verdict is None and ml_out["is_anomaly"]:
        verdict = {"decision": "DENIED", "rule": 0,
                   "reason": f"AI anomaly detected (risk {ml_out['risk']}, {ml_out['votes']}/3 models flagged)"}

    result = {"resource": res["name"], "risk": ml_out["risk"], "locked": False, "forced_logout": False}

    if verdict and verdict["decision"] == "PENDING_DUAL_AUTH":
        exists = db.query(AccessRequest).filter_by(requester_id=user.id, resource_id=rid, status="pending").first()
        if not exists:
            db.add(AccessRequest(requester_id=user.id, requester_name=user.username, resource_id=rid))
            db.commit()
        result.update(decision="PENDING_DUAL_AUTH", reason=verdict["reason"])
    elif verdict:  # DENIED
        user.violation_count += 1
        result.update(decision="DENIED", reason=verdict["reason"], violations=user.violation_count)
        if user.violation_count >= config.MAX_VIOLATIONS:
            user.locked_until = utcnow() + timedelta(seconds=config.VIOLATION_LOCKOUT_SECONDS)
            user.token_version += 1  # kills the current session everywhere
            user.violation_count = 0
            result.update(locked=True, forced_logout=True, lock_seconds=config.VIOLATION_LOCKOUT_SECONDS,
                          reason=result["reason"] + " | Too many violations: session terminated.")
        db.commit()
    else:
        if approved:
            approved.status = "used"
        db.commit()
        result.update(decision="GRANTED", reason="Access granted by policy and AI engine")

    audit.log("access", user.username, resource_id=rid, resource_name=res["name"], decision=result["decision"],
              reason=result["reason"], risk=ml_out["risk"], anomaly=ml_out["is_anomaly"],
              ip=ctx["ip"], device=ctx["device_type"])
    return result


@app.get("/api/history")
def my_history(user: User = Depends(get_current_user)):
    return audit.recent(30, username=user.username)


# ---------- admin ----------
@app.get("/api/admin/stats")
def stats(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    events = audit.recent(500, types=["access"])
    chrono = list(reversed(events))
    granted = sum(1 for e in events if e.get("decision") == "GRANTED")
    denied = sum(1 for e in events if e.get("decision") == "DENIED")
    return {
        "total_events": len(events),
        "anomalies": sum(1 for e in events if e.get("anomaly")),
        "active_identities": db.query(User).filter(User.is_frozen.is_(False)).count(),
        "risk_trajectory": [e.get("risk", 0) for e in chrono[-30:]],
        "distribution": {"GRANTED": granted, "DENIED": denied},
    }


@app.get("/api/admin/audit")
def admin_audit(admin: User = Depends(require_admin)):
    return audit.recent(100)


@app.get("/api/admin/users")
def admin_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return [{"id": u.id, "username": u.username, "role": u.role, "department": u.department,
             "clearance_level": u.clearance_level, "risk": u.login_risk_score, "is_frozen": u.is_frozen}
            for u in db.query(User).order_by(User.id).all()]


@app.post("/api/admin/users/{uid}/{action}")
def freeze_user(uid: int, action: str, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if action not in ("freeze", "unfreeze"):
        raise HTTPException(404, "Unknown action")
    target = db.get(User, uid)
    if not target:
        raise HTTPException(404, "User not found")
    if target.id == admin.id:
        raise HTTPException(400, "You cannot freeze your own account")
    target.is_frozen = action == "freeze"
    target.token_version += 1
    db.commit()
    audit.log("admin_action", admin.username, action=action.upper(), target=target.username)
    return {"username": target.username, "is_frozen": target.is_frozen}


@app.patch("/api/admin/users/{uid}/attributes")
def update_attributes(uid: int, body: AttrIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = db.get(User, uid)
    if not target:
        raise HTTPException(404, "User not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(target, field, value)
    db.commit()
    audit.log("admin_action", admin.username, action="UPDATE_ATTRIBUTES", target=target.username)
    return {"ok": True}


@app.get("/api/admin/requests")
def list_requests(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(AccessRequest).order_by(AccessRequest.id.desc()).limit(50).all()
    return [{"id": r.id, "requester": r.requester_name, "requester_id": r.requester_id,
             "resource": config.RESOURCES[r.resource_id]["name"], "status": r.status} for r in rows]


@app.post("/api/admin/requests/{rid}/{action}")
def decide_request(rid: int, action: str, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if action not in ("approve", "reject"):
        raise HTTPException(404, "Unknown action")
    req = db.get(AccessRequest, rid)
    if not req or req.status != "pending":
        raise HTTPException(404, "No pending request")
    if req.requester_id == admin.id:
        raise HTTPException(403, "You cannot approve your own request")
    req.status = "approved" if action == "approve" else "rejected"
    req.decided_by = admin.id
    db.commit()
    audit.log("admin_action", admin.username, action=f"{action.upper()}_ACCESS", target=req.requester_name)
    return {"id": req.id, "status": req.status}


# ---------- managed devices ----------
class EnrollCodeIn(BaseModel):
    user_id: int
    device_type: str = "Corporate Laptop"


class EnrollIn(BaseModel):
    username: str
    password: str
    code: str


@app.post("/api/admin/devices/enrollment")
def create_enrollment(body: EnrollCodeIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if body.device_type not in config.MANAGED_DEVICES:
        raise HTTPException(400, f"device_type must be one of {sorted(config.MANAGED_DEVICES)}")
    target = db.get(User, body.user_id)
    if not target:
        raise HTTPException(404, "User not found")
    code = secrets.token_hex(4).upper()  # e.g. 9F3A1C07, single use, 15 minutes
    db.add(Device(user_id=target.id, device_type=body.device_type, status="pending",
                  code_hash=hash_code(code), code_expires=utcnow() + timedelta(minutes=15)))
    db.commit()
    audit.log("admin_action", admin.username, action="DEVICE_ENROLLMENT_CODE", target=target.username)
    return {"code": code, "username": target.username, "expires_minutes": 15}


@app.post("/api/devices/enroll")
def enroll_device(body: EnrollIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username).first()
    bad = HTTPException(401, "Invalid credentials or enrollment code")
    if not user:
        verify_password(body.password, DUMMY_HASH)
        raise bad
    if user.is_frozen or lock_remaining(user):
        raise bad
    if not verify_password(body.password, user.password_hash):
        register_failure(db, user)
        raise bad
    dev = (db.query(Device).filter_by(user_id=user.id, status="pending", code_hash=hash_code(body.code)).first())
    if not dev or not dev.code_expires or dev.code_expires < utcnow():
        register_failure(db, user)
        raise bad
    dev.status, dev.code_hash = "active", None
    db.commit()
    audit.log("device_enrolled", user.username, device_type=dev.device_type)
    token = create_token({"did": dev.id, "uid": user.id}, 60 * 24 * 365, "device")
    return {"device_token": token, "device_type": dev.device_type}


@app.get("/api/admin/devices")
def list_devices(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    names = {u.id: u.username for u in db.query(User).all()}
    return [{"id": d.id, "username": names.get(d.user_id, "?"), "device_type": d.device_type, "status": d.status}
            for d in db.query(Device).order_by(Device.id.desc()).limit(50).all()]


@app.post("/api/admin/devices/{did}/revoke")
def revoke_device(did: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    dev = db.get(Device, did)
    if not dev:
        raise HTTPException(404, "Device not found")
    dev.status, dev.code_hash = "revoked", None
    db.commit()
    audit.log("admin_action", admin.username, action="DEVICE_REVOKED", target=str(did))
    return {"id": did, "status": "revoked"}


# ---------- IP blacklist ----------
class BlacklistIn(BaseModel):
    cidr: str
    reason: str = ""


@app.get("/api/admin/blacklist")
def list_blacklist(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = [{"id": e.id, "cidr": e.cidr, "reason": e.reason} for e in db.query(BlacklistEntry).order_by(BlacklistEntry.id.desc()).all()]
    return rows + [{"id": None, "cidr": ip, "reason": "from config/env"} for ip in sorted(config.BLACKLISTED_IPS)]


@app.post("/api/admin/blacklist", status_code=201)
def add_blacklist(body: BlacklistIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        net = str(ipaddress.ip_network(body.cidr.strip(), strict=False))
    except ValueError:
        raise HTTPException(400, "Enter a valid IP address or CIDR range, e.g. 198.51.100.0/24")
    if db.query(BlacklistEntry).filter_by(cidr=net).first():
        raise HTTPException(409, "Already blacklisted")
    db.add(BlacklistEntry(cidr=net, reason=body.reason[:200]))
    db.commit()
    audit.log("admin_action", admin.username, action="BLACKLIST_ADD", target=net)
    return {"cidr": net}


@app.delete("/api/admin/blacklist/{eid}")
def remove_blacklist(eid: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    entry = db.get(BlacklistEntry, eid)
    if not entry:
        raise HTTPException(404, "Entry not found")
    db.delete(entry)
    db.commit()
    audit.log("admin_action", admin.username, action="BLACKLIST_REMOVE", target=entry.cidr)
    return {"removed": entry.cidr}
