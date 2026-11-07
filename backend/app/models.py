from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from .database import Base
from .utils import utcnow


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)

    # ABAC attributes
    role = Column(String, default="user")            # user, admin, superuser
    department = Column(String, default="General")
    clearance_level = Column(Integer, default=1)     # 1=Low, 2=Med, 3=High
    work_start = Column(Integer, default=9)
    work_end = Column(Integer, default=17)
    allowed_days = Column(String, default="0,1,2,3,4")  # 0=Mon ... 6=Sun

    # MFA
    totp_secret = Column(String, nullable=True)
    totp_enabled = Column(Boolean, default=False)

    # Risk / behaviour metadata
    login_risk_score = Column(Float, nullable=True)
    last_login_country = Column(String(2), nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    known_devices = Column(Text, default="")
    known_ips = Column(Text, default="")
    failed_attempts = Column(Integer, default=0)
    violation_count = Column(Integer, default=0)
    request_burst_count = Column(Integer, default=0)
    burst_window_start = Column(DateTime, nullable=True)

    # Protection state
    locked_until = Column(DateTime, nullable=True)
    is_frozen = Column(Boolean, default=False)       # global kill-switch
    token_version = Column(Integer, default=0)       # bump to kill all sessions


class AccessRequest(Base):
    """Just-in-time dual authorization for admins crossing departments."""
    __tablename__ = "access_requests"
    id = Column(Integer, primary_key=True)
    requester_id = Column(Integer, index=True)
    requester_name = Column(String)
    resource_id = Column(Integer)
    status = Column(String, default="pending")       # pending/approved/rejected/used
    decided_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=utcnow)


class Device(Base):
    """Enrolled managed device. The browser holds a signed token that points at this row."""
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True)
    device_type = Column(String)                     # Corporate Laptop / Corporate Desktop
    status = Column(String, default="pending")       # pending / active / revoked
    code_hash = Column(String, nullable=True)        # hash of the one-time enrollment code
    code_expires = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)


class BlacklistEntry(Base):
    __tablename__ = "ip_blacklist"
    id = Column(Integer, primary_key=True)
    cidr = Column(String, unique=True)               # single IP or CIDR range
    reason = Column(String, default="")
    created_at = Column(DateTime, default=utcnow)
