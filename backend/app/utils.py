from datetime import datetime, timezone
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def now_ist() -> datetime:
    return datetime.now(IST)


def lock_remaining(user) -> int:
    """Seconds left on an account lock (0 if not locked)."""
    if user.locked_until and user.locked_until > utcnow():
        return int((user.locked_until - utcnow()).total_seconds()) + 1
    return 0
