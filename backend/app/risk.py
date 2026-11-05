from . import config
from .utils import utcnow


def _allowed_days(user):
    return [int(d) for d in (user.allowed_days or "").split(",") if d.strip() != ""]


def basic_risk(user, ctx: dict, prior_failed: int):
    """Stage 1: contextual score from 0.0 to 1.0 with human-readable reasons."""
    score, reasons = 0.0, []
    if ctx["is_new_device"]:
        score += 0.25
        reasons.append("Unrecognized device fingerprint (new browser or user-agent)")
    if ctx["is_new_ip"]:
        score += 0.20
        reasons.append("Login from a new IP address")
    if ctx["hour"] < user.work_start or ctx["hour"] >= user.work_end:
        score += 0.20
        reasons.append("Login outside normal working hours")
    if ctx["weekday"] not in _allowed_days(user):
        score += 0.15
        reasons.append("Login outside permitted schedule (allowed days: %s)" % user.allowed_days)
    if prior_failed:
        score += min(prior_failed, 3) * 0.10
        reasons.append(f"{prior_failed} recent failed attempt(s)")
    return round(min(score, 1.0), 2), reasons


def is_impossible_travel(user, current_country: str) -> bool:
    if not (user.last_login_at and user.last_login_country and current_country):
        return False
    hours = (utcnow() - user.last_login_at).total_seconds() / 3600
    return current_country != user.last_login_country and hours < config.IMPOSSIBLE_TRAVEL_HOURS


def advanced_risk(ctx: dict, user) -> dict:
    """Stage 2: hard threat signals that block immediately."""
    if ctx["ip"] in config.BLACKLISTED_IPS:
        return {"action": "BLOCKED", "risk_level": "CRITICAL",
                "reason": f"IP address {ctx['ip']} is on the organisation's security blacklist."}
    if ctx["country"] in config.RESTRICTED_COUNTRIES:
        return {"action": "BLOCKED", "risk_level": "CRITICAL",
                "reason": f"Login from restricted geography ({ctx['country']})."}
    if is_impossible_travel(user, ctx["country"]):
        return {"action": "BLOCKED", "risk_level": "HIGH",
                "reason": f"Impossible travel: previous login from {user.last_login_country} was too recent."}
    if ctx["is_new_device"] and ctx["is_new_ip"] and (ctx["hour"] < 6 or ctx["hour"] >= 22):
        return {"action": "BLOCKED", "risk_level": "HIGH",
                "reason": "Simultaneous anomalies: unrecognised device + new IP + unusual hour."}
    return {"action": "ALLOW", "risk_level": "LOW", "reason": ""}
