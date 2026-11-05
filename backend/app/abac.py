from . import config


def _deny(rule: int, reason: str) -> dict:
    return {"decision": "DENIED", "rule": rule, "reason": f"ABAC Rule {rule}: {reason}"}


def check_abac(user, res: dict, ctx: dict, dual_auth_approved: bool = False):
    """Evaluate the six ABAC rules in priority order. Returns None if all pass."""
    sens = res["sensitivity"]
    allowed_days = [int(d) for d in (user.allowed_days or "").split(",") if d.strip() != ""]

    # Rule 1: working hours
    if ctx["hour"] < user.work_start or ctx["hour"] >= user.work_end:
        return _deny(1, f"Working hours violation (allowed {user.work_start}:00-{user.work_end}:00)")

    # Rule 2: department match (admins need just-in-time dual authorization)
    if res["department"] != "General" and user.department != res["department"]:
        if user.role in ("admin", "superuser"):
            if not dual_auth_approved:
                return {"decision": "PENDING_DUAL_AUTH", "rule": 2,
                        "reason": "Cross-department access needs approval from another administrator"}
        else:
            return _deny(2, "Department access violation")

    # Rule 3: trusted network for sensitive resources
    if sens >= 2 and not ctx["trusted_network"]:
        return _deny(3, "Untrusted network for a sensitive resource")

    # Rule 4: managed device for sensitive resources
    if sens >= 2 and ctx["device_type"] not in config.MANAGED_DEVICES:
        return _deny(4, "Device policy violation (managed device required)")

    # Rule 5: day of week
    if ctx["weekday"] not in allowed_days:
        return _deny(5, f"Day-of-week restriction (allowed days: {user.allowed_days})")

    # Rule 6: hierarchical clearance
    if user.clearance_level < sens:
        return _deny(6, "Clearance level insufficient")

    return None
