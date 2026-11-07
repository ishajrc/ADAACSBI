import ipaddress


def in_list(ip: str, entries) -> bool:
    """True if ip equals or falls inside any entry (plain IPs or CIDR ranges)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip in entries
    for entry in entries:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            if ip == entry:
                return True
    return False
