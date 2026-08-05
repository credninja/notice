"""
Input validation helpers for Notice route handlers.
"""

import ipaddress

# Valid enum values for commonly validated fields
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
VALID_INCIDENT_STATUSES = frozenset({"open", "investigating", "resolved", "closed"})
VALID_ACTION_STATUSES = frozenset({"open", "in_progress", "completed", "overdue", "cancelled"})
VALID_VERDICTS = frozenset({"true_positive", "false_positive", "investigating"})
VALID_SCOPES = frozenset({"internal", "external"})

# Bounds
MIN_MINUTES = 1
MAX_MINUTES = 10080  # 7 days
MAX_STRING_LEN = 2000
MAX_PAGE_SIZE = 200


def validate_minutes(val, default=60):
    """Parse and clamp minutes parameter. Returns int in [1, 10080]."""
    try:
        m = int(val)
    except (TypeError, ValueError):
        return default
    if m < MIN_MINUTES:
        return MIN_MINUTES
    if m > MAX_MINUTES:
        return MAX_MINUTES
    return m


def validate_ip(val):
    """Validate an IPv4 address string. Returns (ip_str, None) or (None, error_msg)."""
    if not val or not isinstance(val, str):
        return None, "IP address is required"
    val = val.strip()
    try:
        addr = ipaddress.ip_address(val)
        if not isinstance(addr, ipaddress.IPv4Address):
            return None, "Only IPv4 addresses are supported"
        return str(addr), None
    except ValueError:
        return None, f"Invalid IP address: {val}"


def validate_severity(val):
    """Validate severity enum. Returns val if valid, else None."""
    if val in VALID_SEVERITIES:
        return val
    return None


def validate_status(val, valid_set=VALID_INCIDENT_STATUSES):
    """Validate status enum against given set. Returns val if valid, else None."""
    if val in valid_set:
        return val
    return None


def sanitize_string(val, max_len=MAX_STRING_LEN):
    """Sanitize and truncate a string value."""
    if not isinstance(val, str):
        return ""
    return val.strip()[:max_len]


def validate_page_params(query):
    """Extract and validate page/page_size from query params. Returns (page, page_size)."""
    try:
        page = max(1, int(query.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = min(MAX_PAGE_SIZE, max(1, int(query.get("page_size", 50))))
    except (TypeError, ValueError):
        page_size = 50
    return page, page_size
