"""
Suricata rule parser - classifies rules as general vs asset-specific,
counts active rules, and maps rules to protected assets.
"""

import re
import os
import ipaddress

RULES_DIR = os.environ.get("SURICATA_RULES_DIR", "/var/lib/suricata/rules")
RULES_FILE = os.path.join(RULES_DIR, "suricata.rules")
LOCAL_FILE = os.path.join(RULES_DIR, "local.rules")
INTERNAL_NET = ipaddress.ip_network("10.0.0.0/8")

# Regex patterns
SID_RE = re.compile(r"sid:\s*(\d+)")
MSG_RE = re.compile(r'msg:"([^"]+)"')
CLASSTYPE_RE = re.compile(r"classtype:\s*(\S+?);")
DEST_PORT_RE = re.compile(r"->\s+\S+\s+(\S+)\s+\(")
IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
SEVERITY_RE = re.compile(r"signature_severity\s+(\w+)")
DEST_VAR_RE = re.compile(r"->\s+(\$\w+)")

# Port-to-service mapping
PORT_SERVICE = {
    "22": "SSH", "23": "Telnet", "25": "SMTP", "53": "DNS", "80": "HTTP",
    "110": "POP3", "135": "RPC/DCOM", "139": "NetBIOS", "143": "IMAP",
    "161": "SNMP", "389": "LDAP", "443": "HTTPS", "445": "SMB",
    "993": "IMAPS", "995": "POP3S", "1433": "MSSQL", "1521": "Oracle",
    "3306": "MySQL", "3389": "RDP", "5432": "PostgreSQL", "5900": "VNC",
    "6379": "Redis", "8080": "HTTP-Alt", "8443": "HTTPS-Alt", "27017": "MongoDB",
}

# Server variable mapping
SERVER_VARS = {
    "$HTTP_SERVERS": {"ports": ["80", "443", "8080", "8443"], "service": "Web Server"},
    "$SQL_SERVERS": {"ports": ["3306", "1433", "5432", "1521"], "service": "Database"},
    "$DNS_SERVERS": {"ports": ["53"], "service": "DNS Server"},
    "$SMTP_SERVERS": {"ports": ["25", "587"], "service": "Mail Server"},
    "$TELNET_SERVERS": {"ports": ["23"], "service": "Telnet Server"},
}


def parse_rule(line):
    """Parse a single Suricata rule line into a structured dict."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if not line.startswith(("alert ", "drop ", "reject ", "pass ")):
        return None

    action = line.split()[0]
    sid_m = SID_RE.search(line)
    msg_m = MSG_RE.search(line)
    cls_m = CLASSTYPE_RE.search(line)
    port_m = DEST_PORT_RE.search(line)
    sev_m = SEVERITY_RE.search(line)
    dest_var_m = DEST_VAR_RE.search(line)

    sid = int(sid_m.group(1)) if sid_m else 0
    msg = msg_m.group(1) if msg_m else ""

    # Find specific IPs in the rule
    ips_in_rule = IP_RE.findall(line.split("(")[0]) if "(" in line else IP_RE.findall(line)
    internal_ips = []
    for ip_str in ips_in_rule:
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr in INTERNAL_NET:
                internal_ips.append(ip_str)
        except ValueError:
            pass

    # Determine target port and service
    dest_port = port_m.group(1) if port_m else "any"
    dest_var = dest_var_m.group(1) if dest_var_m else ""
    services = []
    if dest_port in PORT_SERVICE:
        services.append(PORT_SERVICE[dest_port])
    if dest_var in SERVER_VARS:
        services.append(SERVER_VARS[dest_var]["service"])

    # Classify: asset-specific if it mentions specific IPs or is a NOTICE ASSET rule
    is_asset_specific = bool(internal_ips) or msg.startswith("NOTICE ASSET")
    is_custom = sid >= 1000000 and sid < 2000000

    # Category from message prefix
    category = ""
    if msg.startswith("NOTICE "):
        parts = msg.split(" ", 2)
        if len(parts) >= 2:
            category = parts[1]

    return {
        "sid": sid,
        "action": action,
        "msg": msg,
        "classtype": cls_m.group(1) if cls_m else "",
        "severity": sev_m.group(1) if sev_m else "",
        "dest_port": dest_port,
        "dest_var": dest_var,
        "services": services,
        "internal_ips": internal_ips,
        "is_asset_specific": is_asset_specific,
        "is_custom": is_custom,
        "category": category,
    }


# Module-level caches (rules don't change during runtime)
_RULE_STATS_CACHE = None
_RULE_STATS_MTIME = 0
_ASSET_RULES_INDEX = None  # ip -> list of rules
_RULE_BY_SID = None        # sid -> {raw_line, source, parsed dict}
_RULE_BY_SID_MTIME = 0


def _get_rule_files_mtime():
    """Get max mtime of all rule files for cache invalidation."""
    mtime = 0
    for filepath in [RULES_FILE, LOCAL_FILE]:
        if os.path.exists(filepath):
            mtime = max(mtime, os.path.getmtime(filepath))
    return mtime


def get_rule_stats():
    """Get comprehensive rule statistics. Cached at module level."""
    global _RULE_STATS_CACHE, _RULE_STATS_MTIME, _ASSET_RULES_INDEX

    current_mtime = _get_rule_files_mtime()
    if _RULE_STATS_CACHE is not None and current_mtime <= _RULE_STATS_MTIME:
        return _RULE_STATS_CACHE

    general_rules = 0
    asset_specific_rules = 0
    custom_rules = 0
    total_active = 0
    total_disabled = 0
    asset_rules_detail = []
    rules_by_service = {}
    rules_by_category = {}
    rules_by_action = {}
    server_var_counts = {}
    asset_rules_index = {}  # ip -> [rules]

    for filepath in [RULES_FILE, LOCAL_FILE]:
        if not os.path.exists(filepath):
            continue
        source = "local" if filepath == LOCAL_FILE else "et_pro"
        try:
            with open(filepath, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("#"):
                        # Check if it's a disabled rule (starts with # alert/drop)
                        inner = line.lstrip("# ")
                        if inner.startswith(("alert ", "drop ", "reject ", "pass ")):
                            total_disabled += 1
                        continue

                    rule = parse_rule(line)
                    if not rule:
                        continue

                    total_active += 1
                    rules_by_action[rule["action"]] = rules_by_action.get(rule["action"], 0) + 1

                    if rule["is_custom"]:
                        custom_rules += 1

                    if rule["is_asset_specific"]:
                        asset_specific_rules += 1
                        rule_summary = {
                            "sid": rule["sid"],
                            "msg": rule["msg"],
                            "target_ips": rule["internal_ips"],
                            "services": rule["services"],
                            "dest_port": rule["dest_port"],
                            "category": rule["category"],
                            "source": source,
                        }
                        asset_rules_detail.append(rule_summary)
                        # Index by target IP for fast lookup
                        for ip in rule["internal_ips"]:
                            asset_rules_index.setdefault(ip, []).append(rule_summary)
                    else:
                        general_rules += 1

                    # Count by server variable
                    if rule["dest_var"] in SERVER_VARS:
                        v = rule["dest_var"]
                        server_var_counts[v] = server_var_counts.get(v, 0) + 1

                    # Count by service
                    for svc in rule["services"]:
                        rules_by_service[svc] = rules_by_service.get(svc, 0) + 1

                    # Count by category (custom rules only)
                    if rule["category"]:
                        rules_by_category[rule["category"]] = rules_by_category.get(rule["category"], 0) + 1

        except (IOError, PermissionError):
            continue

    result = {
        "total_active": total_active,
        "total_disabled": total_disabled,
        "general_rules": general_rules,
        "asset_specific_rules": asset_specific_rules,
        "custom_rules": custom_rules,
        "et_pro_rules": total_active - custom_rules,
        "rules_by_action": rules_by_action,
        "rules_by_service": dict(sorted(rules_by_service.items(), key=lambda x: -x[1])),
        "rules_by_category": dict(sorted(rules_by_category.items(), key=lambda x: -x[1])),
        "server_var_counts": server_var_counts,
        "asset_rules": asset_rules_detail,
    }
    _RULE_STATS_CACHE = result
    _RULE_STATS_MTIME = current_mtime
    _ASSET_RULES_INDEX = asset_rules_index
    return result


def _build_sid_index():
    """Walk both rule files + the user_rules DB table and build a sid → rule map.
    Cached at module level; invalidated when any source file's mtime changes.
    """
    global _RULE_BY_SID, _RULE_BY_SID_MTIME

    current_mtime = _get_rule_files_mtime()
    if _RULE_BY_SID is not None and current_mtime <= _RULE_BY_SID_MTIME:
        return _RULE_BY_SID

    index = {}
    for filepath in [RULES_FILE, LOCAL_FILE]:
        if not os.path.exists(filepath):
            continue
        # 'local' = NOTICE-managed; 'et_pro' = upstream feed (default suricata.rules)
        source = "local" if filepath == LOCAL_FILE else "et_pro"
        try:
            with open(filepath, "r", errors="ignore") as f:
                for line in f:
                    line_stripped = line.strip()
                    if not line_stripped:
                        continue
                    is_disabled = False
                    if line_stripped.startswith("#"):
                        inner = line_stripped.lstrip("# ")
                        if inner.startswith(("alert ", "drop ", "reject ", "pass ")):
                            line_stripped = inner
                            is_disabled = True
                        else:
                            continue
                    parsed = parse_rule(line_stripped)
                    if not parsed or not parsed.get("sid"):
                        continue
                    index[parsed["sid"]] = {
                        "sid": parsed["sid"],
                        "msg": parsed["msg"],
                        "action": parsed["action"],
                        "classtype": parsed["classtype"],
                        "category": parsed.get("category", ""),
                        "is_asset_specific": parsed.get("is_asset_specific", False),
                        "is_custom": parsed.get("is_custom", False),
                        "raw_line": line_stripped,
                        "source": source,
                        "enabled": not is_disabled,
                        "internal_ips": parsed.get("internal_ips", []),
                        "services": parsed.get("services", []),
                    }
        except (IOError, PermissionError):
            continue

    # Pull NOTICE user-defined rules from the DB (managed via the Rule Manager UI).
    # These don't live in the .rules files until "Apply" runs, so they need a
    # separate sweep so analysts see the rule text in incident events even
    # before it's been written to disk.
    try:
        from db import get_db
        conn = get_db()
        rows = conn.execute(
            "SELECT sid, msg, action, classtype, raw_rule, enabled "
            "FROM user_rules"
        ).fetchall()
        conn.close()
        for r in rows:
            sid = r["sid"]
            if not sid or sid in index:
                continue
            # Synthesize a representation similar to the file-derived rules
            index[sid] = {
                "sid": sid,
                "msg": r["msg"] or "",
                "action": r["action"] or "alert",
                "classtype": r["classtype"] or "",
                "category": "USER",
                "is_asset_specific": False,
                "is_custom": True,
                "raw_line": r["raw_rule"] or f'(user rule sid={sid}, no raw_rule stored)',
                "source": "notice_user",
                "enabled": bool(r["enabled"]),
                "internal_ips": [],
                "services": [],
            }
    except Exception:
        pass

    _RULE_BY_SID = index
    _RULE_BY_SID_MTIME = current_mtime
    return _RULE_BY_SID


def get_rule_by_sid(sid):
    """Return the rule that matches the given sid, or None.

    Result fields:
      sid, msg, action, classtype, category, raw_line,
      source ('et_pro' / 'local' / 'notice_user'),
      enabled (False if commented out),
      is_asset_specific, is_custom
    """
    if not sid:
        return None
    try:
        sid = int(sid)
    except (TypeError, ValueError):
        return None
    index = _build_sid_index()
    return index.get(sid)


def get_rules_by_sids(sids):
    """Bulk lookup: input list of sids → dict {sid: rule_or_none}."""
    index = _build_sid_index()
    out = {}
    for s in sids:
        try:
            s_int = int(s) if s is not None else None
        except (TypeError, ValueError):
            s_int = None
        out[s] = index.get(s_int) if s_int is not None else None
    return out


def get_rules_for_asset(ip):
    """Get all rules that specifically target or mention this IP. Uses cached index."""
    # Ensure stats (and index) are populated
    get_rule_stats()

    asset_rules = _ASSET_RULES_INDEX.get(ip, []) if _ASSET_RULES_INDEX else []

    # Determine asset type for server-var inheritance
    from db import get_db
    conn = get_db()
    asset = conn.execute("SELECT * FROM assets WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    asset_type = dict(asset).get("asset_type", "workstation") if asset else "workstation"

    inherited_count = 0
    if asset_type == "server" and _RULE_STATS_CACHE:
        # Server inherits HTTP_SERVERS / SQL_SERVERS / etc. rules
        inherited_count = sum(_RULE_STATS_CACHE.get("server_var_counts", {}).values())

    return {
        "direct_rules": asset_rules,
        "inherited_rules": [],  # Don't return huge list, just count
        "direct_count": len(asset_rules),
        "inherited_count": inherited_count,
    }
