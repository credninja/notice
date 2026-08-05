"""
Sigma rule converter — parse Sigma YAML and convert to Suricata rules.

Supports a subset of Sigma network-oriented rules:
  - logsource.category mapping to Suricata protocol
  - detection field mapping to Suricata keywords (content, dns.query, http.uri, etc.)
  - SID assignment from range 9000000+
  - level → severity / classtype mapping

Unconvertible rules are flagged with a conversion_log explaining what failed.
"""

import os
import re
from datetime import datetime

import yaml

from db import get_db, close_db

# SID range for Sigma-converted rules (clear of ET, user, and local SIDs)
SIGMA_SID_BASE = 9_000_000

# Output file for deployed Sigma rules
SIGMA_RULES_FILE = os.environ.get(
    "SIGMA_RULES_FILE",
    "/var/lib/suricata/rules/sigma.rules",
)

# Sigma logsource.category → Suricata protocol
CATEGORY_PROTOCOL_MAP = {
    "network_connection": "tcp",
    "firewall": "tcp",
    "dns": "dns",
    "web": "http",
    "proxy": "http",
}

# Sigma level → (Suricata severity int, classtype)
LEVEL_MAP = {
    "critical": (1, "trojan-activity"),
    "high": (1, "attempted-admin"),
    "medium": (2, "misc-attack"),
    "low": (3, "attempted-recon"),
    "informational": (4, "not-suspicious"),
}

# Sigma detection field → Suricata keyword builder
# Each entry maps a Sigma field name to a function that returns a list of
# Suricata keyword strings for a given value.
def _kw_dst_port(value):
    """Map dst_port to a destination port in the rule header (handled separately)."""
    return []

def _kw_src_ip(value):
    return []

def _kw_dst_ip(value):
    return []

def _kw_dns_query(value):
    return [f'dns.query; content:"{value}";']

def _kw_http_uri(value):
    return [f'http.uri; content:"{value}";']

def _kw_http_method(value):
    return [f'http.method; content:"{value}";']

def _kw_http_user_agent(value):
    return [f'http.user_agent; content:"{value}";']

def _kw_generic_content(value):
    return [f'content:"{value}";']


FIELD_KEYWORD_MAP = {
    "dst_port": _kw_dst_port,
    "destination.port": _kw_dst_port,
    "src_ip": _kw_src_ip,
    "source.ip": _kw_src_ip,
    "dst_ip": _kw_dst_ip,
    "destination.ip": _kw_dst_ip,
    "dns.query.name": _kw_dns_query,
    "query": _kw_dns_query,
    "http.url": _kw_http_uri,
    "http.uri": _kw_http_uri,
    "cs-uri": _kw_http_uri,
    "http.method": _kw_http_method,
    "cs-method": _kw_http_method,
    "http.user_agent": _kw_http_user_agent,
    "c-useragent": _kw_http_user_agent,
    "cs-user-agent": _kw_http_user_agent,
    "user_agent": _kw_http_user_agent,
}


def parse_sigma_yaml(yaml_text):
    """Parse Sigma YAML text and return the structured dict.

    Raises ValueError on invalid YAML or missing required fields.
    """
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}")

    if not isinstance(data, dict):
        raise ValueError("Sigma rule must be a YAML mapping")

    # Minimal validation — Sigma spec requires title + logsource + detection
    if "title" not in data:
        raise ValueError("Sigma rule missing required field: title")

    return data


def _next_sigma_sid(conn):
    """Return the next available SID in the 9000000+ range."""
    row = conn.execute("SELECT MAX(sid_assigned) AS m FROM sigma_rules WHERE sid_assigned IS NOT NULL").fetchone()
    cur = row["m"] if row and row["m"] else None
    return max(SIGMA_SID_BASE, (cur or SIGMA_SID_BASE - 1) + 1)


def convert_to_suricata(sigma_dict, conn=None):
    """Convert a parsed Sigma rule dict to a Suricata rule string.

    Args:
        sigma_dict: parsed Sigma rule (from parse_sigma_yaml)
        conn: optional DB connection (used to assign SID). If None, uses
              a placeholder SID.

    Returns:
        (suricata_rule_string, conversion_log_string)
        If conversion fails completely, suricata_rule_string will be empty.
    """
    log_lines = []
    title = sigma_dict.get("title", "Sigma Rule")
    description = sigma_dict.get("description", "")
    level = sigma_dict.get("level", "medium").lower()

    # ── Determine protocol from logsource ────────────────────────────────
    logsource = sigma_dict.get("logsource", {}) or {}
    category = (logsource.get("category") or "").lower()
    product = (logsource.get("product") or "").lower()

    protocol = CATEGORY_PROTOCOL_MAP.get(category)
    if not protocol:
        # Try product-based fallback
        if "dns" in product:
            protocol = "dns"
        elif "web" in product or "http" in product or "proxy" in product:
            protocol = "http"
        elif "firewall" in product or "network" in product:
            protocol = "tcp"

    if not protocol:
        log_lines.append(f"WARNING: Cannot map logsource category='{category}' product='{product}' to protocol. Defaulting to 'ip'.")
        protocol = "ip"

    # ── Parse detection block ────────────────────────────────────────────
    detection = sigma_dict.get("detection", {}) or {}
    condition = (detection.get("condition") or "").strip()

    if not detection:
        log_lines.append("ERROR: No detection block found.")
        return "", "\n".join(log_lines)

    # Extract selection(s)
    selection = detection.get("selection", {}) or {}
    filter_block = detection.get("filter", {}) or {}

    # Determine if we use "selection and not filter"
    use_filter = False
    if condition:
        if "not filter" in condition.lower() or "not 1 of filter" in condition.lower():
            use_filter = True

    if not selection and not condition:
        log_lines.append("ERROR: No selection in detection block and no condition specified.")
        return "", "\n".join(log_lines)

    # If selection is empty but condition references something else, try to find it
    if not selection:
        for key in detection:
            if key not in ("condition", "filter", "timeframe") and isinstance(detection[key], dict):
                selection = detection[key]
                log_lines.append(f"INFO: Using detection key '{key}' as selection.")
                break

    if not selection:
        log_lines.append("ERROR: Could not identify any selection fields in detection block.")
        return "", "\n".join(log_lines)

    # ── Map fields to Suricata keywords ──────────────────────────────────
    keywords = []
    src_ip = "any"
    dst_ip = "any"
    src_port = "any"
    dst_port = "any"
    unmapped_fields = []

    for field, value in selection.items():
        field_lower = field.lower()

        # Handle list values (OR logic in Sigma) — take first for now, log the rest
        values = value if isinstance(value, list) else [value]

        mapper = FIELD_KEYWORD_MAP.get(field_lower)

        if mapper is not None:
            # Special header-level fields
            if field_lower in ("dst_port", "destination.port"):
                dst_port = str(values[0])
                if len(values) > 1:
                    log_lines.append(f"WARNING: Multiple dst_port values; using first: {dst_port}")
            elif field_lower in ("src_ip", "source.ip"):
                src_ip = str(values[0])
                if len(values) > 1:
                    log_lines.append(f"WARNING: Multiple src_ip values; using first: {src_ip}")
            elif field_lower in ("dst_ip", "destination.ip"):
                dst_ip = str(values[0])
                if len(values) > 1:
                    log_lines.append(f"WARNING: Multiple dst_ip values; using first: {dst_ip}")
            else:
                for v in values:
                    kw_list = mapper(str(v))
                    keywords.extend(kw_list)
        else:
            # Unknown field — try generic content match
            for v in values:
                if v is not None and str(v).strip():
                    keywords.append(f'content:"{v}";')
            unmapped_fields.append(field)

    if unmapped_fields:
        log_lines.append(f"WARNING: Fields mapped as generic content (no specific Suricata keyword): {', '.join(unmapped_fields)}")

    # ── Negated filter handling ──────────────────────────────────────────
    negated_keywords = []
    if use_filter and filter_block:
        for field, value in filter_block.items():
            values = value if isinstance(value, list) else [value]
            for v in values:
                if v is not None and str(v).strip():
                    negated_keywords.append(f'content:!"{v}";')
        log_lines.append(f"INFO: Applied {len(negated_keywords)} negated content matches from filter block.")

    # ── SID assignment ───────────────────────────────────────────────────
    own_conn = False
    if conn is None:
        conn = get_db()
        own_conn = True
    try:
        sid = _next_sigma_sid(conn)
    finally:
        if own_conn:
            close_db(conn)

    # ── Severity and classtype ───────────────────────────────────────────
    severity, classtype = LEVEL_MAP.get(level, (2, "misc-attack"))

    # ── Build Suricata rule ──────────────────────────────────────────────
    # Escape quotes in title for msg
    msg = title.replace('"', '\\"')

    all_keywords = keywords + negated_keywords
    keyword_str = " ".join(all_keywords)

    # Build rule options
    options_parts = [
        f'msg:"SIGMA - {msg}";',
    ]
    if keyword_str:
        options_parts.append(keyword_str)
    options_parts.extend([
        f"classtype:{classtype};",
        f"sid:{sid};",
        "rev:1;",
    ])

    options = " ".join(options_parts)

    # Rule header
    action = "alert"
    rule = f'{action} {protocol} {src_ip} {src_port} -> {dst_ip} {dst_port} ({options})'

    if not keywords and not negated_keywords:
        log_lines.append("WARNING: No content keywords generated. Rule may be overly broad.")

    log_lines.append(f"OK: Converted to Suricata rule with SID {sid}, protocol={protocol}, severity={severity}.")

    return rule, "\n".join(log_lines)


def import_sigma_file(yaml_text):
    """Import a Sigma YAML rule into the database.

    Parses the YAML, attempts conversion, and stores everything in sigma_rules.

    Returns:
        dict with import result (id, title, converted, suricata_rule, conversion_log)

    Raises:
        ValueError if YAML is invalid or missing required fields.
    """
    sigma_dict = parse_sigma_yaml(yaml_text)

    title = sigma_dict.get("title", "Untitled Sigma Rule")
    sigma_id = sigma_dict.get("id", "")
    description = sigma_dict.get("description", "")
    level = sigma_dict.get("level", "medium")
    status = sigma_dict.get("status", "active")
    author = sigma_dict.get("author", "")
    logsource = yaml.dump(sigma_dict.get("logsource", {})) if sigma_dict.get("logsource") else ""

    conn = get_db()
    try:
        # Attempt conversion
        suricata_rule = ""
        conversion_log = ""
        sid_assigned = None
        converted = False

        try:
            suricata_rule, conversion_log = convert_to_suricata(sigma_dict, conn=conn)
            if suricata_rule:
                # Extract SID from the generated rule
                sid_match = re.search(r"sid:(\d+);", suricata_rule)
                if sid_match:
                    sid_assigned = int(sid_match.group(1))
                converted = True
        except Exception as exc:
            conversion_log = f"ERROR: Conversion failed: {exc}"

        cur = conn.execute(
            """INSERT INTO sigma_rules
               (title, sigma_id, description, level, status, author, logsource,
                yaml_content, suricata_rule, conversion_log, sid_assigned, enabled)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (title, sigma_id, description, level, status, author, logsource,
             yaml_text, suricata_rule, conversion_log, sid_assigned, 1),
        )
        rule_id = cur.lastrowid
        conn.commit()

        return {
            "id": rule_id,
            "title": title,
            "sigma_id": sigma_id,
            "level": level,
            "converted": converted,
            "suricata_rule": suricata_rule,
            "conversion_log": conversion_log,
            "sid_assigned": sid_assigned,
        }
    finally:
        close_db(conn)


def deploy_sigma_rules():
    """Write all enabled + converted Sigma rules to the sigma.rules file.

    Returns:
        dict with deployment result (rules_written, filepath)
    """
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM sigma_rules WHERE enabled = 1 AND suricata_rule != '' "
            "ORDER BY sid_assigned ASC"
        ).fetchall()

        rules_lines = [
            "# NOTICE Sigma-converted rules",
            f"# Auto-generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"# Total rules: {len(rows)}",
            "",
        ]

        for row in rows:
            r = dict(row)
            rules_lines.append(f"# Sigma: {r.get('title', 'unknown')} (level={r.get('level', 'medium')})")
            rules_lines.append(r["suricata_rule"])
            rules_lines.append("")

        # Ensure parent directory exists
        rules_dir = os.path.dirname(SIGMA_RULES_FILE)
        if rules_dir:
            os.makedirs(rules_dir, exist_ok=True)

        with open(SIGMA_RULES_FILE, "w") as f:
            f.write("\n".join(rules_lines))

        return {
            "ok": True,
            "rules_written": len(rows),
            "filepath": SIGMA_RULES_FILE,
        }
    finally:
        close_db(conn)
