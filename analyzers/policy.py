"""
Policy rule evaluation engine.
Evaluates configured policy rules against eve.json events.
"""

import json
from collections import defaultdict
from eve_reader import iter_events, is_internal


def evaluate_policies(rules, minutes=None):
    """
    Evaluate policy rules against events, return violations.
    Deduplicates by (rule_id, src_ip, dest_ip).
    """
    # Parse rule configs
    active_rules = []
    for rule in rules:
        if not rule["enabled"]:
            continue
        config = json.loads(rule["config"]) if isinstance(rule["config"], str) else rule["config"]
        active_rules.append({
            "id": rule["id"],
            "name": rule["name"],
            "rule_type": rule["rule_type"],
            "config": config,
            "severity": rule["severity"],
        })

    if not active_rules:
        return []

    # Determine which event types we need
    needed_types = set()
    for r in active_rules:
        rt = r["rule_type"]
        if rt == "plaintext_protocol":
            needed_types.update(r["config"].get("event_types", []))
        elif rt == "weak_snmp":
            needed_types.add("snmp")
        elif rt == "unauthorized_service":
            needed_types.update(r["config"].get("event_types", []))
        elif rt == "deprecated_tls":
            needed_types.add("tls")

    # Collect violations, deduplicate by (rule_id, src, dst)
    seen = defaultdict(lambda: {"count": 0, "first_ts": None, "last_ts": None, "details": []})

    for ev in iter_events(event_types=needed_types, minutes=minutes):
        etype = ev["event_type"]
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        ts = ev.get("timestamp", "")

        for rule in active_rules:
            violation = _check_rule(rule, ev, etype, src, dst)
            if violation:
                key = (rule["id"], src, dst)
                entry = seen[key]
                entry["count"] += 1
                if not entry["first_ts"]:
                    entry["first_ts"] = ts
                entry["last_ts"] = ts
                if len(entry["details"]) < 3:
                    entry["details"].append(violation)
                entry["rule"] = rule

    # Build violation list
    violations = []
    for (rule_id, src, dst), info in seen.items():
        rule = info["rule"]
        violations.append({
            "rule_id": rule_id,
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "src_ip": src,
            "dest_ip": dst,
            "count": info["count"],
            "first_seen": info["first_ts"],
            "last_seen": info["last_ts"],
            "event_type": info["details"][0].get("event_type", "") if info["details"] else "",
            "detail": json.dumps(info["details"][:3]),
            "src_internal": is_internal(src),
            "dest_internal": is_internal(dst),
        })

    violations.sort(key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4),
        -x["count"]
    ))

    return violations


def _check_rule(rule, ev, etype, src, dst):
    """Check if a single event violates a rule. Returns detail dict or None."""
    rt = rule["rule_type"]
    config = rule["config"]

    if rt == "plaintext_protocol":
        if etype in config.get("event_types", []):
            ports = config.get("ports", [])
            if ports and ev.get("dest_port") not in ports:
                return None
            detail = {"event_type": etype}
            if etype == "http":
                http = ev.get("http", {})
                detail["hostname"] = http.get("hostname", "")
                detail["url"] = http.get("url", "")
            elif etype == "ftp":
                ftp = ev.get("ftp", {})
                detail["command"] = ftp.get("command", "")
            elif etype == "smtp":
                smtp = ev.get("smtp", {})
                detail["helo"] = smtp.get("helo", "")
            return detail

    elif rt == "weak_snmp":
        if etype == "snmp":
            snmp = ev.get("snmp", {})
            community = snmp.get("community", "").lower()
            blocked = [c.lower() for c in config.get("blocked_communities", [])]
            if community in blocked:
                return {
                    "event_type": "snmp",
                    "community": snmp.get("community", ""),
                    "version": snmp.get("version"),
                    "pdu_type": snmp.get("pdu_type", ""),
                }

    elif rt == "unauthorized_service":
        if etype in config.get("event_types", []):
            return {"event_type": etype}

    elif rt == "deprecated_tls":
        if etype == "tls":
            tls = ev.get("tls", {})
            version = tls.get("version", "")
            if version in config.get("blocked_versions", []):
                return {
                    "event_type": "tls",
                    "version": version,
                    "sni": tls.get("sni", ""),
                }

    return None
