"""
NIST CSF 2.0 data aggregator.
Structures existing detection data into Govern, Identify, Protect, Detect, Respond, Recover.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from analyzers.drilldown import compute_drilldown
from analyzers.plaintext import detect_plaintext
from analyzers.anomaly import detect_anomalies
from analyzers.policy import evaluate_policies
from eve_reader import iter_events, is_internal, is_ipv4
from db import get_db


def compute_nist(minutes=1440):
    """Compute NIST CSF 2.0 structured data from all available sources."""

    # Core data from existing analyzers
    dd = compute_drilldown(minutes)
    anomalies = detect_anomalies(minutes)
    plaintext = detect_plaintext(minutes)

    # DB queries
    conn = get_db()
    asset_rows = conn.execute("SELECT * FROM assets").fetchall()
    assets = [dict(r) for r in asset_rows]
    asset_map = {a["ip"]: a for a in assets}

    incident_rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
    incidents = [dict(r) for r in incident_rows]

    action_rows = conn.execute("SELECT * FROM action_items ORDER BY created_at DESC").fetchall()
    actions = [dict(r) for r in action_rows]

    policy_rows = conn.execute("SELECT * FROM policy_rules WHERE enabled = 1").fetchall()
    policy_rules = [dict(r) for r in policy_rows]

    # MTTR
    mttr_row = conn.execute(
        "SELECT COUNT(*) as cnt, AVG(julianday(updated_at) - julianday(created_at)) * 24 as avg_hrs "
        "FROM incidents WHERE status IN ('resolved','closed')"
    ).fetchone()
    mttr_hours = round(mttr_row["avg_hrs"], 1) if mttr_row["avg_hrs"] else None
    mttr_count = mttr_row["cnt"]

    # Incident notes for recover
    notes_by_inc = defaultdict(list)
    note_rows = conn.execute("SELECT incident_id, content, created_at FROM incident_notes ORDER BY created_at").fetchall()
    for n in note_rows:
        notes_by_inc[n["incident_id"]].append({"content": n["content"], "created_at": n["created_at"]})

    conn.close()

    # Policy violations
    violations = evaluate_policies(policy_rules, minutes=minutes)

    # Asset discovery data (lightweight — just counts from drilldown)
    active_internal = set()
    active_external = set()
    new_assets_24h = []
    now = datetime.now().astimezone()
    cutoff_24h = now - timedelta(hours=24)

    for ev in iter_events(event_types={"flow"}, minutes=minutes):
        src, dst = ev.get("src_ip", ""), ev.get("dest_ip", "")
        if not is_ipv4(src) or not is_ipv4(dst):
            continue
        for ip in (src, dst):
            if is_internal(ip):
                active_internal.add(ip)
            elif not ip.startswith("224.") and not ip.startswith("255."):
                active_external.add(ip)

    identified_internal = sum(1 for ip in active_internal if ip in asset_map)
    unidentified_internal = [ip for ip in active_internal if ip not in asset_map]
    identified_external = sum(1 for ip in active_external if ip in asset_map)
    shadow_it = [ip for ip in unidentified_internal if ip in {a["src_ip"] for a in dd["q1"]["alerts"]}]

    # Posture score
    total_active = len(active_internal) or 1
    total_alerts = dd["q1"]["total"] or 1
    total_actions_count = len(actions) or 1
    total_assets_count = len(assets) or 1
    total_incidents = len(incidents) or 1

    asset_coverage = min(100, (identified_internal / total_active) * 100) if total_active else 100
    triage_rate = ((dd["q2"]["true_positive"] + dd["q2"]["false_positive"]) / total_alerts * 100) if dd["q1"]["total"] else 100
    sla_compliance = ((len([a for a in actions if a["status"] == "completed" and not a.get("sla_breached")]) / total_actions_count) * 100) if actions else 100
    policy_compliance = max(0, (1 - len(violations) / max(total_assets_count, 1)) * 100)
    incident_closure = (len([i for i in incidents if i["status"] in ("resolved", "closed")]) / total_incidents * 100) if incidents else 100

    posture_score = round(
        asset_coverage * 0.20 +
        triage_rate * 0.20 +
        sla_compliance * 0.20 +
        policy_compliance * 0.20 +
        incident_closure * 0.20
    )

    # Blocked vs allowed
    blocked = sum(1 for a in dd["q1"]["alerts"] if a.get("action") in ("blocked", "dropped"))
    allowed = sum(1 for a in dd["q1"]["alerts"] if a.get("action") in ("allowed", ""))

    # Segmentation score (subnets with alerts / total subnets)
    total_subnets = len(dd["q6"].get("subnet_nodes", []))
    alerted_subnets = sum(1 for s in dd["q6"].get("subnet_nodes", []) if s["has_suspicious"])
    seg_score = round((1 - alerted_subnets / max(total_subnets, 1)) * 100)

    # Recurring patterns (same signature from same IP appearing multiple times)
    sig_counts = defaultdict(int)
    for a in dd["q1"]["alerts"]:
        sig_counts[a["signature"]] += 1
    recurring = [{"signature": sig, "count": c} for sig, c in sorted(sig_counts.items(), key=lambda x: -x[1]) if c >= 3]

    return {
        "generated_at": datetime.now().isoformat(),
        "period_minutes": minutes,
        "posture_score": posture_score,

        "govern": {
            "posture_score": posture_score,
            "score_breakdown": {
                "asset_coverage": round(asset_coverage),
                "triage_rate": round(triage_rate),
                "sla_compliance": round(sla_compliance),
                "policy_compliance": round(policy_compliance),
                "incident_closure": round(incident_closure),
            },
            "sla_total": len(actions),
            "sla_compliant": len([a for a in actions if a["status"] == "completed" and not a.get("sla_breached")]),
            "sla_breached": len([a for a in actions if a.get("sla_breached")]),
            "sla_open": len([a for a in actions if a["status"] in ("open", "in_progress", "overdue")]),
            "policy_violations_total": len(violations),
            "policy_violations_by_rule": _group_violations(violations),
            "asset_gaps": len(unidentified_internal),
            "top_risks": dd.get("q1", {}).get("alerts", [])[:5],
            "breached_actions": [a for a in actions if a.get("sla_breached")][:10],
            "ownership_gaps": unidentified_internal[:15],
        },

        "identify": {
            "total_internal": len(active_internal),
            "total_external": len(active_external),
            "identified_internal": identified_internal,
            "unidentified_internal": len(unidentified_internal),
            "identified_external": identified_external,
            "unidentified_external": len(active_external) - identified_external,
            "coverage_pct": round(asset_coverage),
            "shadow_it_count": len(shadow_it),
            "shadow_it_ips": shadow_it[:20],
            "unidentified_with_traffic": _build_unidentified_list(unidentified_internal, dd),
            "assets_by_type": _count_by_field(assets, "asset_type"),
            "critical_assets": [a for a in assets if a.get("business_critical")],
        },

        "protect": {
            "blocked_count": blocked,
            "allowed_count": allowed,
            "blocked_ratio": round(blocked / max(blocked + allowed, 1) * 100),
            "plaintext_http": plaintext["summary"]["http_connections"],
            "plaintext_ftp": plaintext["summary"]["ftp_events"],
            "deprecated_tls": plaintext["summary"]["tls_deprecated_connections"],
            "weak_snmp": plaintext["summary"]["snmp_weak_connections"],
            "segmentation_score": seg_score,
            "subnet_nodes": dd["q6"].get("subnet_nodes", []),
            "subnet_links": dd["q6"].get("subnet_links", []),
            "unusual_ports": anomalies.get("unusual_ports", [])[:20],
            "exfiltration": dd["q4"].get("exfiltration", []),
            "plaintext_detail": plaintext.get("http", [])[:20],
            "tls_deprecated_detail": plaintext.get("tls_deprecated", [])[:20],
        },

        "detect": {
            "total_alerts": dd["q1"]["total"],
            "by_severity": dd["q1"]["by_severity"],
            "critical_high": dd["q1"]["critical_high"],
            "true_positive": dd["q2"]["true_positive"],
            "false_positive": dd["q2"]["false_positive"],
            "investigating": dd["q2"]["investigating"],
            "recurring_fp": dd["q2"]["recurring_fp"],
            "tp_fp_ratio": f"{dd['q2']['true_positive']}:{dd['q2']['false_positive']}" if dd["q2"]["false_positive"] else f"{dd['q2']['true_positive']}:0",
            "alerts": dd["q1"]["alerts"],
            "repetitive_attackers": dd["q5"]["repetitive_attackers"],
            "targeted_assets": dd["q5"]["targeted_assets"],
            "country_breakdown": dd["q5"]["country_breakdown"],
            "top_country": dd["q5"]["country_breakdown"][0]["country"] if dd["q5"]["country_breakdown"] else "N/A",
            "internal_alerts": dd["q6"]["internal_alerts"],
            "nmap_scanners": dd["q6"]["nmap_scanners"],
            "lateral_movement": dd["q4"]["lateral_movement"],
            "anomaly_summary": anomalies.get("summary", {}),
        },

        "respond": {
            "total_incidents": len(incidents),
            "open_incidents": len([i for i in incidents if i["status"] in ("open", "investigating")]),
            "resolved_incidents": len([i for i in incidents if i["status"] in ("resolved", "closed")]),
            "confirmed_compromises": len([i for i in incidents if i.get("verdict") == "true_positive"]),
            "mttr_hours": mttr_hours,
            "mttr_count": mttr_count,
            "actions_total": len(actions),
            "actions_open": [a for a in actions if a["status"] in ("open", "in_progress")][:15],
            "actions_completed": [a for a in actions if a["status"] == "completed"][:10],
            "sla_breaches": [a for a in actions if a.get("sla_breached")][:10],
            "incidents": incidents[:15],
            "affected_assets": dd["q3"]["affected_assets"],
        },

        "recover": {
            "incidents_with_rca": dd["q8"]["with_rca"],
            "incidents_without_rca": dd["q8"]["without_rca"],
            "rca_completion_pct": round(
                len(dd["q8"]["with_rca"]) / max(len(dd["q8"]["with_rca"]) + len(dd["q8"]["without_rca"]), 1) * 100
            ),
            "lessons_learned": _get_lessons(notes_by_inc, incidents),
            "recurring_patterns": recurring[:10],
            "recurring_count": len(recurring),
            "recommendations": dd["q9"]["recommendations"],
            "breach_reasons": dd["q8"]["breach_reasons"],
        },
    }


def _group_violations(violations):
    by_rule = defaultdict(lambda: {"count": 0, "severity": "medium"})
    for v in violations:
        r = by_rule[v["rule_name"]]
        r["count"] += 1
        r["severity"] = v.get("severity", "medium")
    return [{"rule": k, "count": v["count"], "severity": v["severity"]}
            for k, v in sorted(by_rule.items(), key=lambda x: -x[1]["count"])]


def _build_unidentified_list(ips, dd):
    """Build traffic summary for unidentified IPs from drilldown alert data."""
    alerted = {a["src_ip"] for a in dd["q1"]["alerts"]} | {a["dest_ip"] for a in dd["q1"]["alerts"]}
    result = []
    for ip in sorted(ips):
        result.append({"ip": ip, "has_alerts": ip in alerted})
    result.sort(key=lambda x: (not x["has_alerts"], x["ip"]))
    return result[:30]


def _count_by_field(items, field):
    counts = defaultdict(int)
    for item in items:
        counts[item.get(field, "unknown")] += 1
    return [{"type": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])]


def _get_lessons(notes_by_inc, incidents):
    """Extract lessons learned from incident notes."""
    lessons = []
    for inc in incidents:
        notes = notes_by_inc.get(inc["id"], [])
        if notes:
            lessons.append({
                "incident_id": inc["id"],
                "title": inc["title"],
                "status": inc["status"],
                "notes": [n["content"] for n in notes[-3:]],  # last 3 notes
            })
    return lessons[:10]
