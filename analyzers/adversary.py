"""
Adversary profiling engine.
Groups alerts by attacker IP, builds adversary profiles with cross-asset
attack patterns, techniques, and timeline.
"""

from collections import defaultdict
from datetime import datetime
from eve_reader import iter_events, is_internal, is_ipv4
from db import get_db
from analyzers.correlation import SIGNATURE_MAP


def build_adversary_profiles(minutes=None):
    """Build adversary profiles from alert data."""
    attackers = defaultdict(lambda: {
        "ip": "",
        "targets": defaultdict(lambda: {
            "alerts": [],
            "techniques": set(),
            "signatures": set(),
            "first_seen": None,
            "last_seen": None,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }),
        "total_alerts": 0,
        "total_targets": 0,
        "techniques": set(),
        "signatures": set(),
        "first_seen": None,
        "last_seen": None,
        "timeline": [],
    })

    for ev in iter_events(event_types={"alert"}, minutes=minutes):
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        if not is_ipv4(src) or not is_ipv4(dst):
            continue

        # Attacker = external hitting internal, OR internal scanning internal
        attacker_ip = None
        target_ip = None
        if not is_internal(src) and is_internal(dst):
            attacker_ip = src
            target_ip = dst
        elif is_internal(src) and is_internal(dst):
            # Internal lateral movement
            attacker_ip = src
            target_ip = dst

        if not attacker_ip:
            continue

        alert = ev.get("alert", {})
        sig = alert.get("signature", "")
        sev = alert.get("severity", 3)
        ts = ev.get("timestamp", "")
        sid = alert.get("signature_id", 0)

        # Map to MITRE technique
        technique = ""
        sig_lower = sig.lower()
        for mapping in SIGNATURE_MAP:
            if mapping["pattern"] in sig_lower:
                technique = mapping.get("technique_name", "")
                break

        sev_key = {1: "critical", 2: "high", 3: "medium"}.get(sev, "low")

        a = attackers[attacker_ip]
        a["ip"] = attacker_ip
        a["total_alerts"] += 1
        a["techniques"].add(technique or sig[:60])
        a["signatures"].add(sig[:100])

        if not a["first_seen"] or ts < a["first_seen"]:
            a["first_seen"] = ts
        if not a["last_seen"] or ts > a["last_seen"]:
            a["last_seen"] = ts

        # Per-target tracking
        t = a["targets"][target_ip]
        t["severity_counts"][sev_key] += 1
        t["techniques"].add(technique or sig[:60])
        t["signatures"].add(sig[:100])
        if not t["first_seen"] or ts < t["first_seen"]:
            t["first_seen"] = ts
        if not t["last_seen"] or ts > t["last_seen"]:
            t["last_seen"] = ts
        if len(t["alerts"]) < 20:
            t["alerts"].append({
                "timestamp": ts,
                "signature": sig,
                "signature_id": sid,
                "severity": sev,
                "technique": technique,
            })

        if len(a["timeline"]) < 100:
            a["timeline"].append({
                "timestamp": ts,
                "target": target_ip,
                "signature": sig[:80],
                "severity": sev,
            })

    # Enrich with asset info
    conn = get_db()
    asset_rows = conn.execute("SELECT ip, owner, hostname, asset_type, business_critical FROM assets").fetchall()
    conn.close()
    asset_map = {r["ip"]: dict(r) for r in asset_rows}

    # Build output
    profiles = []
    for ip, data in sorted(attackers.items(), key=lambda x: x[1]["total_alerts"], reverse=True):
        targets_list = []
        for tip, tdata in sorted(data["targets"].items(), key=lambda x: sum(x[1]["severity_counts"].values()), reverse=True):
            asset = asset_map.get(tip, {})
            targets_list.append({
                "ip": tip,
                "owner": asset.get("owner", ""),
                "hostname": asset.get("hostname", ""),
                "asset_type": asset.get("asset_type", ""),
                "business_critical": asset.get("business_critical", 0),
                "alert_count": sum(tdata["severity_counts"].values()),
                "severity_counts": tdata["severity_counts"],
                "techniques": list(tdata["techniques"]),
                "signatures": list(tdata["signatures"])[:10],
                "first_seen": tdata["first_seen"],
                "last_seen": tdata["last_seen"],
                "alerts": tdata["alerts"],
            })

        # Classify adversary threat level
        total = data["total_alerts"]
        target_count = len(data["targets"])
        has_critical = any(t["severity_counts"]["critical"] > 0 for t in targets_list)
        hits_critical_assets = any(t["business_critical"] for t in targets_list)

        if has_critical and target_count >= 3:
            threat_level = "critical"
        elif has_critical or target_count >= 3:
            threat_level = "high"
        elif total >= 5 or target_count >= 2:
            threat_level = "medium"
        else:
            threat_level = "low"

        profiles.append({
            "ip": ip,
            "is_internal": is_internal(ip),
            "total_alerts": total,
            "target_count": target_count,
            "technique_count": len(data["techniques"] - {""}),
            "techniques": list(data["techniques"] - {""})[:15],
            "unique_signatures": len(data["signatures"]),
            "first_seen": data["first_seen"],
            "last_seen": data["last_seen"],
            "threat_level": threat_level,
            "targets": targets_list,
            "timeline": sorted(data["timeline"], key=lambda x: x["timestamp"]),
        })

    # Cross-asset attack patterns
    technique_spread = defaultdict(lambda: {"attackers": set(), "targets": set(), "count": 0})
    for p in profiles:
        for tech in p["techniques"]:
            ts = technique_spread[tech]
            ts["attackers"].add(p["ip"])
            for t in p["targets"]:
                ts["targets"].add(t["ip"])
            ts["count"] += p["total_alerts"]

    cross_patterns = []
    for tech, data in sorted(technique_spread.items(), key=lambda x: x[1]["count"], reverse=True):
        if len(data["attackers"]) > 0:
            cross_patterns.append({
                "technique": tech,
                "attacker_count": len(data["attackers"]),
                "target_count": len(data["targets"]),
                "total_alerts": data["count"],
            })

    return {
        "adversaries": profiles[:50],
        "cross_patterns": cross_patterns[:20],
        "summary": {
            "total_adversaries": len(profiles),
            "internal_adversaries": sum(1 for p in profiles if p["is_internal"]),
            "external_adversaries": sum(1 for p in profiles if not p["is_internal"]),
            "critical_threat": sum(1 for p in profiles if p["threat_level"] == "critical"),
            "high_threat": sum(1 for p in profiles if p["threat_level"] == "high"),
            "unique_techniques": len(technique_spread),
        },
    }
