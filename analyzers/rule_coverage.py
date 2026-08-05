"""
Comprehensive rule coverage analyzer — scans ALL rule files in the rules
directory and produces the full inventory, classification, protocol,
MITRE, and source breakdown for the Rule Coverage dashboard.
"""

import os
import re
from collections import defaultdict

RULES_DIR = os.environ.get("SURICATA_RULES_DIR", "/var/lib/suricata/rules")

_RE_SID = re.compile(r"sid:\s*(\d+)")
_RE_MSG = re.compile(r'msg:"([^"]+)"')
_RE_CLASSTYPE = re.compile(r"classtype:\s*(\S+?);")
_RE_SEVERITY = re.compile(r"signature_severity\s+(\w+)")
_RE_DEPLOY = re.compile(r"deployment\s+(\w+)")
_RE_TARGET = re.compile(r"attack_target\s+(\w+)")
_RE_TACTIC = re.compile(r"mitre_tactic_id\s+(\w+)")
_RE_TECHNIQUE = re.compile(r"mitre_technique_id\s+(\w+)")
_RE_PROTO = re.compile(r"^\w+\s+(\w+)")
_RE_CVE = re.compile(r"reference:\s*cve,")

_cache = None
_cache_mtime = 0

MITRE_TACTICS = {
    "TA0001": "Initial Access", "TA0002": "Execution",
    "TA0003": "Persistence", "TA0005": "Defense Evasion",
    "TA0006": "Credential Access", "TA0007": "Discovery",
    "TA0008": "Lateral Movement", "TA0009": "Collection",
    "TA0010": "Exfiltration", "TA0011": "Command & Control",
    "TA0040": "Impact", "TA0042": "Resource Development",
    "TA0043": "Reconnaissance", "TA0037": "C2 (Mobile)",
}

MITRE_TECHNIQUES = {
    "T1071": "Application Layer Protocol",
    "T1190": "Exploit Public-Facing App",
    "T1566": "Phishing",
    "T1568": "Dynamic Resolution",
    "T1573": "Encrypted Channel",
    "T1041": "Exfil Over C2 Channel",
    "T1189": "Drive-by Compromise",
    "T1572": "Protocol Tunneling",
    "T1027": "Obfuscated Files/Info",
    "T1486": "Data Encrypted for Impact",
    "T1102": "Web Service",
    "T1583": "Acquire Infrastructure",
    "T1587": "Develop Capabilities",
    "T1219": "Remote Access Software",
    "T1105": "Ingress Tool Transfer",
    "T1210": "Exploitation of Remote Services",
    "T1001": "Data Obfuscation",
    "T1496": "Resource Hijacking",
    "T1567": "Exfil Over Web Service",
    "T1005": "Data from Local System",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1590": "Gather Victim Network Info",
}


def _max_mtime():
    m = 0
    try:
        for fn in os.listdir(RULES_DIR):
            if fn.endswith(".rules"):
                m = max(m, os.path.getmtime(os.path.join(RULES_DIR, fn)))
    except OSError:
        pass
    return m


def _clear_cache():
    global _cache, _cache_mtime
    _cache = None
    _cache_mtime = 0


def get_full_coverage():
    global _cache, _cache_mtime
    mt = _max_mtime()
    if _cache is not None and mt <= _cache_mtime:
        return _cache
    _cache = _analyze()
    _cache_mtime = mt
    return _cache


def _analyze():
    files = []
    total_active = 0
    total_disabled = 0
    classtypes = defaultdict(int)
    severities = defaultdict(int)
    deployments = defaultdict(int)
    targets = defaultdict(int)
    tactics = defaultdict(int)
    techniques = defaultdict(int)
    protocols = defaultdict(int)
    sources = defaultdict(int)
    actions = defaultdict(int)
    cve_count = 0
    custom_rules = []
    custom_categories = defaultdict(int)
    custom_classtypes = defaultdict(int)
    monitored_assets = {}

    try:
        rule_files = sorted(f for f in os.listdir(RULES_DIR) if f.endswith(".rules"))
    except OSError:
        return {"error": "Cannot read rules directory"}

    for fn in rule_files:
        fp = os.path.join(RULES_DIR, fn)
        active = 0
        disabled = 0
        try:
            with open(fp, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("#"):
                        inner = line.lstrip("# ")
                        if inner.startswith(("alert ", "drop ", "reject ", "pass ")):
                            disabled += 1
                        continue
                    if not line.startswith(("alert ", "drop ", "reject ", "pass ")):
                        continue
                    active += 1
                    _process_active_rule(
                        line, fn, classtypes, severities, deployments,
                        targets, tactics, techniques, protocols, sources,
                        actions, custom_rules, custom_categories,
                        custom_classtypes, monitored_assets,
                    )
                    if _RE_CVE.search(line):
                        cve_count += 1
        except (IOError, PermissionError):
            continue
        total_active += active
        total_disabled += disabled
        if active > 0 or disabled > 0:
            files.append({
                "file": fn,
                "active": active,
                "disabled": disabled,
                "total": active + disabled,
                "active_pct": round(active / (active + disabled) * 100, 1) if (active + disabled) else 0,
            })

    files.sort(key=lambda x: -x["active"])

    # Cross-reference with assets DB for current owner/label
    db_assets = {}
    try:
        from db import get_db
        conn = get_db()
        for r in conn.execute("SELECT ip, owner, hostname FROM assets WHERE scope='internal'").fetchall():
            db_assets[r["ip"]] = {"owner": r["owner"], "hostname": r["hostname"]}
        conn.close()
    except Exception:
        pass

    asset_list = []
    for ip, info in sorted(monitored_assets.items()):
        db = db_assets.get(ip, {})
        label = db.get("owner") or db.get("hostname") or info.get("label", "")
        asset_list.append({
            "ip": ip,
            "label": label,
            "rule_count": info.get("count", 0),
            "categories": list(info.get("cats", set())),
        })

    tactic_list = []
    for tid, cnt in sorted(tactics.items(), key=lambda x: -x[1]):
        tactic_list.append({"id": tid, "name": MITRE_TACTICS.get(tid, tid), "count": cnt})

    technique_list = []
    for tid, cnt in sorted(techniques.items(), key=lambda x: -x[1])[:20]:
        technique_list.append({"id": tid, "name": MITRE_TECHNIQUES.get(tid, tid), "count": cnt})

    proto_list = []
    for p, cnt in sorted(protocols.items(), key=lambda x: -x[1]):
        proto_list.append({"protocol": p, "count": cnt})

    src_list = []
    for s, cnt in sorted(sources.items(), key=lambda x: -x[1]):
        src_list.append({"source": s, "count": cnt})

    ct_list = []
    for c, cnt in sorted(classtypes.items(), key=lambda x: -x[1]):
        ct_list.append({"classtype": c, "count": cnt, "pct": round(cnt / total_active * 100, 1) if total_active else 0})

    sev_list = []
    for s, cnt in sorted(severities.items(), key=lambda x: -x[1]):
        sev_list.append({"severity": s, "count": cnt, "pct": round(cnt / total_active * 100, 1) if total_active else 0})

    dep_list = []
    for d, cnt in sorted(deployments.items(), key=lambda x: -x[1]):
        dep_list.append({"zone": d, "count": cnt})

    tgt_list = []
    for t, cnt in sorted(targets.items(), key=lambda x: -x[1]):
        tgt_list.append({"target": t.replace("_", " "), "count": cnt})

    custom_cat_list = []
    for c, cnt in sorted(custom_categories.items(), key=lambda x: -x[1]):
        custom_cat_list.append({"category": c, "count": cnt})

    custom_ct_list = []
    for c, cnt in sorted(custom_classtypes.items(), key=lambda x: -x[1]):
        custom_ct_list.append({"classtype": c, "count": cnt})

    gaps = _assess_gaps(tactics, protocols, actions, total_active, total_disabled)

    return {
        "inventory": {
            "total_files": len(rule_files),
            "total_active": total_active,
            "total_disabled": total_disabled,
            "total_rules": total_active + total_disabled,
            "active_rate": round(total_active / (total_active + total_disabled) * 100, 1) if (total_active + total_disabled) else 0,
            "files": files[:20],
        },
        "classifications": ct_list[:20],
        "severities": sev_list,
        "deployments": dep_list,
        "attack_targets": tgt_list[:12],
        "mitre_tactics": tactic_list,
        "mitre_techniques": technique_list,
        "protocols": proto_list,
        "sources": src_list,
        "actions": dict(actions),
        "cve_references": cve_count,
        "custom_rules": {
            "total": len(custom_rules),
            "sid_range": [custom_rules[0]["sid"], custom_rules[-1]["sid"]] if custom_rules else [0, 0],
            "categories": custom_cat_list,
            "classtypes": custom_ct_list,
            "assets": asset_list,
            "rules": custom_rules[:50],
        },
        "gaps": gaps,
    }


def _process_active_rule(line, filename, classtypes, severities, deployments,
                         targets, tactics, techniques, protocols, sources,
                         actions, custom_rules, custom_categories,
                         custom_classtypes, monitored_assets):
    action_m = line.split()[0]
    actions[action_m] = actions.get(action_m, 0) + 1

    proto_m = _RE_PROTO.match(line)
    if proto_m:
        protocols[proto_m.group(1)] += 1

    cls_m = _RE_CLASSTYPE.search(line)
    if cls_m:
        classtypes[cls_m.group(1)] += 1

    sev_m = _RE_SEVERITY.search(line)
    if sev_m:
        severities[sev_m.group(1)] += 1

    dep_m = _RE_DEPLOY.search(line)
    if dep_m:
        deployments[dep_m.group(1)] += 1

    tgt_m = _RE_TARGET.search(line)
    if tgt_m:
        targets[tgt_m.group(1)] += 1

    for m in _RE_TACTIC.finditer(line):
        tactics[m.group(1)] += 1
    for m in _RE_TECHNIQUE.finditer(line):
        techniques[m.group(1)] += 1

    msg_m = _RE_MSG.search(line)
    msg = msg_m.group(1) if msg_m else ""
    if msg.startswith("ET "):
        sources["ET Open"] += 1
    elif msg.startswith("ETPRO "):
        sources["ET Pro"] += 1
    elif msg.startswith("GPL "):
        sources["GPL"] += 1
    elif msg.startswith("NOTICE "):
        sources["NOTICE Custom"] += 1
    else:
        sources["Other"] += 1

    sid_m = _RE_SID.search(line)
    sid = int(sid_m.group(1)) if sid_m else 0

    if sid >= 1000000 and sid < 2000000:
        cat = ""
        if msg.startswith("NOTICE "):
            parts = msg.split(" ", 2)
            cat = parts[1] if len(parts) >= 2 else ""
        custom_rules.append({"sid": sid, "msg": msg, "category": cat})
        if cat:
            custom_categories[cat] += 1
        if cls_m:
            custom_classtypes[cls_m.group(1)] += 1

        if "NOTICE ASSET" in msg:
            ip_match = re.search(r"\b(\d+\.\d+\.\d+\.\d+)\b", msg)
            label_match = re.search(r"\[([^\]]+)\]", msg)
            if ip_match:
                ip = ip_match.group(1)
                label = label_match.group(1) if label_match else ""
                if ip not in monitored_assets:
                    monitored_assets[ip] = {"label": label, "count": 0, "cats": set()}
                monitored_assets[ip]["count"] += 1
                if cat:
                    monitored_assets[ip]["cats"].add(cat)


def _assess_gaps(tactics, protocols, actions, total_active, total_disabled):
    gaps = []
    weak_tactics = {
        "TA0002": ("Execution", "PowerShell, WMI, scripting engine detections"),
        "TA0006": ("Credential Access", "LSASS dumping, pass-the-hash, pass-the-ticket"),
        "TA0003": ("Persistence", "Registry run keys, scheduled tasks, service creation"),
    }
    for tid, (name, suggestion) in weak_tactics.items():
        cnt = tactics.get(tid, 0)
        if cnt < 100:
            gaps.append({
                "area": f"MITRE {tid} — {name}",
                "current": f"{cnt} rules",
                "recommendation": f"Expand: {suggestion}",
                "severity": "high" if cnt < 20 else "medium",
            })

    drop_count = actions.get("drop", 0)
    if drop_count < 10:
        gaps.append({
            "area": "IPS Mode (drop rules)",
            "current": f"{drop_count} drop rules",
            "recommendation": "Enable drop action for high-confidence malware C2 signatures",
            "severity": "medium",
        })

    ssh_count = protocols.get("ssh", 0)
    if ssh_count < 50:
        gaps.append({
            "area": "SSH Protocol Rules",
            "current": f"{ssh_count} rules",
            "recommendation": "Add SSH brute force, version detection, tunnel detection rules",
            "severity": "medium",
        })

    quic_count = protocols.get("quic", 0)
    if quic_count < 10:
        gaps.append({
            "area": "QUIC / HTTP/3 Protocol",
            "current": f"{quic_count} rules",
            "recommendation": "Growing protocol — add QUIC-based C2 and tunneling detection",
            "severity": "low",
        })

    if total_disabled > total_active * 0.3:
        gaps.append({
            "area": "Disabled Rules Review",
            "current": f"{total_disabled:,} disabled ({round(total_disabled/(total_active+total_disabled)*100,1)}%)",
            "recommendation": "Review disabled exploit-kit and coin-mining rules for re-enablement",
            "severity": "low",
        })

    return gaps
