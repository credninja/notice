"""
Alert Correlation Engine — Automatic Attack Chain Building
============================================================
1. Maps every alert signature to MITRE ATT&CK tactics/techniques
2. Groups alerts by attacker-victim pair within time windows
3. Builds kill chain: Recon -> Weaponize -> Exploit -> Install -> C2 -> Exfil
4. When multiple kill chain phases detected from same source, creates incident
5. Generates human-readable attack narrative

Kill Chain Phases (Unified Cyber Kill Chain):
  Phase 1: RECONNAISSANCE    — Scanning, probing, fingerprinting
  Phase 2: WEAPONIZATION     — Tool setup, payload crafting (rarely seen on network)
  Phase 3: DELIVERY          — Sending exploit/payload to target
  Phase 4: EXPLOITATION      — SQLi, XSS, RCE, command injection
  Phase 5: INSTALLATION      — Dropping malware, creating persistence
  Phase 6: COMMAND & CONTROL — C2 beaconing, callback channels
  Phase 7: ACTIONS ON OBJ    — Data exfiltration, lateral movement, destruction
"""

from collections import defaultdict
from datetime import datetime
from eve_reader import iter_events, is_internal, is_ipv4
from db import get_db


# ── MITRE ATT&CK Mapping ──
# Maps IDS signature patterns to kill chain phases and MITRE techniques
SIGNATURE_MAP = [
    # Phase 1: RECONNAISSANCE (TA0043)
    {"pattern": "scan", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1046", "technique_name": "Network Service Discovery"},
    {"pattern": "recon", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1046", "technique_name": "Network Service Discovery"},
    {"pattern": "nmap", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1046", "technique_name": "Network Service Discovery"},
    {"pattern": "port scan", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1046", "technique_name": "Network Service Discovery"},
    {"pattern": "nikto", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1595", "technique_name": "Active Scanning"},
    {"pattern": "directory traversal", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1083", "technique_name": "File and Directory Discovery"},
    {"pattern": "admin panel", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1083", "technique_name": "File and Directory Discovery"},
    {"pattern": "sensitive file", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1083", "technique_name": "File and Directory Discovery"},
    {"pattern": "robots.txt", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1592", "technique_name": "Gather Victim Host Information"},
    {"pattern": ".env", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1592", "technique_name": "Gather Victim Host Information"},
    {"pattern": ".git", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1592", "technique_name": "Gather Victim Host Information"},
    {"pattern": "spring boot actuator", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1046", "technique_name": "Network Service Discovery"},
    {"pattern": "empty user-agent", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1595", "technique_name": "Active Scanning"},
    {"pattern": "go http client", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1595", "technique_name": "Active Scanning"},
    {"pattern": "python http", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1595", "technique_name": "Active Scanning"},
    {"pattern": "curl/wget", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1595", "technique_name": "Active Scanning"},
    {"pattern": "external ip lookup", "phase": 1, "phase_name": "Reconnaissance", "tactic": "TA0043",
     "technique": "T1590", "technique_name": "Gather Victim Network Information"},

    # Phase 3: DELIVERY (TA0001 Initial Access)
    {"pattern": "phishing", "phase": 3, "phase_name": "Delivery", "tactic": "TA0001",
     "technique": "T1566", "technique_name": "Phishing"},
    {"pattern": "mz response", "phase": 3, "phase_name": "Delivery", "tactic": "TA0001",
     "technique": "T1204", "technique_name": "User Execution"},
    {"pattern": "pe download", "phase": 3, "phase_name": "Delivery", "tactic": "TA0001",
     "technique": "T1204", "technique_name": "User Execution"},

    # Phase 4: EXPLOITATION (TA0002 Execution)
    {"pattern": "sql injection", "phase": 4, "phase_name": "Exploitation", "tactic": "TA0002",
     "technique": "T1190", "technique_name": "Exploit Public-Facing Application"},
    {"pattern": "union select", "phase": 4, "phase_name": "Exploitation", "tactic": "TA0002",
     "technique": "T1190", "technique_name": "Exploit Public-Facing Application"},
    {"pattern": "xss", "phase": 4, "phase_name": "Exploitation", "tactic": "TA0002",
     "technique": "T1059.007", "technique_name": "JavaScript Execution"},
    {"pattern": "command injection", "phase": 4, "phase_name": "Exploitation", "tactic": "TA0002",
     "technique": "T1059", "technique_name": "Command and Scripting Interpreter"},
    {"pattern": "whoami", "phase": 4, "phase_name": "Exploitation", "tactic": "TA0002",
     "technique": "T1059", "technique_name": "Command and Scripting Interpreter"},
    {"pattern": "etc/passwd", "phase": 4, "phase_name": "Exploitation", "tactic": "TA0002",
     "technique": "T1003", "technique_name": "OS Credential Dumping"},
    {"pattern": "rce", "phase": 4, "phase_name": "Exploitation", "tactic": "TA0002",
     "technique": "T1203", "technique_name": "Exploitation for Client Execution"},
    {"pattern": "php filter", "phase": 4, "phase_name": "Exploitation", "tactic": "TA0002",
     "technique": "T1190", "technique_name": "Exploit Public-Facing Application"},
    {"pattern": "exploit", "phase": 4, "phase_name": "Exploitation", "tactic": "TA0002",
     "technique": "T1190", "technique_name": "Exploit Public-Facing Application"},
    {"pattern": "attack_response", "phase": 4, "phase_name": "Exploitation", "tactic": "TA0002",
     "technique": "T1059", "technique_name": "Command Execution Confirmed"},
    {"pattern": "id check returned root", "phase": 4, "phase_name": "Exploitation", "tactic": "TA0002",
     "technique": "T1059", "technique_name": "Command Execution — ROOT ACCESS CONFIRMED"},
    {"pattern": "brute", "phase": 4, "phase_name": "Exploitation", "tactic": "TA0006",
     "technique": "T1110", "technique_name": "Brute Force"},
    {"pattern": "java runtime exec", "phase": 4, "phase_name": "Exploitation", "tactic": "TA0002",
     "technique": "T1059", "technique_name": "Command and Scripting Interpreter"},
    {"pattern": "struts", "phase": 4, "phase_name": "Exploitation", "tactic": "TA0002",
     "technique": "T1190", "technique_name": "Exploit Public-Facing Application"},

    # Phase 5: INSTALLATION (TA0003 Persistence)
    {"pattern": "webshell", "phase": 5, "phase_name": "Installation", "tactic": "TA0003",
     "technique": "T1505.003", "technique_name": "Web Shell"},
    {"pattern": "backdoor", "phase": 5, "phase_name": "Installation", "tactic": "TA0003",
     "technique": "T1505", "technique_name": "Server Software Component"},
    {"pattern": "malware", "phase": 5, "phase_name": "Installation", "tactic": "TA0003",
     "technique": "T1059", "technique_name": "Malware Installation"},

    # Phase 6: COMMAND & CONTROL (TA0011)
    {"pattern": "c2", "phase": 6, "phase_name": "Command & Control", "tactic": "TA0011",
     "technique": "T1071", "technique_name": "Application Layer Protocol"},
    {"pattern": "beacon", "phase": 6, "phase_name": "Command & Control", "tactic": "TA0011",
     "technique": "T1071.001", "technique_name": "Web Protocols (HTTP/HTTPS C2)"},
    {"pattern": "cobalt strike", "phase": 6, "phase_name": "Command & Control", "tactic": "TA0011",
     "technique": "T1071.001", "technique_name": "Cobalt Strike C2"},
    {"pattern": "meterpreter", "phase": 6, "phase_name": "Command & Control", "tactic": "TA0011",
     "technique": "T1071", "technique_name": "Meterpreter C2"},

    # Phase 7: ACTIONS ON OBJECTIVES (TA0040 Impact / TA0010 Exfiltration)
    {"pattern": "exfil", "phase": 7, "phase_name": "Actions on Objectives", "tactic": "TA0010",
     "technique": "T1048", "technique_name": "Exfiltration Over Alternative Protocol"},
    {"pattern": "dns tunnel", "phase": 7, "phase_name": "Actions on Objectives", "tactic": "TA0010",
     "technique": "T1048.001", "technique_name": "Exfiltration Over DNS"},
    {"pattern": "lateral", "phase": 7, "phase_name": "Actions on Objectives", "tactic": "TA0008",
     "technique": "T1021", "technique_name": "Remote Services (Lateral Movement)"},
    {"pattern": "psexec", "phase": 7, "phase_name": "Actions on Objectives", "tactic": "TA0008",
     "technique": "T1021.002", "technique_name": "SMB/Windows Admin Shares"},
]

# Phase display config
PHASES = {
    1: {"name": "Reconnaissance", "color": "#3b82f6", "icon": "1"},
    2: {"name": "Weaponization", "color": "#8b5cf6", "icon": "2"},
    3: {"name": "Delivery", "color": "#f59e0b", "icon": "3"},
    4: {"name": "Exploitation", "color": "#ef4444", "icon": "4"},
    5: {"name": "Installation", "color": "#dc2626", "icon": "5"},
    6: {"name": "Command & Control", "color": "#b91c1c", "icon": "6"},
    7: {"name": "Actions on Objectives", "color": "#991b1b", "icon": "7"},
}


def map_signature_to_phase(signature):
    """Map an alert signature to a kill chain phase and MITRE technique."""
    sig_lower = signature.lower()
    for mapping in SIGNATURE_MAP:
        if mapping["pattern"] in sig_lower:
            return mapping
    # Default: unclassified
    return {"phase": 0, "phase_name": "Unclassified", "tactic": "", "technique": "",
            "technique_name": "Unclassified Alert", "pattern": ""}


def correlate_alerts(minutes=None):
    """
    Main correlation engine.
    Groups alerts by attacker-victim pair, maps to kill chain, builds attack chains,
    and identifies incidents.
    """
    # Load asset info for enrichment
    conn = get_db()
    asset_rows = conn.execute("SELECT ip, owner, hostname FROM assets WHERE scope='internal'").fetchall()
    conn.close()
    asset_map = {r["ip"]: r["owner"] or r["hostname"] or "" for r in asset_rows}

    # Group alerts by (src_ip, dst_ip) pair
    pairs = defaultdict(lambda: {
        "alerts": [],
        "phases_seen": set(),
        "phase_details": defaultdict(list),
        "first_seen": "",
        "last_seen": "",
        "signatures": set(),
        "sids": set(),
    })

    total_alerts = 0
    for ev in iter_events(event_types={"alert"}, minutes=minutes):
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        if not is_ipv4(src) or not is_ipv4(dst):
            continue

        alert = ev.get("alert", {})
        sig = alert.get("signature", "")
        sid = alert.get("signature_id", 0)
        sev = alert.get("severity", 3)
        ts = ev.get("timestamp", "")
        total_alerts += 1

        # Map to kill chain phase
        mapping = map_signature_to_phase(sig)
        phase = mapping["phase"]

        # Key: attacker -> victim (we consider src as attacker for inbound alerts)
        key = (src, dst)
        pair = pairs[key]

        pair["alerts"].append({
            "timestamp": ts,
            "signature": sig,
            "sid": sid,
            "severity": sev,
            "phase": phase,
            "phase_name": mapping["phase_name"],
            "tactic": mapping["tactic"],
            "technique": mapping["technique"],
            "technique_name": mapping["technique_name"],
            "proto": ev.get("proto", ""),
            "dest_port": ev.get("dest_port", 0),
        })

        pair["phases_seen"].add(phase)
        pair["phase_details"][phase].append({
            "timestamp": ts, "signature": sig, "sid": sid, "severity": sev,
            "technique": mapping["technique"], "technique_name": mapping["technique_name"],
        })
        pair["signatures"].add(sig)
        pair["sids"].add(sid)

        if not pair["first_seen"] or ts < pair["first_seen"]:
            pair["first_seen"] = ts
        if not pair["last_seen"] or ts > pair["last_seen"]:
            pair["last_seen"] = ts

    # Build attack chains for pairs with multiple phases
    attack_chains = []
    for (src, dst), pair in pairs.items():
        # Sort alerts chronologically
        pair["alerts"].sort(key=lambda a: a["timestamp"])

        # Consider chains with 2+ different phases OR 3+ unique signatures in same phase
        real_phases = pair["phases_seen"] - {0}
        if len(real_phases) < 2 and len(pair["signatures"]) < 3:
            continue

        # Calculate severity
        max_phase = max(real_phases)
        total_alerts_in_chain = len(pair["alerts"])
        has_exploitation = 4 in real_phases
        has_c2 = 6 in real_phases
        has_exfil = 7 in real_phases

        if has_exploitation and (has_c2 or has_exfil):
            chain_severity = "critical"
        elif has_exploitation:
            chain_severity = "high"
        elif max_phase >= 4:
            chain_severity = "high"
        else:
            chain_severity = "medium"

        # Build narrative
        narrative = _build_narrative(src, dst, pair, real_phases, asset_map)

        # Build phase timeline
        phase_timeline = []
        for phase_num in sorted(real_phases):
            details = pair["phase_details"][phase_num]
            details.sort(key=lambda d: d["timestamp"])
            phase_info = PHASES.get(phase_num, {"name": "Unknown", "color": "#666"})
            phase_timeline.append({
                "phase": phase_num,
                "phase_name": phase_info["name"],
                "color": phase_info["color"],
                "alert_count": len(details),
                "first_alert": details[0]["timestamp"] if details else "",
                "last_alert": details[-1]["timestamp"] if details else "",
                "techniques": list(set(d["technique"] + ": " + d["technique_name"] for d in details)),
                "sample_signatures": list(set(d["signature"] for d in details))[:3],
            })

        attack_chains.append({
            "attacker_ip": src,
            "attacker_owner": asset_map.get(src, ""),
            "attacker_internal": is_internal(src),
            "victim_ip": dst,
            "victim_owner": asset_map.get(dst, ""),
            "victim_internal": is_internal(dst),
            "severity": chain_severity,
            "phases_detected": sorted(real_phases),
            "phase_count": len(real_phases),
            "total_alerts": total_alerts_in_chain,
            "unique_signatures": len(pair["signatures"]),
            "first_seen": pair["first_seen"],
            "last_seen": pair["last_seen"],
            "phase_timeline": phase_timeline,
            "narrative": narrative,
            "auto_incident": chain_severity in ("critical", "high"),
        })

    # Sort by severity then phase count
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    attack_chains.sort(key=lambda c: (sev_order.get(c["severity"], 4), -c["phase_count"]))

    # Auto-create incidents for critical/high chains
    auto_incidents = []
    for chain in attack_chains:
        if chain["auto_incident"]:
            auto_incidents.append({
                "title": f"Multi-Phase Attack: {chain['attacker_ip']} -> {chain['victim_owner'] or chain['victim_ip']}",
                "severity": chain["severity"],
                "attacker": chain["attacker_ip"],
                "victim": chain["victim_ip"],
                "phases": chain["phases_detected"],
                "alert_count": chain["total_alerts"],
                "narrative": chain["narrative"],
            })

    return {
        "attack_chains": attack_chains[:50],
        "auto_incidents": auto_incidents,
        "summary": {
            "total_alerts_analyzed": total_alerts,
            "total_pairs": len(pairs),
            "chains_detected": len(attack_chains),
            "critical_chains": sum(1 for c in attack_chains if c["severity"] == "critical"),
            "high_chains": sum(1 for c in attack_chains if c["severity"] == "high"),
            "auto_incidents_created": len(auto_incidents),
        },
        "phases": PHASES,
    }


def _build_narrative(src, dst, pair, phases, asset_map):
    """Build a human-readable attack narrative."""
    src_label = asset_map.get(src, src)
    dst_label = asset_map.get(dst, dst)
    if src_label != src:
        src_label = f"{src_label} ({src})"
    if dst_label != dst:
        dst_label = f"{dst_label} ({dst})"

    parts = []

    if 1 in phases:
        details = pair["phase_details"][1]
        parts.append(f"The attacker at {src_label} began by scanning {dst_label}, "
                     f"triggering {len(details)} reconnaissance alert(s). "
                     f"This included {', '.join(set(d['technique_name'] for d in details[:3]))}.")

    if 3 in phases:
        details = pair["phase_details"][3]
        parts.append(f"A delivery attempt was detected — {len(details)} alert(s) indicating "
                     f"payload delivery to the target.")

    if 4 in phases:
        details = pair["phase_details"][4]
        techniques = set(d["technique_name"] for d in details)
        parts.append(f"The attack escalated to active exploitation with {len(details)} alert(s): "
                     f"{', '.join(list(techniques)[:3])}. "
                     f"This represents an attempt to gain unauthorized access to the target system.")

        # Check for confirmed RCE
        if any("root" in d["technique_name"].lower() or "confirmed" in d["technique_name"].lower() for d in details):
            parts.append("CRITICAL: The server responded with root-level access confirmation, "
                         "indicating successful remote code execution (RCE).")

    if 6 in phases:
        details = pair["phase_details"][6]
        parts.append(f"Command & Control activity detected — {len(details)} beacon/C2 alert(s), "
                     f"suggesting the attacker established a persistent communication channel.")

    if 7 in phases:
        details = pair["phase_details"][7]
        parts.append(f"Post-exploitation activity detected — {len(details)} alert(s) indicating "
                     f"data exfiltration or lateral movement attempts.")

    duration = ""
    if pair["first_seen"] and pair["last_seen"]:
        try:
            t1 = datetime.fromisoformat(pair["first_seen"])
            t2 = datetime.fromisoformat(pair["last_seen"])
            delta = (t2 - t1).total_seconds()
            if delta < 60:
                duration = f"{int(delta)} seconds"
            elif delta < 3600:
                duration = f"{int(delta / 60)} minutes"
            else:
                duration = f"{delta / 3600:.1f} hours"
        except Exception:
            pass

    if duration:
        parts.append(f"The entire attack chain spanned {duration} with {len(pair['alerts'])} total alerts "
                     f"across {len(phases)} kill chain phases.")

    return " ".join(parts)
