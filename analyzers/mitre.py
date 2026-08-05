"""
MITRE ATT&CK heatmap builder.
Aggregates alert signatures into ATT&CK tactics and techniques,
producing a matrix-style heatmap dataset.
"""

from collections import defaultdict
from eve_reader import iter_events, is_ipv4
from analyzers.correlation import SIGNATURE_MAP


# Full MITRE ATT&CK Enterprise Tactic list (ordered)
TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "short": "Recon"},
    {"id": "TA0042", "name": "Resource Development", "short": "Resrc Dev"},
    {"id": "TA0001", "name": "Initial Access", "short": "Init Access"},
    {"id": "TA0002", "name": "Execution", "short": "Execution"},
    {"id": "TA0003", "name": "Persistence", "short": "Persist"},
    {"id": "TA0004", "name": "Privilege Escalation", "short": "Priv Esc"},
    {"id": "TA0005", "name": "Defense Evasion", "short": "Def Evasion"},
    {"id": "TA0006", "name": "Credential Access", "short": "Cred Access"},
    {"id": "TA0007", "name": "Discovery", "short": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement", "short": "Lateral Mvmt"},
    {"id": "TA0009", "name": "Collection", "short": "Collection"},
    {"id": "TA0011", "name": "Command and Control", "short": "C2"},
    {"id": "TA0010", "name": "Exfiltration", "short": "Exfil"},
    {"id": "TA0040", "name": "Impact", "short": "Impact"},
]

# Map kill chain phases (1-7) to tactic IDs for items that only have phase
PHASE_TO_TACTIC = {
    1: "TA0043",  # Recon
    2: "TA0042",  # Resource Development
    3: "TA0001",  # Initial Access / Delivery
    4: "TA0002",  # Execution / Exploitation
    5: "TA0003",  # Persistence / Installation
    6: "TA0011",  # C2
    7: "TA0010",  # Exfiltration / Actions
}


def build_mitre_heatmap(minutes=None):
    """
    Build a MITRE ATT&CK heatmap from IDS alerts.
    Returns tactics with technique counts for matrix visualization.
    """
    # Collect technique hits
    technique_hits = defaultdict(lambda: {
        "count": 0, "tactic": "", "tactic_id": "",
        "sources": set(), "targets": set(), "signatures": set(),
    })
    tactic_counts = defaultdict(int)
    total_mapped = 0
    total_unmapped = 0

    for ev in iter_events(event_types={"alert"}, minutes=minutes):
        sig = ev.get("alert", {}).get("signature", "")
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        sig_lower = sig.lower()

        mapped = False
        for mapping in SIGNATURE_MAP:
            if mapping["pattern"] in sig_lower:
                tactic_id = mapping.get("tactic", PHASE_TO_TACTIC.get(mapping["phase"], ""))
                technique_id = mapping.get("technique", "")
                technique_name = mapping.get("technique_name", "")

                if tactic_id and technique_id:
                    key = f"{tactic_id}:{technique_id}"
                    t = technique_hits[key]
                    t["count"] += 1
                    t["tactic_id"] = tactic_id
                    t["tactic"] = mapping.get("phase_name", "")
                    t["technique_id"] = technique_id
                    t["technique_name"] = technique_name
                    if is_ipv4(src):
                        t["sources"].add(src)
                    if is_ipv4(dst):
                        t["targets"].add(dst)
                    t["signatures"].add(sig[:100])
                    tactic_counts[tactic_id] += 1
                    mapped = True
                    break

        if mapped:
            total_mapped += 1
        else:
            total_unmapped += 1

    # Build matrix structure
    matrix = []
    for tactic in TACTICS:
        tid = tactic["id"]
        techniques = []
        for key, info in technique_hits.items():
            if info["tactic_id"] == tid:
                techniques.append({
                    "technique_id": info["technique_id"],
                    "technique_name": info["technique_name"],
                    "count": info["count"],
                    "sources": len(info["sources"]),
                    "targets": len(info["targets"]),
                    "sample_signatures": list(info["signatures"])[:5],
                })
        techniques.sort(key=lambda x: x["count"], reverse=True)
        matrix.append({
            "tactic_id": tid,
            "tactic_name": tactic["name"],
            "tactic_short": tactic["short"],
            "total_hits": tactic_counts.get(tid, 0),
            "techniques": techniques,
        })

    # Top attacked techniques overall
    top_techniques = sorted(technique_hits.values(), key=lambda x: x["count"], reverse=True)[:10]
    top_list = [{
        "technique_id": t["technique_id"],
        "technique_name": t["technique_name"],
        "tactic": t["tactic"],
        "count": t["count"],
        "sources": len(t["sources"]),
        "targets": len(t["targets"]),
    } for t in top_techniques]

    # Coverage stats
    active_tactics = sum(1 for t in matrix if t["total_hits"] > 0)
    active_techniques = len(technique_hits)

    return {
        "matrix": matrix,
        "top_techniques": top_list,
        "summary": {
            "total_mapped": total_mapped,
            "total_unmapped": total_unmapped,
            "active_tactics": active_tactics,
            "total_tactics": len(TACTICS),
            "active_techniques": active_techniques,
            "coverage_pct": round(active_tactics / len(TACTICS) * 100) if TACTICS else 0,
        },
    }
