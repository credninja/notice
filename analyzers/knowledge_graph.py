"""
Incident knowledge graph builder.

Produces an ontology-rich graph for one incident — not a network topology.
Five node kinds, six labeled-edge kinds. Layout is rendered in the front-
end with a left-to-right tendency:

    [attackers]  ──uses──▶  [techniques]  ──exploits──▶  [assets]
         │                                                   │
         └────indicates───▶  [indicators]  ◀───generates────┘
                                  │
                                  └──results-in──▶  [impact]

Node kinds:
  attacker      — external IP that initiated alerts (red gradient by TI score)
  technique     — MITRE ATT&CK technique extracted from signatures (purple)
  asset         — internal IP touched (blue, bigger if business_critical)
  indicator     — IOCs collected on the incident (signatures, domains, etc.)
  impact        — derived: 'data exfiltration risk' / 'C2 established' /
                  'lateral movement' inferred from kill-chain phases reached

Edge kinds (label, color):
  uses          (attacker → technique)
  exploits      (technique → asset)
  indicates     (technique → indicator) / (attacker → indicator)
  generates     (asset → indicator)
  affects       (asset → impact)
  results-in    (technique → impact)

This is what the UI calls a "knowledge graph" — relationships, causality,
mapped to ATT&CK — not just who-talked-to-whom.
"""

from collections import Counter, defaultdict

from db import get_db
from eve_reader import is_internal
from analyzers.correlation import SIGNATURE_MAP
from analyzers.ti_score import quick_chip_for_ip


# Phase → impact derivation. We promote the deepest phase reached into a
# single "impact" node so analysts see consequence at a glance.
PHASE_IMPACT = {
    1: ("Recon Activity",       "Reconnaissance / scanning observed", "#3b82f6"),
    2: ("Weaponization",        "Pre-attack tooling indicators",      "#3b82f6"),
    3: ("Delivery",             "Payload delivery attempt",            "#f59e0b"),
    4: ("Exploitation",         "Vulnerability exploitation",          "#f59e0b"),
    5: ("Installation",         "Persistence / installation",          "#ef4444"),
    6: ("Command & Control",    "C2 channel established",              "#ef4444"),
    7: ("Actions on Objectives","Data exfil / lateral / impact stage", "#dc2626"),
}


def _signature_to_technique(sig):
    s = (sig or "").lower()
    for m in SIGNATURE_MAP:
        if m["pattern"] in s:
            return {
                "id": m.get("technique") or "",
                "name": m.get("technique_name") or "",
                "phase": int(m.get("phase") or 0),
                "phase_name": m.get("phase_name") or "",
            }
    return None


def _classification_color(cls):
    return {
        "malicious": "#dc2626",
        "suspicious": "#f59e0b",
        "benign": "#10b981",
        "internal": "#3b82f6",
        "unknown": "#94a3b8",
    }.get(cls, "#94a3b8")


def build_incident_graph(incident_id):
    conn = get_db()
    inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not inc:
        conn.close()
        return None
    inc = dict(inc)
    iocs = [dict(r) for r in conn.execute(
        "SELECT * FROM incident_iocs WHERE incident_id=?", (incident_id,)
    ).fetchall()]
    events = [dict(r) for r in conn.execute(
        "SELECT * FROM incident_events WHERE incident_id=? ORDER BY timestamp", (incident_id,)
    ).fetchall()]
    # Pull asset records to mark business_critical
    asset_rows = {r["ip"]: dict(r) for r in conn.execute(
        "SELECT ip, owner, hostname, business_critical, asset_type FROM assets"
    ).fetchall()}
    conn.close()

    nodes = {}
    links = []

    def add_node(_id, kind, label, **extra):
        if _id not in nodes:
            nodes[_id] = {"id": _id, "kind": kind, "label": label, **extra}
        return nodes[_id]

    def add_link(src, dst, rel, weight=1):
        links.append({"source": src, "target": dst, "rel": rel, "value": weight})

    # ── Pass 1: derive techniques + asset/attacker maps from events ─────
    technique_hits = Counter()      # technique_id → count
    technique_by_id = {}            # technique_id → {name, phase, phase_name}
    asset_techniques = defaultdict(set)   # asset_ip → {technique_id}
    attacker_techniques = defaultdict(set) # attacker_ip → {technique_id}
    attacker_asset_hits = Counter()  # (attacker, asset) → count
    technique_asset_hits = Counter() # (tid, asset) → count
    deepest_phase = 0

    for e in events:
        sig = ""
        if (e.get("event_summary") or "").startswith("[sid "):
            try:
                sig = e["event_summary"].split("] ", 1)[1]
            except IndexError:
                pass
        t = _signature_to_technique(sig)
        if not t:
            continue
        tid = t["id"]
        if not tid:
            continue
        technique_hits[tid] += 1
        technique_by_id[tid] = t
        if t["phase"] > deepest_phase:
            deepest_phase = t["phase"]

        s, d = e.get("src_ip", ""), e.get("dest_ip", "")
        # The internal endpoint is the asset; whichever side is external is the attacker
        asset = d if is_internal(d) else (s if is_internal(s) else None)
        attacker = s if (s and not is_internal(s)) else (d if (d and not is_internal(d)) else None)
        if asset:
            asset_techniques[asset].add(tid)
            if attacker:
                attacker_techniques[attacker].add(tid)
                attacker_asset_hits[(attacker, asset)] += 1
            technique_asset_hits[(tid, asset)] += 1

    # ── Pass 2: build nodes ────────────────────────────────────────────

    # Incident root for context (small)
    add_node(f"inc:{inc['id']}", "incident",
             f"#{inc['id']}",
             severity=inc.get("severity"),
             phase=inc.get("phase"),
             status=inc.get("status"),
             color="#94a3b8")

    # Attackers (external IPs) — color by TI classification
    for atk in attacker_techniques.keys():
        chip = quick_chip_for_ip(atk)
        cls = chip.get("classification") or "unknown"
        add_node(f"atk:{atk}", "attacker", atk,
                 classification=cls, score=chip.get("score", 0),
                 color=_classification_color(cls))
    # Also include attacker_ip from the incident itself if not already a node
    if inc.get("attacker_ip") and not is_internal(inc["attacker_ip"]):
        atk = inc["attacker_ip"]
        if f"atk:{atk}" not in nodes:
            chip = quick_chip_for_ip(atk)
            cls = chip.get("classification") or "unknown"
            add_node(f"atk:{atk}", "attacker", atk,
                     classification=cls, score=chip.get("score", 0),
                     color=_classification_color(cls))

    # Assets (internal IPs) — bigger if business_critical
    for asset in asset_techniques.keys():
        ar = asset_rows.get(asset, {})
        label = (ar.get("owner") + " (" + asset + ")") if ar.get("owner") else asset
        add_node(f"asset:{asset}", "asset", label,
                 ip=asset,
                 owner=ar.get("owner") or "",
                 critical=bool(ar.get("business_critical")),
                 asset_type=ar.get("asset_type") or "",
                 color="#3b82f6")
    if inc.get("victim_ip") and is_internal(inc["victim_ip"]) and f"asset:{inc['victim_ip']}" not in nodes:
        v = inc["victim_ip"]
        ar = asset_rows.get(v, {})
        add_node(f"asset:{v}", "asset",
                 (ar.get("owner") + " (" + v + ")") if ar.get("owner") else v,
                 ip=v, owner=ar.get("owner") or "",
                 critical=bool(ar.get("business_critical")),
                 asset_type=ar.get("asset_type") or "",
                 color="#3b82f6")

    # Techniques — labeled with ID + name
    for tid, t in technique_by_id.items():
        add_node(f"tech:{tid}", "technique",
                 f"{tid} · {t['name']}",
                 technique_id=tid,
                 technique_name=t["name"],
                 phase=t["phase"],
                 phase_name=t["phase_name"],
                 hits=technique_hits[tid],
                 color="#8b5cf6")

    # Indicators — only the *primary* IOCs and a few high-frequency aux IOCs
    primary_iocs = [i for i in iocs if i.get("is_primary")]
    aux_iocs = sorted(
        [i for i in iocs if not i.get("is_primary")],
        key=lambda i: -(i.get("frequency") or 0),
    )[:6]  # cap so the graph stays readable
    for i in (primary_iocs + aux_iocs):
        if i["ioc_type"] == "src_ip" and is_internal(i["ioc_value"]):
            continue  # handled as asset, not indicator
        if i["ioc_type"] == "src_ip" and f"atk:{i['ioc_value']}" in nodes:
            continue  # handled as attacker
        if i["ioc_type"] in ("dest_ip",) and is_internal(i["ioc_value"]):
            continue
        nid = f"ind:{i['ioc_type']}:{i['ioc_value']}"
        label = i["ioc_value"][:42] + ("…" if len(i["ioc_value"]) > 42 else "")
        if i["ioc_type"] == "signature_id":
            label = f"sid {i['ioc_value']}"
        elif i["ioc_type"] == "signature":
            label = f'"{label}"'
        add_node(nid, "indicator", label,
                 ioc_type=i["ioc_type"],
                 ioc_value=i["ioc_value"],
                 is_primary=bool(i.get("is_primary")),
                 frequency=i.get("frequency") or 1,
                 color="#10b981" if i.get("is_primary") else "#22d3ee")

    # Impact node (single, derived from deepest phase)
    if deepest_phase:
        impact_label, impact_desc, impact_color = PHASE_IMPACT.get(
            deepest_phase, ("Unknown impact", "", "#94a3b8"))
        add_node("impact:0", "impact", impact_label,
                 phase=deepest_phase, desc=impact_desc, color=impact_color)

    # ── Pass 3: build labeled edges ────────────────────────────────────

    # attacker → technique (uses)
    for atk, tids in attacker_techniques.items():
        for tid in tids:
            if f"tech:{tid}" not in nodes:
                continue
            add_link(f"atk:{atk}", f"tech:{tid}", "uses",
                     weight=technique_hits.get(tid, 1))

    # technique → asset (exploits)
    for (tid, asset), cnt in technique_asset_hits.items():
        if f"tech:{tid}" not in nodes or f"asset:{asset}" not in nodes:
            continue
        add_link(f"tech:{tid}", f"asset:{asset}", "exploits", weight=cnt)

    # technique / attacker → indicator (indicates)
    # Connect each indicator to ALL techniques whose phase matches the
    # indicator's signature mapping (best-effort; falls back to "any
    # attacker" relationship for IP indicators).
    for i in (primary_iocs + aux_iocs):
        nid = f"ind:{i['ioc_type']}:{i['ioc_value']}"
        if nid not in nodes:
            continue
        if i["ioc_type"] == "signature_id":
            # Find a technique that fired with this sid via events
            for e in events:
                if str(e.get("sid")) != str(i["ioc_value"]):
                    continue
                sig = ""
                if (e.get("event_summary") or "").startswith("[sid "):
                    try: sig = e["event_summary"].split("] ", 1)[1]
                    except IndexError: pass
                t = _signature_to_technique(sig)
                if t and t["id"] and f"tech:{t['id']}" in nodes:
                    add_link(f"tech:{t['id']}", nid, "indicates", weight=1)
                    break
        elif i["ioc_type"] in ("src_ip", "dest_ip"):
            # External IP IOC → linked to its attacker node
            if f"atk:{i['ioc_value']}" in nodes:
                add_link(f"atk:{i['ioc_value']}", nid, "indicates", weight=1)
        elif i["ioc_type"] in ("signature",):
            # Signature text → if we can map to a technique, link
            t = _signature_to_technique(i["ioc_value"])
            if t and t["id"] and f"tech:{t['id']}" in nodes:
                add_link(f"tech:{t['id']}", nid, "indicates", weight=1)
        # else: standalone indicator without a parent technique — leave it dangling

    # asset → impact (affects)
    if deepest_phase:
        for asset in asset_techniques.keys():
            add_link(f"asset:{asset}", "impact:0", "affects",
                     weight=sum(technique_asset_hits.get((tid, asset), 0)
                                for tid in asset_techniques[asset]))
        # technique → impact (results-in) only for the deepest-phase techs
        for tid, t in technique_by_id.items():
            if t["phase"] == deepest_phase and f"tech:{tid}" in nodes:
                add_link(f"tech:{tid}", "impact:0", "results-in",
                         weight=technique_hits[tid])

    # ── Stats for the UI summary strip ─────────────────────────────────
    counts = Counter(n["kind"] for n in nodes.values())
    summary = {
        "attackers": counts.get("attacker", 0),
        "techniques": counts.get("technique", 0),
        "assets": counts.get("asset", 0),
        "indicators": counts.get("indicator", 0),
        "deepest_phase": deepest_phase,
        "deepest_phase_name": PHASE_IMPACT.get(deepest_phase, ("", "", ""))[0],
        "top_techniques": [
            {"id": tid, "name": technique_by_id[tid]["name"], "hits": cnt}
            for tid, cnt in technique_hits.most_common(5)
        ],
    }

    return {
        "nodes": list(nodes.values()),
        "links": links,
        "incident": {
            "id": inc["id"], "title": inc["title"],
            "severity": inc.get("severity"), "phase": inc.get("phase"),
        },
        "summary": summary,
    }
