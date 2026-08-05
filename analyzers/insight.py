"""
Incident insight analyzers: impact assessment, origin/patient-zero, asset
timeline, reinfection check.

These are read-only views computed from incidents + incident_events +
asset_compromise_state + eve.json. They drive the new panels on the
incident detail page.
"""

from collections import Counter, defaultdict
from datetime import datetime, timedelta

from db import get_db
from eve_reader import iter_events, is_internal
from analyzers.correlation import SIGNATURE_MAP


def _phase_for_signature(sig):
    s = (sig or "").lower()
    for m in SIGNATURE_MAP:
        if m["pattern"] in s:
            return int(m.get("phase") or 0), m.get("phase_name", "")
    return 0, ""


# ── Impact analysis ─────────────────────────────────────────────────────

def compute_impact(incident_id):
    """Per-incident impact summary.

    Compromised: an internal IP that has at least one event in this incident
                 with a kill-chain phase >= 6 (C2 / Actions on Objectives).
    Suspected:   an internal IP touched by the incident with only earlier
                 phases (recon / delivery / exploitation).
    Scope:       single-host (one internal IP touched) or multi-host.
    """
    conn = get_db()
    inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not inc:
        conn.close()
        return None
    events = [dict(r) for r in conn.execute(
        "SELECT * FROM incident_events WHERE incident_id=? ORDER BY timestamp", (incident_id,)
    ).fetchall()]
    # Pull all signatures we'll see for phase classification
    # (we already store sid per event but not the signature text — pull from events list anyway)
    asset_phases = defaultdict(int)  # internal_ip → max phase observed
    asset_alert_count = defaultdict(int)
    for e in events:
        for ip in (e.get("src_ip"), e.get("dest_ip")):
            if not ip or not is_internal(ip):
                continue
            asset_alert_count[ip] += 1
            # We don't have signature text here; phase=0 unless event_summary
            # encodes "[sid X] signature"
            summary = e.get("event_summary") or ""
            if "] " in summary:
                sig = summary.split("] ", 1)[1]
                phase, _ = _phase_for_signature(sig)
                if phase > asset_phases[ip]:
                    asset_phases[ip] = phase
    compromised, suspected = [], []
    for ip, phase in asset_phases.items():
        item = {
            "ip": ip, "max_phase": phase,
            "alert_count": asset_alert_count[ip],
        }
        if phase >= 6:
            compromised.append(item)
        else:
            suspected.append(item)
    compromised.sort(key=lambda x: -x["alert_count"])
    suspected.sort(key=lambda x: -x["alert_count"])

    # Scope
    touched_internal = set(asset_phases.keys())
    scope = "single-host" if len(touched_internal) <= 1 else f"multi-host ({len(touched_internal)} internal assets)"

    # Entry point: oldest event in the incident
    entry_event = events[0] if events else None
    conn.close()

    return {
        "incident_id": incident_id,
        "compromised_count": len(compromised),
        "suspected_count": len(suspected),
        "compromised_assets": compromised,
        "suspected_assets": suspected,
        "scope": scope,
        "entry_point": {
            "timestamp": entry_event.get("timestamp") if entry_event else None,
            "summary": entry_event.get("event_summary") if entry_event else None,
            "src_ip": entry_event.get("src_ip") if entry_event else None,
            "dest_ip": entry_event.get("dest_ip") if entry_event else None,
            "sid": entry_event.get("sid") if entry_event else None,
        } if entry_event else None,
        "total_events": len(events),
    }


# ── Origin / patient zero / escalation sequence ─────────────────────────

def compute_origin(incident_id):
    """First-alert + patient-zero + ordered phase escalation.

    patient_zero: the internal asset that owns the entry-point alert (whoever
                  was the internal endpoint of that first alert)
    escalation:   distinct (sid, signature, phase) tuples in chronological
                  order — gives an analyst the kill-chain sequence in one row
    """
    conn = get_db()
    events = [dict(r) for r in conn.execute(
        "SELECT * FROM incident_events WHERE incident_id=? ORDER BY timestamp", (incident_id,)
    ).fetchall()]
    conn.close()
    if not events:
        return None

    first = events[0]
    # Patient zero: whichever side of the first alert is internal; if both, prefer dest
    pz = None
    src, dst = first.get("src_ip"), first.get("dest_ip")
    if dst and is_internal(dst):
        pz = dst
    elif src and is_internal(src):
        pz = src

    # Escalation sequence: dedup by sid keeping first occurrence of each
    seen_sids = set()
    escalation = []
    for e in events:
        sid = e.get("sid")
        if sid is None or sid in seen_sids:
            continue
        seen_sids.add(sid)
        sig = ""
        if (e.get("event_summary") or "").startswith("[sid "):
            try:
                sig = e["event_summary"].split("] ", 1)[1]
            except IndexError:
                sig = ""
        phase, phase_name = _phase_for_signature(sig)
        escalation.append({
            "sid": sid,
            "signature": sig,
            "phase": phase,
            "phase_name": phase_name,
            "timestamp": e.get("timestamp"),
            "src_ip": e.get("src_ip"),
            "dest_ip": e.get("dest_ip"),
        })

    return {
        "incident_id": incident_id,
        "first_alert": {
            "timestamp": first.get("timestamp"),
            "summary": first.get("event_summary"),
            "src_ip": first.get("src_ip"),
            "dest_ip": first.get("dest_ip"),
            "sid": first.get("sid"),
        },
        "patient_zero": pz,
        "escalation": escalation,
        "escalation_phase_max": max((s["phase"] for s in escalation), default=0),
    }


# ── Pre-detection asset timeline ────────────────────────────────────────

def asset_timeline(asset_ip, minutes=1440):
    """Return last N minutes of activity for the given asset, merged from
    eve.json: alerts + DNS queries + flows. Sorted newest-first.

    Output shape:
      [
        {kind: 'alert'|'dns'|'flow', timestamp, ...details},
        ...
      ]
    """
    out = []
    counts = Counter()
    for ev in iter_events(minutes=minutes):
        s = ev.get("src_ip", "")
        d = ev.get("dest_ip", "")
        if asset_ip not in (s, d):
            continue
        et = ev.get("event_type")
        ts = ev.get("timestamp", "")
        if et == "alert":
            a = ev.get("alert") or {}
            out.append({
                "kind": "alert",
                "timestamp": ts,
                "src_ip": s, "dest_ip": d,
                "signature": a.get("signature", ""),
                "sid": a.get("signature_id"),
                "category": a.get("category", ""),
                "severity": a.get("severity", 3),
            })
        elif et == "dns":
            dns = ev.get("dns") or {}
            out.append({
                "kind": "dns",
                "timestamp": ts,
                "src_ip": s, "dest_ip": d,
                "query": dns.get("rrname") or dns.get("query") or "",
                "rcode": dns.get("rcode", ""),
                "rrtype": dns.get("rrtype", ""),
            })
        elif et == "flow":
            flow = ev.get("flow") or {}
            out.append({
                "kind": "flow",
                "timestamp": ts,
                "src_ip": s, "dest_ip": d,
                "proto": ev.get("proto", ""),
                "app_proto": ev.get("app_proto", ""),
                "src_port": ev.get("src_port"),
                "dest_port": ev.get("dest_port"),
                "bytes": (flow.get("bytes_toserver", 0) or 0) + (flow.get("bytes_toclient", 0) or 0),
            })
        counts[et] += 1
        if len(out) >= 800:  # cap output, keep memory sane
            break
    out.sort(key=lambda x: x["timestamp"], reverse=True)
    return {
        "asset_ip": asset_ip,
        "minutes": minutes,
        "events": out[:500],
        "totals": dict(counts),
        "kind_breakdown": {
            "alerts": sum(1 for e in out if e["kind"] == "alert"),
            "dns": sum(1 for e in out if e["kind"] == "dns"),
            "flows": sum(1 for e in out if e["kind"] == "flow"),
        },
    }


# ── Asset compromise state (post-compromise tracking) ───────────────────

def update_asset_state(asset_ip, status, incident_id=None, last_indicator=""):
    """Upsert a row into asset_compromise_state."""
    conn = get_db()
    conn.execute(
        """INSERT INTO asset_compromise_state (asset_ip, status, since, incident_id, last_indicator)
           VALUES (?,?,datetime('now','localtime'),?,?)
           ON CONFLICT(asset_ip) DO UPDATE SET
               status=excluded.status,
               incident_id=excluded.incident_id,
               last_indicator=excluded.last_indicator,
               updated_at=datetime('now','localtime')""",
        (asset_ip, status, incident_id, last_indicator),
    )
    conn.commit()
    conn.close()


def get_asset_states():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM asset_compromise_state ORDER BY updated_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def reinfection_check():
    """For each asset currently in 'resolved' state, look back 60 min for
    any new alert touching it. If found, flip to 'reinfected' and increment
    the watchlist hit if a watch IOC matches.

    Returns list of newly-reinfected asset IPs.
    """
    conn = get_db()
    resolved = [dict(r) for r in conn.execute(
        "SELECT asset_ip, incident_id FROM asset_compromise_state WHERE status='resolved'"
    ).fetchall()]
    conn.close()
    if not resolved:
        return []
    resolved_set = {r["asset_ip"]: r for r in resolved}
    fired = []
    for ev in iter_events(event_types={"alert"}, minutes=60):
        s, d = ev.get("src_ip", ""), ev.get("dest_ip", "")
        for ip in (s, d):
            if ip in resolved_set:
                update_asset_state(ip, "reinfected",
                                   incident_id=resolved_set[ip]["incident_id"],
                                   last_indicator=(ev.get("alert") or {}).get("signature", "")[:120])
                fired.append(ip)
                break
    return fired
