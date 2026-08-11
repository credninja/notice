"""
Incident/case management CRUD API + IR-lifecycle workflow.

Lifecycle phases (canonical order):
    triage → investigate → contain → eradicate → recover → closed

When an incident is created via /api/incidents/promote-from-alert, it starts
in 'triage' and the first phase log row is opened. Calling
/api/incidents/<id>/phase closes the current phase and opens the next.
"""

import json
import os
import re
import ipaddress
from bottle import request, response
from db import get_db, safe_update


PHASES = ["triage", "investigate", "contain", "eradicate", "recover", "closed"]

# How far back to scan for "related" alerts when auto-clustering on Promote.
# 2 hours is a sensible attack window — long enough to capture recon→exploitation
# progression, short enough to keep the scan cheap.
DEFAULT_CLUSTER_MINUTES = 120
# Cap how many events we attach to one incident — we want the analyst's view to
# stay readable. The summary tells them how many were eligible.
MAX_CLUSTER_EVENTS = 100


def _scan_related_alerts(minutes, attacker_ip=None, victim_ip=None, signature_id=None, mode="attacker"):
    """Scan eve.json for alerts that should cluster with the seed.

    Modes:
      mode='attacker'  — alert is related when src_ip OR dest_ip equals
                         attacker_ip, OR signature_id matches.
                         Used by promote-from-alert and promote-from-adversary.
      mode='pair'      — alert is related when (src_ip, dest_ip) is exactly
                         (attacker_ip, victim_ip) or the reverse. Strictest;
                         used by promote-from-chain to keep the cluster
                         scoped to one attacker/victim conversation.

    Returns (alerts_list, frequency_counter).
      frequency_counter is a Counter keyed by (ioc_type, value) → occurrences.
      The caller uses this to rank auxiliary IOCs.
    """
    from eve_reader import iter_events
    from collections import Counter
    out = []
    freq = Counter()
    for ev in iter_events(event_types={"alert"}, minutes=minutes):
        s = ev.get("src_ip", "")
        d = ev.get("dest_ip", "")
        a = ev.get("alert", {}) or {}
        sid = a.get("signature_id")
        match = False
        if mode == "pair":
            pair = {s, d}
            if attacker_ip and victim_ip and attacker_ip in pair and victim_ip in pair:
                match = True
        else:  # 'attacker'
            if attacker_ip and (s == attacker_ip or d == attacker_ip):
                match = True
            elif signature_id and sid == signature_id:
                match = True
        if not match:
            continue
        out.append({
            "timestamp": ev.get("timestamp", ""),
            "signature_id": sid,
            "signature": a.get("signature", ""),
            "src_ip": s,
            "dest_ip": d,
            "severity": a.get("severity", 3),
            "category": a.get("category", ""),
            "proto": ev.get("proto", ""),
            "dest_port": ev.get("dest_port"),
        })
        # Tally frequencies for IOC ranking
        if s:
            freq[("src_ip", s)] += 1
        if d:
            freq[("dest_ip", d)] += 1
        if sid:
            freq[("signature_id", str(sid))] += 1
        if len(out) >= MAX_CLUSTER_EVENTS * 2:
            break
    return out, freq


def _curate_cluster_iocs(freq_counter, max_external_ips=20, max_signatures=10):
    """Pick the most relevant IOCs from a cluster's frequency map.

    SOC convention: indicators are external markers (attacker IPs, malicious
    domains, signatures), not internal hosts. So:
      - src_ip / dest_ip IOCs are kept only if the IP is EXTERNAL (outside 10.0.0.0/8)
      - top max_external_ips by frequency
      - top max_signatures signature_ids by frequency

    Returns: list of (type, value) tuples ordered by descending frequency.
    """
    from eve_reader import is_internal
    ext_ips = []
    sigs = []
    for (t, v), n in freq_counter.items():
        if t in ("src_ip", "dest_ip"):
            if is_internal(v):
                continue
            ext_ips.append((t, v, n))
        elif t == "signature_id":
            sigs.append((t, v, n))
    ext_ips.sort(key=lambda x: -x[2])
    sigs.sort(key=lambda x: -x[2])
    return [(t, v) for t, v, _ in ext_ips[:max_external_ips]] + \
           [(t, v) for t, v, _ in sigs[:max_signatures]]


def _attach_cluster(conn, incident_id, related_alerts, freq_counter, primary_seen=None):
    """Persist clustered alerts as incident_events + curated auxiliary IOCs.

    primary_seen: set of (type, str(value)) already inserted as primary IOCs;
                  used to avoid double-inserting them as auxiliary.

    Returns (events_attached, ioc_count_added, distinct_signatures).
    """
    events_attached = 0
    sigs = set()
    for ev in related_alerts[:MAX_CLUSTER_EVENTS]:
        sid = ev.get("signature_id")
        try:
            sid_int = int(sid) if sid is not None else None
        except (TypeError, ValueError):
            sid_int = None
        conn.execute(
            """INSERT INTO incident_events
               (incident_id, event_type, event_summary, src_ip, dest_ip, timestamp, sid)
               VALUES (?,?,?,?,?,?,?)""",
            (incident_id, "alert", f"[sid {sid}] {ev.get('signature','')[:140]}",
             ev.get("src_ip", ""), ev.get("dest_ip", ""), ev.get("timestamp", ""), sid_int),
        )
        events_attached += 1
        if ev.get("signature"):
            sigs.add(ev["signature"])
    # Curated auxiliary IOCs (external IPs only, ranked by frequency)
    aux = _curate_cluster_iocs(freq_counter)
    seen = primary_seen if primary_seen is not None else set()
    seen_before = len(seen)
    _attach_iocs(conn, incident_id, aux, is_primary=False, frequency_map=dict(freq_counter), seen=seen)
    iocs_added = len(seen) - seen_before
    return events_attached, iocs_added, len(sigs)


def _attach_iocs(conn, incident_id, iocs, is_primary=False, frequency_map=None, seen=None):
    """Insert IOC rows.

    iocs:           list of (type, value) tuples
    is_primary:     mark these as seed/primary indicators (visible at top of UI)
    frequency_map:  optional dict keyed by (type, str(value)) → count, used to
                    fill the frequency column for cluster-derived IOCs
    seen:           caller-provided dedup set so primary + auxiliary inserts
                    don't double-insert the same IOC. Function returns it so
                    the caller can chain calls.
    """
    if seen is None:
        seen = set()
    for t, v in iocs:
        if not v or (t, str(v)) in seen:
            continue
        seen.add((t, str(v)))
        freq = (frequency_map or {}).get((t, str(v)), 1)
        conn.execute(
            "INSERT INTO incident_iocs (incident_id, ioc_type, ioc_value, is_primary, frequency) "
            "VALUES (?,?,?,?,?)",
            (incident_id, t, str(v), 1 if is_primary else 0, int(freq)),
        )
    return seen


def _open_phase_log(conn, incident_id, phase, by="analyst"):
    """Insert a new phase log row (closes nothing on its own)."""
    conn.execute(
        "INSERT INTO incident_phase_log (incident_id, phase, started_at, completed_by) VALUES (?,?,datetime('now','localtime'),?)",
        (incident_id, phase, by),
    )


def _close_active_phase(conn, incident_id, by="analyst", notes=""):
    """Close whichever phase is currently open (latest started, no completed_at)."""
    row = conn.execute(
        "SELECT id FROM incident_phase_log WHERE incident_id=? AND completed_at IS NULL ORDER BY started_at DESC LIMIT 1",
        (incident_id,),
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE incident_phase_log SET completed_at=datetime('now','localtime'), completed_by=?, notes=? WHERE id=?",
            (by, notes, row["id"]),
        )


def register(app):

    @app.get("/api/incidents")
    def list_incidents():
        conn = get_db()
        status = request.query.get("status", "")
        severity = request.query.get("severity", "")
        assigned_to = request.query.get("assigned_to", "").strip()
        q = request.query.get("q", "").strip()

        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if assigned_to:
            query += " AND assigned_to = ?"
            params.append(assigned_to)
        if q:
            # Search title, description, attacker_ip, victim_ip, signature, signature_id
            like = f"%{q}%"
            query += (" AND (title LIKE ? OR description LIKE ? OR attacker_ip LIKE ? "
                      "OR victim_ip LIKE ? OR signature LIKE ? OR CAST(signature_id AS TEXT) LIKE ? "
                      "OR CAST(id AS TEXT) LIKE ?)")
            params.extend([like, like, like, like, like, like, like])
        query += " ORDER BY created_at DESC"

        rows = conn.execute(query, params).fetchall()
        incidents = []
        for r in rows:
            inc = dict(r)
            event_count = conn.execute(
                "SELECT COUNT(*) FROM incident_events WHERE incident_id = ?", (r["id"],)
            ).fetchone()[0]
            note_count = conn.execute(
                "SELECT COUNT(*) FROM incident_notes WHERE incident_id = ?", (r["id"],)
            ).fetchone()[0]
            inc["event_count"] = event_count
            inc["note_count"] = note_count
            incidents.append(inc)
        conn.close()
        return {"incidents": incidents}

    @app.post("/api/incidents")
    def create_incident():
        data = request.json or {}
        title = data.get("title", "").strip()
        if not title:
            response.status = 400
            return {"error": "Title is required"}

        conn = get_db()
        cur = conn.execute(
            "INSERT INTO incidents (title, description, severity, assigned_to) VALUES (?, ?, ?, ?)",
            (title, data.get("description", ""), data.get("severity", "medium"), data.get("assigned_to", "")),
        )
        incident_id = cur.lastrowid
        conn.commit()
        inc = dict(conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone())
        conn.close()
        response.status = 201
        return inc

    @app.get("/api/incidents/<incident_id:int>")
    def get_incident(incident_id):
        conn = get_db()
        inc = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not inc:
            conn.close()
            response.status = 404
            return {"error": "Incident not found"}

        events = [dict(r) for r in conn.execute(
            "SELECT * FROM incident_events WHERE incident_id = ? ORDER BY timestamp", (incident_id,)
        ).fetchall()]
        # Enrich each event with the rule that fired it.  Bulk-look-up by sid
        # so we don't hit the rule-files index per row. Events that pre-date
        # the sid column will fall back to parsing the summary string.
        try:
            from analyzers.suricata_rules import get_rules_by_sids
            sids = []
            import re as _re
            _sid_pat = _re.compile(r"\[sid (\d+)\]")
            for ev in events:
                if ev.get("sid"):
                    sids.append(ev["sid"])
                else:
                    m = _sid_pat.search(ev.get("event_summary") or "")
                    if m:
                        ev["sid"] = int(m.group(1))
                        sids.append(ev["sid"])
            rule_map = get_rules_by_sids(set(sids)) if sids else {}
            for ev in events:
                rule = rule_map.get(ev.get("sid"))
                if rule:
                    ev["rule"] = {
                        "sid": rule["sid"],
                        "msg": rule.get("msg", ""),
                        "action": rule.get("action", ""),
                        "classtype": rule.get("classtype", ""),
                        "category": rule.get("category", ""),
                        "source": rule.get("source", ""),
                        "enabled": rule.get("enabled", True),
                        "is_asset_specific": rule.get("is_asset_specific", False),
                        "is_custom": rule.get("is_custom", False),
                        "raw_line": rule.get("raw_line", ""),
                    }
                else:
                    ev["rule"] = None
        except Exception:
            for ev in events:
                ev["rule"] = None
        notes = [dict(r) for r in conn.execute(
            "SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at", (incident_id,)
        ).fetchall()]
        iocs = [dict(r) for r in conn.execute(
            "SELECT * FROM incident_iocs WHERE incident_id = ? ORDER BY created_at", (incident_id,)
        ).fetchall()]
        phase_log = [dict(r) for r in conn.execute(
            "SELECT * FROM incident_phase_log WHERE incident_id = ? ORDER BY started_at", (incident_id,)
        ).fetchall()]
        # Linked containment + watch records (helps the workflow show "what's been done")
        blocklist_rows = [dict(r) for r in conn.execute(
            "SELECT * FROM blocklist WHERE incident_id = ? ORDER BY created_at DESC", (incident_id,)
        ).fetchall()]
        quarantine_rows = [dict(r) for r in conn.execute(
            "SELECT * FROM quarantine WHERE incident_id = ? ORDER BY created_at DESC", (incident_id,)
        ).fetchall()]
        watchlist_rows = [dict(r) for r in conn.execute(
            "SELECT * FROM watchlist WHERE incident_id = ? ORDER BY created_at DESC", (incident_id,)
        ).fetchall()]
        conn.close()

        result = dict(inc)
        result["events"] = events
        result["notes"] = notes
        result["iocs"] = iocs
        result["phase_log"] = phase_log
        result["blocklist"] = blocklist_rows
        result["quarantine"] = quarantine_rows
        result["watchlist"] = watchlist_rows
        result["phases"] = PHASES
        return result

    @app.post("/api/incidents/promote-from-alert")
    def promote_from_alert():
        """Create a new incident from an alert. Pre-fills IOCs (src/dst/sid/sig)
        and opens the 'triage' phase. Idempotent on (signature_id, src_ip, dest_ip)
        within 24h — re-promoting the same alert returns the existing incident."""
        data = request.json or {}
        sid = data.get("signature_id")
        src = (data.get("src_ip") or "").strip()
        dst = (data.get("dest_ip") or "").strip()
        sig = (data.get("signature") or "").strip()
        if not sig and not (sid or src or dst):
            response.status = 400
            return {"error": "alert info required (signature, signature_id, src_ip, dest_ip)"}

        severity = data.get("severity", "medium")
        if severity not in ("critical", "high", "medium", "low"):
            severity = "medium"
        title = data.get("title") or (f"Incident: {sig}" if sig else f"Incident from alert sid={sid}")

        conn = get_db()
        # Idempotency: same sid + src + dst already promoted in last 24h?
        existing = conn.execute(
            "SELECT * FROM incidents WHERE signature_id=? AND attacker_ip=? AND victim_ip=? "
            "AND created_at > datetime('now','-1 day') ORDER BY id DESC LIMIT 1",
            (sid, src, dst),
        ).fetchone()
        if existing:
            existing_id = existing["id"]
            ev_count = conn.execute(
                "SELECT COUNT(*) FROM incident_events WHERE incident_id=?", (existing_id,)
            ).fetchone()[0]
            cluster_info = None
            # Auto-heal: if the existing incident was created before auto-cluster
            # shipped (or cluster previously failed), back-fill the cluster now.
            if ev_count == 0:
                cluster_minutes = int(data.get("cluster_minutes", DEFAULT_CLUSTER_MINUTES) or DEFAULT_CLUSTER_MINUTES)
                related, freq = _scan_related_alerts(
                    cluster_minutes,
                    attacker_ip=existing["attacker_ip"] or src or None,
                    signature_id=existing["signature_id"] or sid,
                    mode="attacker",
                )
                # Pre-populate the seen set with whatever's already in incident_iocs
                # so the auxiliary insert doesn't dup primary indicators.
                existing_iocs = conn.execute(
                    "SELECT ioc_type, ioc_value FROM incident_iocs WHERE incident_id=?",
                    (existing_id,),
                ).fetchall()
                seen = {(r["ioc_type"], str(r["ioc_value"])) for r in existing_iocs}
                events_attached, iocs_added, sigs_seen = _attach_cluster(
                    conn, existing_id, related, freq, primary_seen=seen,
                )
                conn.commit()
                cluster_info = {
                    "events_attached": events_attached,
                    "alerts_eligible": len(related),
                    "iocs_added": iocs_added,
                    "distinct_signatures": sigs_seen,
                    "window_minutes": cluster_minutes,
                    "back_filled": True,
                }
            conn.close()
            return {"existing": True, "incident": dict(existing), "cluster": cluster_info}

        cur = conn.execute(
            """INSERT INTO incidents
               (title, description, severity, status, phase, phase_started_at,
                attacker_ip, victim_ip, signature_id, signature, assigned_to)
               VALUES (?,?,?,?,?,datetime('now','localtime'),?,?,?,?,?)""",
            (title, data.get("description", ""), severity, "open", "triage",
             src, dst, sid, sig, data.get("assigned_to", "")),
        )
        incident_id = cur.lastrowid
        # Mark the seed indicators as PRIMARY so the UI surfaces them at the top
        primary_seen = _attach_iocs(conn, incident_id, [
            ("src_ip", src),
            ("dest_ip", dst),
            ("signature_id", sid),
            ("signature", sig),
        ], is_primary=True)
        _open_phase_log(conn, incident_id, "triage")

        # Auto-cluster on attacker_ip OR signature_id (drops victim_ip from the
        # match rule — that catches too much noise when the victim is a busy
        # internal host).
        cluster_minutes = int(data.get("cluster_minutes", DEFAULT_CLUSTER_MINUTES) or DEFAULT_CLUSTER_MINUTES)
        related, freq = _scan_related_alerts(
            cluster_minutes,
            attacker_ip=src or None,
            signature_id=sid,
            mode="attacker",
        )
        events_attached, iocs_added, sigs_seen = _attach_cluster(
            conn, incident_id, related, freq, primary_seen=primary_seen,
        )

        conn.commit()
        inc = dict(conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone())
        conn.close()
        response.status = 201
        return {
            "existing": False,
            "incident": inc,
            "cluster": {
                "events_attached": events_attached,
                "alerts_eligible": len(related),
                "iocs_added": iocs_added,
                "distinct_signatures": sigs_seen,
                "window_minutes": cluster_minutes,
            },
        }

    @app.post("/api/incidents/promote-from-chain")
    def promote_from_chain():
        """Promote an attack chain (from Security → Attack Chains) to an incident.

        Body:
            attacker_ip, victim_ip   — chain endpoints (required)
            chain_summary            — narrative string for the incident description
            cluster_minutes          — how far back to pull related alerts (default 120)
            severity                 — defaults to 'high' (chains imply multi-phase progression)
            title                    — optional; auto-generated if omitted
        """
        data = request.json or {}
        attacker = (data.get("attacker_ip") or "").strip()
        victim = (data.get("victim_ip") or "").strip()
        if not attacker or not victim:
            response.status = 400
            return {"error": "attacker_ip and victim_ip are required"}
        severity = data.get("severity", "high")
        if severity not in ("critical", "high", "medium", "low"):
            severity = "high"
        title = data.get("title") or f"Attack Chain: {attacker} → {victim}"
        cluster_minutes = int(data.get("cluster_minutes", DEFAULT_CLUSTER_MINUTES) or DEFAULT_CLUSTER_MINUTES)

        conn = get_db()
        existing = conn.execute(
            "SELECT * FROM incidents WHERE attacker_ip=? AND victim_ip=? "
            "AND created_at > datetime('now','-1 day') ORDER BY id DESC LIMIT 1",
            (attacker, victim),
        ).fetchone()
        if existing:
            existing_id = existing["id"]
            ev_count = conn.execute(
                "SELECT COUNT(*) FROM incident_events WHERE incident_id=?", (existing_id,)
            ).fetchone()[0]
            cluster_info = None
            if ev_count == 0:
                related, freq = _scan_related_alerts(
                    cluster_minutes, attacker_ip=attacker, victim_ip=victim, mode="pair",
                )
                existing_iocs = conn.execute(
                    "SELECT ioc_type, ioc_value FROM incident_iocs WHERE incident_id=?", (existing_id,)
                ).fetchall()
                seen = {(r["ioc_type"], str(r["ioc_value"])) for r in existing_iocs}
                events_attached, iocs_added, sigs_seen = _attach_cluster(
                    conn, existing_id, related, freq, primary_seen=seen,
                )
                conn.commit()
                cluster_info = {
                    "events_attached": events_attached, "alerts_eligible": len(related),
                    "iocs_added": iocs_added, "distinct_signatures": sigs_seen,
                    "window_minutes": cluster_minutes, "back_filled": True,
                }
            conn.close()
            return {"existing": True, "incident": dict(existing), "cluster": cluster_info}

        cur = conn.execute(
            """INSERT INTO incidents
               (title, description, severity, status, phase, phase_started_at,
                attacker_ip, victim_ip, assigned_to)
               VALUES (?,?,?,?,?,datetime('now','localtime'),?,?,?)""",
            (title, data.get("chain_summary", ""), severity, "open", "triage",
             attacker, victim, data.get("assigned_to", "")),
        )
        incident_id = cur.lastrowid
        primary_seen = _attach_iocs(conn, incident_id, [
            ("src_ip", attacker),
            ("dest_ip", victim),
        ], is_primary=True)
        _open_phase_log(conn, incident_id, "triage")

        # Chain mode: only alerts strictly between attacker↔victim cluster in
        related, freq = _scan_related_alerts(
            cluster_minutes, attacker_ip=attacker, victim_ip=victim, mode="pair",
        )
        events_attached, iocs_added, sigs_seen = _attach_cluster(
            conn, incident_id, related, freq, primary_seen=primary_seen,
        )

        conn.commit()
        inc = dict(conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone())
        conn.close()
        response.status = 201
        return {
            "existing": False,
            "incident": inc,
            "cluster": {
                "events_attached": events_attached,
                "alerts_eligible": len(related),
                "iocs_added": iocs_added,
                "distinct_signatures": sigs_seen,
                "window_minutes": cluster_minutes,
            },
        }

    @app.post("/api/incidents/promote-from-adversary")
    def promote_from_adversary():
        """Open an incident covering ALL alerts from one attacker IP.

        Body:
            attacker_ip      — the adversary IP (required)
            adversary_label  — for the title (e.g. country, owner)
            cluster_minutes  — how far back; defaults to 1440 (24h) since
                               adversaries are tracked over longer periods
            severity         — defaults to 'high'
        """
        data = request.json or {}
        attacker = (data.get("attacker_ip") or "").strip()
        if not attacker:
            response.status = 400
            return {"error": "attacker_ip is required"}
        severity = data.get("severity", "high")
        if severity not in ("critical", "high", "medium", "low"):
            severity = "high"
        label = data.get("adversary_label") or attacker
        title = data.get("title") or f"Adversary Investigation: {label}"
        # Adversaries are observed over a longer window than a single chain
        cluster_minutes = int(data.get("cluster_minutes", 1440) or 1440)

        conn = get_db()
        # Idempotency: same attacker promoted in the last 24h?
        existing = conn.execute(
            "SELECT * FROM incidents WHERE attacker_ip=? "
            "AND created_at > datetime('now','-1 day') ORDER BY id DESC LIMIT 1",
            (attacker,),
        ).fetchone()
        if existing:
            existing_id = existing["id"]
            ev_count = conn.execute(
                "SELECT COUNT(*) FROM incident_events WHERE incident_id=?", (existing_id,)
            ).fetchone()[0]
            cluster_info = None
            if ev_count == 0:
                related, freq = _scan_related_alerts(cluster_minutes, attacker_ip=attacker, mode="attacker")
                existing_iocs = conn.execute(
                    "SELECT ioc_type, ioc_value FROM incident_iocs WHERE incident_id=?", (existing_id,)
                ).fetchall()
                seen = {(r["ioc_type"], str(r["ioc_value"])) for r in existing_iocs}
                events_attached, iocs_added, sigs_seen = _attach_cluster(
                    conn, existing_id, related, freq, primary_seen=seen,
                )
                conn.commit()
                cluster_info = {
                    "events_attached": events_attached, "alerts_eligible": len(related),
                    "iocs_added": iocs_added, "distinct_signatures": sigs_seen,
                    "window_minutes": cluster_minutes, "back_filled": True,
                }
            conn.close()
            return {"existing": True, "incident": dict(existing), "cluster": cluster_info}

        cur = conn.execute(
            """INSERT INTO incidents
               (title, description, severity, status, phase, phase_started_at,
                attacker_ip, assigned_to)
               VALUES (?,?,?,?,?,datetime('now','localtime'),?,?)""",
            (title, data.get("description", ""), severity, "open", "triage",
             attacker, data.get("assigned_to", "")),
        )
        incident_id = cur.lastrowid
        primary_seen = _attach_iocs(conn, incident_id, [("src_ip", attacker)], is_primary=True)
        _open_phase_log(conn, incident_id, "triage")

        related, freq = _scan_related_alerts(cluster_minutes, attacker_ip=attacker, mode="attacker")
        events_attached, iocs_added, sigs_seen = _attach_cluster(
            conn, incident_id, related, freq, primary_seen=primary_seen,
        )

        conn.commit()
        inc = dict(conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone())
        conn.close()
        response.status = 201
        return {
            "existing": False,
            "incident": inc,
            "cluster": {
                "events_attached": events_attached,
                "alerts_eligible": len(related),
                "iocs_added": iocs_added,
                "distinct_signatures": sigs_seen,
                "window_minutes": cluster_minutes,
            },
        }

    @app.post("/api/incidents/<incident_id:int>/phase")
    def advance_phase(incident_id):
        """Advance to the next phase (default) or jump to a specific phase.
        Body: { target?: 'investigate'|..., notes?: '...', by?: 'analyst' }.
        Closes the active phase log row, opens a new one, and updates incidents.phase."""
        data = request.json or {}
        notes = (data.get("notes") or "").strip()
        by = (data.get("by") or "analyst").strip()
        target = data.get("target")

        conn = get_db()
        inc = conn.execute("SELECT phase, status FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not inc:
            conn.close()
            response.status = 404
            return {"error": "Incident not found"}
        cur_phase = inc["phase"] or "triage"

        if target:
            if target not in PHASES:
                conn.close()
                response.status = 400
                return {"error": f"unknown phase '{target}'. Must be one of: {PHASES}"}
            next_phase = target
        else:
            try:
                idx = PHASES.index(cur_phase)
            except ValueError:
                idx = 0
            if idx >= len(PHASES) - 1:
                conn.close()
                response.status = 400
                return {"error": "already at final phase 'closed'"}
            next_phase = PHASES[idx + 1]

        _close_active_phase(conn, incident_id, by=by, notes=notes)
        _open_phase_log(conn, incident_id, next_phase, by=by)
        new_status = "closed" if next_phase == "closed" else (
            "investigating" if next_phase in ("investigate", "contain", "eradicate", "recover") else "open"
        )
        resolved_clause = ", resolved_at=datetime('now','localtime')" if next_phase == "closed" else ""
        conn.execute(
            f"UPDATE incidents SET phase=?, phase_started_at=datetime('now','localtime'), status=?, "
            f"updated_at=datetime('now','localtime'){resolved_clause} WHERE id=?",
            (next_phase, new_status, incident_id),
        )
        conn.commit()
        inc = dict(conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone())
        conn.close()
        return {"ok": True, "phase": next_phase, "status": new_status, "incident": inc}

    @app.post("/api/incidents/<incident_id:int>/iocs")
    def add_ioc(incident_id):
        """Attach one or more IOCs. Body: {iocs:[{type,value},...]} or single {type,value}."""
        data = request.json or {}
        items = data.get("iocs")
        if not items:
            items = [{"type": data.get("type"), "value": data.get("value")}]
        conn = get_db()
        if not conn.execute("SELECT id FROM incidents WHERE id=?", (incident_id,)).fetchone():
            conn.close(); response.status = 404
            return {"error": "Incident not found"}
        _attach_iocs(conn, incident_id, [(i.get("type"), i.get("value")) for i in items if i.get("value")])
        conn.commit()
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM incident_iocs WHERE incident_id=? ORDER BY created_at", (incident_id,)
        ).fetchall()]
        conn.close()
        return {"iocs": rows}

    @app.delete("/api/incidents/<incident_id:int>/iocs/<ioc_id:int>")
    def remove_ioc(incident_id, ioc_id):
        conn = get_db()
        conn.execute("DELETE FROM incident_iocs WHERE id=? AND incident_id=?", (ioc_id, incident_id))
        conn.commit()
        conn.close()
        return {"ok": True}

    @app.post("/api/incidents/<incident_id:int>/recluster")
    def recluster(incident_id):
        """Manually re-run the auto-cluster on an existing incident.
        Body: { cluster_minutes?: 120 }. Useful for incidents created before
        auto-cluster shipped, or when the analyst wants a wider sweep."""
        data = request.json or {}
        cluster_minutes = int(data.get("cluster_minutes", DEFAULT_CLUSTER_MINUTES) or DEFAULT_CLUSTER_MINUTES)
        conn = get_db()
        inc = conn.execute(
            "SELECT * FROM incidents WHERE id=?", (incident_id,)
        ).fetchone()
        if not inc:
            conn.close(); response.status = 404
            return {"error": "Incident not found"}
        # Pick mode based on what the incident has: chain (both endpoints) → pair,
        # otherwise attacker (any direction OR same signature)
        if inc["attacker_ip"] and inc["victim_ip"]:
            related, freq = _scan_related_alerts(
                cluster_minutes,
                attacker_ip=inc["attacker_ip"],
                victim_ip=inc["victim_ip"],
                mode="pair",
            )
        else:
            related, freq = _scan_related_alerts(
                cluster_minutes,
                attacker_ip=inc["attacker_ip"] or None,
                signature_id=inc["signature_id"],
                mode="attacker",
            )
        existing_iocs = conn.execute(
            "SELECT ioc_type, ioc_value FROM incident_iocs WHERE incident_id=?", (incident_id,)
        ).fetchall()
        seen = {(r["ioc_type"], str(r["ioc_value"])) for r in existing_iocs}
        events_attached, iocs_added, sigs_seen = _attach_cluster(
            conn, incident_id, related, freq, primary_seen=seen,
        )
        conn.commit()
        conn.close()
        return {
            "ok": True,
            "cluster": {
                "events_attached": events_attached,
                "alerts_eligible": len(related),
                "iocs_added": iocs_added,
                "distinct_signatures": sigs_seen,
                "window_minutes": cluster_minutes,
            },
        }

    # ── Incident closure (TP/FP verdict + metadata for daily report) ────
    @app.post("/api/incidents/<incident_id:int>/close")
    def close_incident(incident_id):
        """Close an incident with verdict and closure metadata.
        Body: {verdict, classification, certin_category, impact, mitre_tactic,
               mitre_technique, summary, actions_taken, root_cause,
               lessons_learned, closed_by}
        """
        data = request.json or {}
        verdict = data.get("verdict", "").strip()
        if verdict not in ("true_positive", "false_positive"):
            response.status = 400
            return {"error": "verdict must be 'true_positive' or 'false_positive'"}

        conn = get_db()
        inc = conn.execute("SELECT id, phase, status FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not inc:
            conn.close()
            response.status = 404
            return {"error": "Incident not found"}

        closed_by = (data.get("closed_by") or "analyst").strip()
        conn.execute("""
            UPDATE incidents SET
                verdict=?, status='closed', phase='closed',
                resolved_at=datetime('now','localtime'),
                updated_at=datetime('now','localtime'),
                closure_classification=?, closure_certin_category=?,
                closure_impact=?, closure_mitre_tactic=?,
                closure_mitre_technique=?, closure_summary=?,
                rca_root_cause=?, rca_lessons_learned=?,
                rca_actions_taken=?, closed_by=?
            WHERE id=?""",
            (verdict,
             data.get("classification", ""),
             data.get("certin_category", ""),
             data.get("impact", ""),
             data.get("mitre_tactic", ""),
             data.get("mitre_technique", ""),
             data.get("summary", ""),
             data.get("root_cause", ""),
             data.get("lessons_learned", ""),
             data.get("actions_taken", ""),
             closed_by,
             incident_id))

        _close_active_phase(conn, incident_id, by=closed_by, notes=f"Closed as {verdict}")
        _open_phase_log(conn, incident_id, "closed", by=closed_by)

        conn.commit()
        result = dict(conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone())
        conn.close()
        return {"ok": True, "incident": result}

    # ── Daily incident closure report ────────────────────────────────────
    @app.get("/api/reports/daily-closures")
    def daily_closure_report():
        """Return closed incidents for a given date (default today IST).
        Query params: date=YYYY-MM-DD
        """
        date_str = request.query.get("date", "")
        conn = get_db()
        if not date_str:
            date_str = conn.execute("SELECT date('now','localtime')").fetchone()[0]

        rows = conn.execute("""
            SELECT i.*,
                   (SELECT COUNT(*) FROM incident_events WHERE incident_id=i.id) AS event_count,
                   (SELECT COUNT(*) FROM incident_iocs WHERE incident_id=i.id) AS ioc_count
            FROM incidents i
            WHERE date(i.resolved_at)=? AND i.status='closed'
            ORDER BY i.resolved_at DESC
        """, (date_str,)).fetchall()

        incidents = [dict(r) for r in rows]
        tp = sum(1 for i in incidents if i.get("verdict") == "true_positive")
        fp = sum(1 for i in incidents if i.get("verdict") == "false_positive")
        sev_counts = {}
        class_counts = {}
        tactic_counts = {}
        certin_counts = {}
        for inc in incidents:
            sev_counts[inc.get("severity", "medium")] = sev_counts.get(inc.get("severity", "medium"), 0) + 1
            c = inc.get("closure_classification") or "Unclassified"
            class_counts[c] = class_counts.get(c, 0) + 1
            t = inc.get("closure_mitre_tactic") or ""
            if t:
                tactic_counts[t] = tactic_counts.get(t, 0) + 1
            cert = inc.get("closure_certin_category") or ""
            if cert:
                certin_counts[cert] = certin_counts.get(cert, 0) + 1

        conn.close()
        return {
            "date": date_str,
            "total_closed": len(incidents),
            "true_positives": tp,
            "false_positives": fp,
            "by_severity": sev_counts,
            "by_classification": class_counts,
            "by_mitre_tactic": tactic_counts,
            "by_certin_category": certin_counts,
            "incidents": incidents,
        }

    @app.get("/api/reports/daily-closures/export")
    def export_daily_closures():
        """Export daily closures as CSV.
        Query params: date=YYYY-MM-DD, limit=20|50|100 (omit for all)
        """
        import io, csv
        date_str = request.query.get("date", "")
        limit = request.query.get("limit", "")
        conn = get_db()
        if not date_str:
            date_str = conn.execute("SELECT date('now','localtime')").fetchone()[0]

        # Optional: analyst-picked subset via ids=1,2,3
        ids_param = request.query.get("ids", "").strip()
        selected_ids = [int(x) for x in ids_param.split(",") if x.strip().isdigit()] if ids_param else []

        if selected_ids:
            placeholders = ",".join("?" * len(selected_ids))
            query = f"""
                SELECT id, title, severity, verdict, closure_classification,
                       closure_certin_category, closure_impact, closure_mitre_tactic,
                       closure_mitre_technique, closure_summary, rca_root_cause,
                       rca_actions_taken, rca_lessons_learned, closed_by,
                       attacker_ip, victim_ip, signature, created_at, resolved_at
                FROM incidents
                WHERE id IN ({placeholders}) AND status='closed'
                ORDER BY resolved_at DESC
            """
            params = list(selected_ids)
        else:
            query = """
                SELECT id, title, severity, verdict, closure_classification,
                       closure_certin_category, closure_impact, closure_mitre_tactic,
                       closure_mitre_technique, closure_summary, rca_root_cause,
                       rca_actions_taken, rca_lessons_learned, closed_by,
                       attacker_ip, victim_ip, signature, created_at, resolved_at
                FROM incidents
                WHERE date(resolved_at)=? AND status='closed'
                ORDER BY resolved_at DESC
            """
            params = [date_str]
            if limit and limit.isdigit():
                query += " LIMIT ?"
                params.append(int(limit))

        rows = conn.execute(query, params).fetchall()
        # Fetch evidence per incident
        evidence_map = {}
        if rows:
            ids = [r["id"] for r in rows]
            placeholders = ",".join("?" * len(ids))
            ev_rows = conn.execute(
                f"SELECT incident_id, filename, file_size, description, hash_sha256, uploaded_at "
                f"FROM evidence WHERE incident_id IN ({placeholders}) ORDER BY uploaded_at",
                ids,
            ).fetchall()
            for ev in ev_rows:
                evidence_map.setdefault(ev["incident_id"], []).append(dict(ev))
        conn.close()

        suffix = f"_top{limit}" if limit and limit.isdigit() else ""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Incident ID", "Title", "Severity", "Verdict", "Classification (NIST)",
            "CERT-In Category", "Impact Level", "MITRE Tactic", "MITRE Technique",
            "Closure Summary", "Root Cause", "Actions Taken", "Lessons Learned",
            "Closed By", "Source IP", "Destination IP", "Signature",
            "Created At", "Closed At", "Evidence Count", "Evidence Files",
        ])
        for r in rows:
            ev_list = evidence_map.get(r["id"], [])
            ev_summary = " | ".join(
                f"{e['filename']} ({(e.get('file_size',0) or 0)//1024}KB) sha256:{(e.get('hash_sha256','') or '')[:16]}"
                for e in ev_list
            ) if ev_list else "-"
            writer.writerow([
                f"INC-{r['id']:04d}", r["title"], r["severity"],
                "True Positive" if r["verdict"] == "true_positive" else "False Positive",
                r["closure_classification"] or "-", r["closure_certin_category"] or "-",
                r["closure_impact"] or "-", r["closure_mitre_tactic"] or "-",
                r["closure_mitre_technique"] or "-", r["closure_summary"] or "-",
                r["rca_root_cause"] or "-", r["rca_actions_taken"] or "-",
                r["rca_lessons_learned"] or "-", r["closed_by"] or "-",
                r["attacker_ip"] or "-", r["victim_ip"] or "-",
                r["signature"] or "-", r["created_at"], r["resolved_at"],
                len(ev_list), ev_summary,
            ])

        response.content_type = "text/csv"
        response.headers["Content-Disposition"] = f'attachment; filename="NOTICE_Daily_Incident_Report_{date_str}{suffix}.csv"'
        return output.getvalue()

    @app.get("/api/reports/daily-closures/report")
    def daily_closure_html_report():
        """Professional HTML report for daily closures — designed for Print-to-PDF.
        Query params: date=YYYY-MM-DD, limit=20|50|100 (omit for all)
        """
        from html import escape as h_esc
        import math
        date_str = request.query.get("date", "")
        limit = request.query.get("limit", "")
        ids_param = request.query.get("ids", "").strip()
        selected_ids = [int(x) for x in ids_param.split(",") if x.strip().isdigit()] if ids_param else []
        conn = get_db()
        if not date_str:
            date_str = conn.execute("SELECT date('now','localtime')").fetchone()[0]

        if selected_ids:
            placeholders = ",".join("?" * len(selected_ids))
            query = f"""
                SELECT i.*,
                       (SELECT COUNT(*) FROM incident_events WHERE incident_id=i.id) AS event_count,
                       (SELECT COUNT(*) FROM incident_iocs WHERE incident_id=i.id) AS ioc_count
                FROM incidents i
                WHERE i.id IN ({placeholders}) AND i.status='closed'
                ORDER BY i.resolved_at DESC
            """
            params = list(selected_ids)
        else:
            query = """
                SELECT i.*,
                       (SELECT COUNT(*) FROM incident_events WHERE incident_id=i.id) AS event_count,
                       (SELECT COUNT(*) FROM incident_iocs WHERE incident_id=i.id) AS ioc_count
                FROM incidents i
                WHERE date(i.resolved_at)=? AND i.status='closed'
                ORDER BY i.resolved_at DESC
            """
            params = [date_str]
            if limit and limit.isdigit():
                query += " LIMIT ?"
                params.append(int(limit))

        rows = conn.execute(query, params).fetchall()
        all_count = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE date(resolved_at)=? AND status='closed'",
            (date_str,)
        ).fetchone()[0]
        conn.close()

        incidents = [dict(r) for r in rows]
        total = len(incidents)
        tp = sum(1 for i in incidents if i.get("verdict") == "true_positive")
        fp = sum(1 for i in incidents if i.get("verdict") == "false_positive")
        sev_counts = {}
        class_counts = {}
        tactic_counts = {}
        certin_counts = {}
        impact_counts = {}
        top_sources = {}
        top_dests = {}
        for inc in incidents:
            s = inc.get("severity", "medium")
            sev_counts[s] = sev_counts.get(s, 0) + 1
            c = inc.get("closure_classification") or "Unclassified"
            class_counts[c] = class_counts.get(c, 0) + 1
            t = inc.get("closure_mitre_tactic") or ""
            if t:
                tactic_counts[t] = tactic_counts.get(t, 0) + 1
            cert = inc.get("closure_certin_category") or ""
            if cert:
                certin_counts[cert] = certin_counts.get(cert, 0) + 1
            imp = inc.get("closure_impact") or ""
            if imp:
                impact_counts[imp] = impact_counts.get(imp, 0) + 1
            src = inc.get("attacker_ip") or ""
            if src:
                top_sources[src] = top_sources.get(src, 0) + 1
            dst = inc.get("victim_ip") or ""
            if dst:
                top_dests[dst] = top_dests.get(dst, 0) + 1

        tp_pct = round(tp / total * 100) if total else 0
        fp_pct = round(fp / total * 100) if total else 0
        crit_high = sev_counts.get("critical", 0) + sev_counts.get("high", 0)
        med_low = sev_counts.get("medium", 0) + sev_counts.get("low", 0) + sev_counts.get("info", 0)

        showing = f"Top {limit}" if limit and limit.isdigit() and int(limit) < all_count else "All"
        subtitle = f"{showing} of {all_count} Closed Incidents" if all_count != total else f"{total} Closed Incidents"

        # SVG donut chart helper
        def svg_donut(data, colors, size=160):
            if not data:
                return f'<svg width="{size}" height="{size}"><text x="{size//2}" y="{size//2}" text-anchor="middle" fill="#999" font-size="12">No data</text></svg>'
            cx, cy, r = size // 2, size // 2, size // 2 - 10
            ir = r * 0.55
            total_v = sum(data.values())
            paths = ""
            legend = ""
            angle = -90
            for i, (label, val) in enumerate(data.items()):
                if total_v == 0:
                    break
                sweep = val / total_v * 360
                start_rad = math.radians(angle)
                end_rad = math.radians(angle + sweep)
                large = 1 if sweep > 180 else 0
                x1o, y1o = cx + r * math.cos(start_rad), cy + r * math.sin(start_rad)
                x2o, y2o = cx + r * math.cos(end_rad), cy + r * math.sin(end_rad)
                x1i, y1i = cx + ir * math.cos(end_rad), cy + ir * math.sin(end_rad)
                x2i, y2i = cx + ir * math.cos(start_rad), cy + ir * math.sin(start_rad)
                color = colors[i % len(colors)]
                paths += f'<path d="M{x1o:.1f},{y1o:.1f} A{r},{r} 0 {large} 1 {x2o:.1f},{y2o:.1f} L{x1i:.1f},{y1i:.1f} A{ir},{ir} 0 {large} 0 {x2i:.1f},{y2i:.1f} Z" fill="{color}" stroke="#fff" stroke-width="2"/>'
                pct = round(val / total_v * 100)
                legend += f'<div style="display:flex;align-items:center;gap:6px;margin:3px 0;font-size:11px;"><span style="width:10px;height:10px;border-radius:2px;background:{color};display:inline-block;flex-shrink:0;"></span><span style="color:#555;">{h_esc(label)}</span><span style="margin-left:auto;font-weight:700;color:#1a1a2e;">{val}</span><span style="color:#999;font-size:10px;">({pct}%)</span></div>'
                angle += sweep
            center_text = f'<text x="{cx}" y="{cy - 6}" text-anchor="middle" font-size="20" font-weight="800" fill="#1a1a2e">{total_v}</text><text x="{cx}" y="{cy + 12}" text-anchor="middle" font-size="9" fill="#999" text-transform="uppercase">TOTAL</text>'
            svg = f'<div style="display:flex;align-items:center;gap:20px;"><svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">{paths}{center_text}</svg><div style="min-width:120px;">{legend}</div></div>'
            return svg

        sev_order = ["critical", "high", "medium", "low", "info"]
        sev_colors_list = ["#DC2626", "#EA580C", "#D97706", "#16A34A", "#2563EB"]
        sev_sorted = {k: sev_counts[k] for k in sev_order if k in sev_counts}
        sev_chart = svg_donut(sev_sorted, sev_colors_list)
        verdict_chart = svg_donut(
            {"True Positive": tp, "False Positive": fp} if (tp or fp) else {},
            ["#DC2626", "#16A34A"]
        )

        # Horizontal bar chart helper
        def hbar(data, color="#3B82F6", max_items=6):
            if not data:
                return '<div style="color:#999;font-size:11px;padding:8px 0;">No data available</div>'
            items = sorted(data.items(), key=lambda x: -x[1])[:max_items]
            mx = max(v for _, v in items) if items else 1
            out = ""
            for k, v in items:
                pct = int(v / mx * 100) if mx else 0
                out += f'''<div style="margin:6px 0;">
                    <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:2px;"><span style="color:#374151;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="{h_esc(k)}">{h_esc(k)}</span><span style="font-weight:700;color:#1a1a2e;">{v}</span></div>
                    <div style="height:8px;background:#E5E7EB;border-radius:4px;overflow:hidden;"><div style="height:100%;width:{pct}%;background:{color};border-radius:4px;transition:width .3s;"></div></div>
                </div>'''
            return out

        sev_colors_map = {"critical": "#DC2626", "high": "#EA580C", "medium": "#D97706", "low": "#16A34A", "info": "#2563EB"}

        # ── AI executive summary (optional — only if Ollama is up) ──
        ai_exec_html = ""
        try:
            from analyzers.llm_assistant import executive_summary
            crit_titles = [inc.get("title", "")[:120] for inc in incidents
                           if inc.get("verdict") == "true_positive" and inc.get("severity") in ("critical", "high")][:5]
            stats = {
                "date": date_str,
                "total_closed": total,
                "true_positives": tp,
                "false_positives": fp,
                "by_severity": sev_counts,
                "top_classifications": [{"name": k, "count": v} for k, v in
                                        sorted(class_counts.items(), key=lambda x: -x[1])[:5]],
                "critical_incidents": crit_titles,
            }
            exec_r = executive_summary(stats)
            if "error" not in exec_r:
                ai_exec_html = f'''<div style="margin:10px 0 20px 0;padding:16px 20px;background:linear-gradient(135deg,#F5F3FF,#EEF2FF);border-left:4px solid #8B5CF6;border-radius:6px;">
                    <div style="font-size:9px;text-transform:uppercase;letter-spacing:1.5px;color:#6D28D9;font-weight:700;margin-bottom:8px;">&#129504; AI Executive Brief</div>
                    <div style="font-size:14px;font-weight:700;color:#1a1a2e;margin-bottom:8px;">{h_esc(exec_r.get("headline", ""))}</div>
                    <div style="font-size:12px;color:#374151;line-height:1.6;margin-bottom:6px;"><strong>Operations:</strong> {h_esc(exec_r.get("operational_summary", ""))}</div>
                    <div style="font-size:12px;color:#374151;line-height:1.6;margin-bottom:6px;"><strong>Notable:</strong> {h_esc(exec_r.get("notable_items", ""))}</div>
                    <div style="font-size:12px;color:#374151;line-height:1.6;"><strong>Focus tomorrow:</strong> {h_esc(exec_r.get("recommended_focus", ""))}</div>
                    <div style="font-size:9px;color:#9CA3AF;margin-top:8px;font-style:italic;">Model: {h_esc(exec_r.get("_model", "?"))}</div>
                </div>'''
        except Exception:
            pass  # LLM optional; report still renders without it

        # Fetch evidence for all incidents in this batch
        evidence_conn = get_db()
        inc_ids = [inc["id"] for inc in incidents]
        evidence_map = {}
        if inc_ids:
            placeholders = ",".join("?" * len(inc_ids))
            ev_rows = evidence_conn.execute(
                f"SELECT * FROM evidence WHERE incident_id IN ({placeholders}) ORDER BY uploaded_at",
                inc_ids
            ).fetchall()
            for ev in ev_rows:
                evidence_map.setdefault(ev["incident_id"], []).append(dict(ev))
        evidence_conn.close()

        # Build incident cards
        inc_cards = ""
        for idx, inc in enumerate(incidents):
            inc_id = f"INC-{inc['id']:04d}"
            sev = inc.get("severity", "medium")
            sev_c = sev_colors_map.get(sev, "#6B7280")
            verdict = inc.get("verdict", "")
            v_label = "TRUE POSITIVE" if verdict == "true_positive" else "FALSE POSITIVE"
            v_color = "#DC2626" if verdict == "true_positive" else "#16A34A"
            v_bg = "#FEF2F2" if verdict == "true_positive" else "#F0FDF4"
            summary = inc.get("closure_summary", "") or ""
            classification = inc.get("closure_classification", "") or ""
            mitre = inc.get("closure_mitre_tactic", "") or ""
            technique = inc.get("closure_mitre_technique", "") or ""
            certin = inc.get("closure_certin_category", "") or ""
            impact = inc.get("closure_impact", "") or ""
            src_ip = inc.get("attacker_ip", "") or ""
            dst_ip = inc.get("victim_ip", "") or ""
            closed_by = inc.get("closed_by", "") or ""
            closed_at = inc.get("resolved_at", "") or ""
            title = inc.get("title", "") or ""
            root_cause = inc.get("rca_root_cause", "") or ""
            actions_taken = inc.get("rca_actions_taken", "") or ""
            lessons = inc.get("rca_lessons_learned", "") or ""

            meta_items = []
            if classification:
                meta_items.append(f'<span style="background:#EFF6FF;color:#1D4ED8;padding:2px 8px;border-radius:3px;font-size:10px;">{h_esc(classification)}</span>')
            if mitre:
                mitre_text = f"{mitre}" + (f" / {technique}" if technique else "")
                meta_items.append(f'<span style="background:#F5F3FF;color:#7C3AED;padding:2px 8px;border-radius:3px;font-size:10px;">{h_esc(mitre_text)}</span>')
            if certin:
                meta_items.append(f'<span style="background:#FFF7ED;color:#C2410C;padding:2px 8px;border-radius:3px;font-size:10px;">{h_esc(certin)}</span>')
            if impact:
                meta_items.append(f'<span style="background:#F0FDF4;color:#15803D;padding:2px 8px;border-radius:3px;font-size:10px;">Impact: {h_esc(impact)}</span>')
            meta_html = " ".join(meta_items)

            # FP justification section — now symmetric with TP: shows every
            # RCA field the analyst filled in (Analysis, Root Cause, Actions
            # Taken, Lessons Learned) so bulk-close-summary + full analyst
            # notes all render.
            fp_section = ""
            if verdict == "false_positive":
                fp_parts = []
                if summary:
                    fp_parts.append(f'<div style="font-size:11px;color:#374151;line-height:1.5;margin-bottom:6px;"><strong>Analysis:</strong> {h_esc(summary)}</div>')
                if root_cause:
                    fp_parts.append(f'<div style="font-size:11px;color:#374151;line-height:1.5;margin-bottom:6px;"><strong>Root Cause:</strong> {h_esc(root_cause)}</div>')
                if actions_taken:
                    fp_parts.append(f'<div style="font-size:11px;color:#374151;line-height:1.5;margin-bottom:6px;"><strong>Actions Taken:</strong> {h_esc(actions_taken)}</div>')
                if lessons:
                    fp_parts.append(f'<div style="font-size:11px;color:#374151;line-height:1.5;margin-bottom:6px;"><strong>Lessons Learned:</strong> {h_esc(lessons)}</div>')
                # Include evidence for FP as well (proof of analysis)
                ev_list_fp = evidence_map.get(inc["id"], [])
                if ev_list_fp:
                    ev_html = '<div style="font-size:9px;text-transform:uppercase;letter-spacing:1px;color:#6B7280;font-weight:700;margin:6px 0 4px;">Attached Evidence</div>'
                    for ev in ev_list_fp:
                        size_kb = (ev.get("file_size", 0) or 0) / 1024
                        size_str = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb/1024:.1f} MB"
                        ev_html += f'''<div style="display:flex;align-items:center;gap:8px;padding:4px 8px;background:#F8FAFC;border:1px solid #E2E8F0;border-radius:4px;margin:3px 0;font-size:10px;">
                            <span style="color:#16A34A;font-weight:700;">&#128206;</span>
                            <span style="color:#1F2937;font-weight:600;">{h_esc(ev.get("filename",""))}</span>
                            <span style="color:#9CA3AF;">({size_str})</span>
                            {f'<span style="color:#6B7280;font-style:italic;"> — {h_esc(ev.get("description",""))}</span>' if ev.get("description") else ''}
                            <span style="margin-left:auto;color:#9CA3AF;font-size:9px;">SHA256: {h_esc((ev.get("hash_sha256","") or "")[:16])}…</span>
                        </div>'''
                    fp_parts.append(ev_html)
                if fp_parts:
                    fp_section = f'''<div style="margin-top:10px;padding:10px 14px;background:#F0FDF4;border-radius:6px;border-left:3px solid #16A34A;">
                        <div style="font-size:9px;text-transform:uppercase;letter-spacing:1px;color:#16A34A;font-weight:700;margin-bottom:4px;">False Positive — Analysis Report</div>
                        {"".join(fp_parts)}
                    </div>'''

            # TP evidence/POC section
            tp_section = ""
            if verdict == "true_positive":
                tp_parts = []
                if summary:
                    tp_parts.append(f'<div style="font-size:11px;color:#374151;line-height:1.5;margin-bottom:6px;"><strong>Analysis:</strong> {h_esc(summary)}</div>')
                if root_cause:
                    tp_parts.append(f'<div style="font-size:11px;color:#374151;line-height:1.5;margin-bottom:6px;"><strong>Root Cause:</strong> {h_esc(root_cause)}</div>')
                if actions_taken:
                    tp_parts.append(f'<div style="font-size:11px;color:#374151;line-height:1.5;margin-bottom:6px;"><strong>Actions Taken:</strong> {h_esc(actions_taken)}</div>')
                if lessons:
                    tp_parts.append(f'<div style="font-size:11px;color:#374151;line-height:1.5;margin-bottom:6px;"><strong>Lessons Learned:</strong> {h_esc(lessons)}</div>')

                # Evidence/POC files
                ev_list = evidence_map.get(inc["id"], [])
                if ev_list:
                    ev_html = '<div style="font-size:9px;text-transform:uppercase;letter-spacing:1px;color:#6B7280;font-weight:700;margin:6px 0 4px;">Attached Evidence / POC</div>'
                    for ev in ev_list:
                        size_kb = (ev.get("file_size", 0) or 0) / 1024
                        size_str = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb/1024:.1f} MB"
                        ev_html += f'''<div style="display:flex;align-items:center;gap:8px;padding:4px 8px;background:#F8FAFC;border:1px solid #E2E8F0;border-radius:4px;margin:3px 0;font-size:10px;">
                            <span style="color:#3B82F6;font-weight:700;">&#128206;</span>
                            <span style="color:#1F2937;font-weight:600;">{h_esc(ev.get("filename",""))}</span>
                            <span style="color:#9CA3AF;">({size_str})</span>
                            {f'<span style="color:#6B7280;font-style:italic;"> — {h_esc(ev.get("description",""))}</span>' if ev.get("description") else ''}
                            <span style="margin-left:auto;color:#9CA3AF;font-size:9px;">SHA256: {h_esc((ev.get("hash_sha256","") or "")[:16])}…</span>
                        </div>'''
                    tp_parts.append(ev_html)

                if tp_parts:
                    tp_section = f'''<div style="margin-top:10px;padding:10px 14px;background:#FEF2F2;border-radius:6px;border-left:3px solid #DC2626;">
                        <div style="font-size:9px;text-transform:uppercase;letter-spacing:1px;color:#DC2626;font-weight:700;margin-bottom:6px;">True Positive — Investigation Report</div>
                        {"".join(tp_parts)}
                    </div>'''

            inc_cards += f'''<div style="border:1px solid #E5E7EB;border-radius:8px;padding:16px;margin-bottom:12px;border-left:4px solid {sev_c};background:#fff;page-break-inside:avoid;">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;">
                    <div style="flex:1;">
                        <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px;">
                            <span style="font-family:'Courier New',monospace;font-size:12px;font-weight:800;color:#1a1a2e;">{inc_id}</span>
                            <span style="background:{sev_c};color:#fff;padding:2px 10px;border-radius:10px;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;">{h_esc(sev)}</span>
                            <span style="background:{v_bg};color:{v_color};padding:2px 10px;border-radius:10px;font-size:9px;font-weight:700;letter-spacing:.3px;">{v_label}</span>
                        </div>
                        <div style="font-size:12px;color:#1F2937;font-weight:600;line-height:1.4;">{h_esc(title)}</div>
                    </div>
                    <div style="text-align:right;font-size:10px;color:#9CA3AF;white-space:nowrap;margin-left:12px;">
                        <div>{h_esc(closed_at)}</div>
                        <div style="margin-top:2px;">by <span style="color:#6B7280;font-weight:600;">{h_esc(closed_by) if closed_by else "-"}</span></div>
                    </div>
                </div>
                {f'<div style="margin:6px 0;">{meta_html}</div>' if meta_html else ''}
                <div style="display:flex;gap:20px;font-size:10px;color:#6B7280;margin-top:6px;">
                    {f'<span>Source: <strong style="color:#1a1a2e;">{h_esc(src_ip)}</strong></span>' if src_ip else ''}
                    {f'<span>Destination: <strong style="color:#1a1a2e;">{h_esc(dst_ip)}</strong></span>' if dst_ip else ''}
                </div>
                {fp_section}{tp_section}
            </div>'''

        from datetime import datetime
        gen_time = datetime.now().strftime("%d %B %Y, %H:%M IST")
        date_display = datetime.strptime(date_str, "%Y-%m-%d").strftime("%d %B %Y")

        top_src_html = hbar(dict(sorted(top_sources.items(), key=lambda x: -x[1])[:5]), "#6366F1")
        top_dst_html = hbar(dict(sorted(top_dests.items(), key=lambda x: -x[1])[:5]), "#EC4899")

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NOTICE — Daily Incident Report — {h_esc(date_str)}</title>
<style>
  @page {{ size: A4; margin: 15mm 12mm; }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, 'Helvetica Neue', sans-serif; color:#1F2937; background:#F3F4F6; -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  .no-print {{ display:block; }}
  @media print {{
    .no-print {{ display:none !important; }}
    body {{ background:#fff; }}
    .page {{ box-shadow:none !important; margin:0 !important; border-radius:0 !important; }}
    .page-break {{ page-break-before:always; }}
  }}

  .page {{ max-width:900px; margin:20px auto; background:#fff; border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,.1); overflow:hidden; }}

  /* Toolbar */
  .toolbar {{ background:linear-gradient(135deg,#0F172A 0%,#1E293B 100%); color:#fff; padding:12px 28px; display:flex; justify-content:space-between; align-items:center; }}
  .toolbar button {{ background:rgba(255,255,255,.15); color:#fff; border:1px solid rgba(255,255,255,.2); padding:8px 20px; border-radius:6px; font-weight:600; font-size:12px; cursor:pointer; letter-spacing:.3px; backdrop-filter:blur(4px); }}
  .toolbar button:hover {{ background:rgba(255,255,255,.25); }}
  .toolbar .btn-print {{ background:#3B82F6; border-color:#3B82F6; }}
  .toolbar .btn-print:hover {{ background:#2563EB; }}

  /* Cover */
  .cover {{ background:linear-gradient(135deg,#0F172A 0%,#1E293B 50%,#334155 100%); color:#fff; padding:50px 40px 40px; position:relative; overflow:hidden; }}
  .cover::before {{ content:''; position:absolute; top:-50px; right:-50px; width:300px; height:300px; border-radius:50%; background:rgba(59,130,246,.08); }}
  .cover::after {{ content:''; position:absolute; bottom:-80px; left:-40px; width:250px; height:250px; border-radius:50%; background:rgba(139,92,246,.06); }}
  .cover-badge {{ display:inline-block; background:rgba(59,130,246,.2); border:1px solid rgba(59,130,246,.3); color:#93C5FD; padding:4px 14px; border-radius:20px; font-size:10px; font-weight:600; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:16px; }}
  .cover h1 {{ font-size:32px; font-weight:800; letter-spacing:-1px; margin-bottom:4px; position:relative; }}
  .cover .tagline {{ font-size:12px; color:#94A3B8; letter-spacing:2px; text-transform:uppercase; font-weight:500; margin-bottom:24px; }}
  .cover .report-title {{ font-size:20px; font-weight:700; color:#E2E8F0; margin-bottom:6px; position:relative; }}
  .cover .report-meta {{ font-size:12px; color:#64748B; position:relative; }}
  .cover .report-meta span {{ color:#CBD5E1; font-weight:600; }}
  .cover-date {{ position:absolute; top:50px; right:40px; text-align:right; }}
  .cover-date .day {{ font-size:48px; font-weight:800; color:#fff; line-height:1; }}
  .cover-date .month {{ font-size:14px; color:#94A3B8; text-transform:uppercase; letter-spacing:2px; font-weight:600; }}
  .cover-stats {{ display:flex; gap:1px; margin-top:28px; position:relative; }}
  .cover-stat {{ flex:1; background:rgba(255,255,255,.05); padding:14px 16px; text-align:center; }}
  .cover-stat:first-child {{ border-radius:8px 0 0 8px; }}
  .cover-stat:last-child {{ border-radius:0 8px 8px 0; }}
  .cover-stat .num {{ font-size:26px; font-weight:800; }}
  .cover-stat .lbl {{ font-size:9px; color:#94A3B8; text-transform:uppercase; letter-spacing:1px; font-weight:600; margin-top:2px; }}

  /* Content */
  .content {{ padding:30px 40px; }}
  .section {{ margin-bottom:28px; }}
  .section-hdr {{ display:flex; align-items:center; gap:10px; margin-bottom:16px; padding-bottom:10px; border-bottom:2px solid #E5E7EB; }}
  .section-hdr .icon {{ width:32px; height:32px; border-radius:8px; display:flex; align-items:center; justify-content:center; font-size:16px; color:#fff; }}
  .section-hdr h2 {{ font-size:15px; font-weight:700; color:#0F172A; letter-spacing:-.3px; }}
  .section-hdr .sub {{ font-size:11px; color:#9CA3AF; margin-left:auto; }}

  /* KPI row */
  .kpi-row {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin-bottom:28px; }}
  .kpi {{ background:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:18px 14px; text-align:center; position:relative; overflow:hidden; }}
  .kpi::before {{ content:''; position:absolute; top:0; left:0; right:0; height:3px; }}
  .kpi .lbl {{ font-size:9px; text-transform:uppercase; letter-spacing:1px; color:#9CA3AF; font-weight:700; }}
  .kpi .val {{ font-size:30px; font-weight:800; margin:6px 0 2px; line-height:1; }}
  .kpi .pct {{ font-size:10px; color:#9CA3AF; font-weight:500; }}

  /* Charts grid */
  .chart-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:20px; }}
  .chart-box {{ background:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:18px; }}
  .chart-box h3 {{ font-size:10px; text-transform:uppercase; letter-spacing:1px; color:#6B7280; font-weight:700; margin-bottom:14px; padding-bottom:8px; border-bottom:1px solid #F3F4F6; }}

  /* Footer */
  .report-footer {{ background:#F8FAFC; border-top:1px solid #E5E7EB; padding:16px 40px; display:flex; justify-content:space-between; align-items:center; }}
  .report-footer .brand {{ font-size:11px; font-weight:700; color:#374151; }}
  .report-footer .meta {{ font-size:10px; color:#9CA3AF; }}
  .report-footer .conf {{ font-size:9px; color:#DC2626; font-weight:700; text-transform:uppercase; letter-spacing:1px; background:#FEF2F2; padding:3px 10px; border-radius:4px; }}
</style>
</head>
<body>

<!-- Toolbar -->
<div class="toolbar no-print">
  <div>
    <span style="font-weight:700;font-size:14px;">NOTICE</span>
    <span style="color:#94A3B8;margin-left:8px;font-size:12px;">Daily Incident Report Preview</span>
  </div>
  <div style="display:flex;gap:8px;">
    <button class="btn-print" onclick="window.print()">Save as PDF</button>
    <button onclick="window.close()">Close</button>
  </div>
</div>

<div class="page">
  <!-- Cover -->
  <div class="cover">
    <div class="cover-badge">Security Operations Report</div>
    <h1>NOTICE</h1>
    <div class="tagline">Network Observation & Threat Intelligence Correlation Engine</div>
    <div class="report-title">Daily Incident Closure Report</div>
    <div class="report-meta">
      Compliance: <span>NIST SP 800-61 Rev. 2</span> &middot; <span>MITRE ATT&CK</span> &middot; <span>CERT-In</span>
    </div>
    <div class="report-meta" style="margin-top:4px;">
      Generated: <span>{gen_time}</span> &middot; Scope: <span>{subtitle}</span>
    </div>
    <div class="cover-date">
      <div class="day">{datetime.strptime(date_str,"%Y-%m-%d").strftime("%d")}</div>
      <div class="month">{datetime.strptime(date_str,"%Y-%m-%d").strftime("%b %Y")}</div>
    </div>
    <div class="cover-stats">
      <div class="cover-stat"><div class="num" style="color:#fff;">{total}</div><div class="lbl">Total Closed</div></div>
      <div class="cover-stat"><div class="num" style="color:#FCA5A5;">{tp}</div><div class="lbl">True Positives</div></div>
      <div class="cover-stat"><div class="num" style="color:#86EFAC;">{fp}</div><div class="lbl">False Positives</div></div>
      <div class="cover-stat"><div class="num" style="color:#FCD34D;">{crit_high}</div><div class="lbl">Critical / High</div></div>
      <div class="cover-stat"><div class="num" style="color:#93C5FD;">{med_low}</div><div class="lbl">Medium / Low</div></div>
    </div>
  </div>

  <div class="content">
    <!-- Executive Summary -->
    <div class="section">
      <div class="section-hdr">
        <div class="icon" style="background:linear-gradient(135deg,#3B82F6,#1D4ED8);">&#x1f4ca;</div>
        <h2>Executive Summary</h2>
        <div class="sub">{date_display}</div>
      </div>
      {ai_exec_html}
      <div class="chart-grid">
        <div class="chart-box">
          <h3>Verdict Distribution</h3>
          {verdict_chart}
        </div>
        <div class="chart-box">
          <h3>Severity Distribution</h3>
          {sev_chart}
        </div>
      </div>
    </div>

    <!-- Breakdown Analysis -->
    <div class="section">
      <div class="section-hdr">
        <div class="icon" style="background:linear-gradient(135deg,#8B5CF6,#6D28D9);">&#x1f50d;</div>
        <h2>Breakdown Analysis</h2>
      </div>
      <div class="chart-grid">
        <div class="chart-box">
          <h3>Classification (NIST SP 800-61)</h3>
          {hbar(class_counts, "#3B82F6")}
        </div>
        <div class="chart-box">
          <h3>MITRE ATT&CK Tactic</h3>
          {hbar(tactic_counts, "#8B5CF6")}
        </div>
        <div class="chart-box">
          <h3>CERT-In Category</h3>
          {hbar(certin_counts, "#DC2626")}
        </div>
        <div class="chart-box">
          <h3>Impact Level</h3>
          {hbar(impact_counts, "#16A34A") if impact_counts else '<div style="color:#999;font-size:11px;padding:8px 0;">No data available</div>'}
        </div>
      </div>
    </div>

    <!-- Top Talkers -->
    <div class="section" style="page-break-inside:avoid;">
      <div class="section-hdr">
        <div class="icon" style="background:linear-gradient(135deg,#EC4899,#BE185D);">&#x1f310;</div>
        <h2>Top Talkers</h2>
      </div>
      <div class="chart-grid">
        <div class="chart-box">
          <h3>Top Source IPs</h3>
          {top_src_html}
        </div>
        <div class="chart-box">
          <h3>Top Destination IPs</h3>
          {top_dst_html}
        </div>
      </div>
    </div>

    <!-- Incident Details -->
    <div class="page-break"></div>
    <div class="section">
      <div class="section-hdr">
        <div class="icon" style="background:linear-gradient(135deg,#F59E0B,#D97706);">&#x1f6e1;</div>
        <h2>Incident Details</h2>
        <div class="sub">{total} incident{"s" if total != 1 else ""}</div>
      </div>
      {inc_cards if inc_cards else '<div style="text-align:center;color:#9CA3AF;padding:40px;font-size:13px;">No incidents closed on this date.</div>'}
    </div>
  </div>

  <!-- Footer -->
  <div class="report-footer">
    <div class="brand">NOTICE — Network Observation & Threat Intelligence Correlation Engine</div>
    <div class="conf">Confidential</div>
    <div class="meta">Generated: {gen_time}</div>
  </div>
</div>
</body>
</html>'''

        response.content_type = "text/html; charset=utf-8"
        return html

    @app.post("/api/incidents/<incident_id:int>/rca")
    def update_rca(incident_id):
        """Save root-cause / lessons-learned / actions-taken on an incident."""
        data = request.json or {}
        conn = get_db()
        inc = conn.execute("SELECT id FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not inc:
            conn.close(); response.status = 404
            return {"error": "Incident not found"}
        conn.execute(
            "UPDATE incidents SET rca_root_cause=?, rca_lessons_learned=?, rca_actions_taken=?, "
            "updated_at=datetime('now','localtime') WHERE id=?",
            (data.get("rca_root_cause", ""), data.get("rca_lessons_learned", ""),
             data.get("rca_actions_taken", ""), incident_id),
        )
        conn.commit()
        inc = dict(conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone())
        conn.close()
        return inc

    @app.put("/api/incidents/<incident_id:int>")
    def update_incident(incident_id):
        data = request.json or {}
        conn = get_db()
        inc = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not inc:
            conn.close()
            response.status = 404
            return {"error": "Incident not found"}

        extra_sets = ["updated_at = datetime('now','localtime')"]
        if "status" in data and data["status"] in ("resolved", "closed"):
            extra_sets.append("resolved_at = datetime('now','localtime')")

        # Reject phase changes on already-closed incidents (re-open would be a separate action)
        if "phase" in data:
            if inc["status"] == "closed":
                conn.close()
                response.status = 400
                return {"error": "Cannot change phase of a closed incident. Reopen first."}
            valid_phases = {"triage", "investigate", "contain", "eradicate", "recover", "closed"}
            if data["phase"] not in valid_phases:
                conn.close()
                response.status = 400
                return {"error": f"Invalid phase. Must be one of: {sorted(valid_phases)}"}
            # When phase changes, stamp phase_started_at and log to incident_phase_log
            extra_sets.append("phase_started_at = datetime('now','localtime')")

        _INCIDENT_FIELDS = frozenset({"title", "description", "severity", "status",
                                       "assigned_to", "phase"})
        safe_update("incidents", _INCIDENT_FIELDS, data, "WHERE id = ?", [incident_id], extra_sets)

        # Actor for audit + notification
        actor = ""
        try:
            actor = (getattr(request, "user", {}) or {}).get("username", "") or ""
        except Exception:
            pass

        # Audit-log phase transitions in incident_phase_log for the timeline
        if "phase" in data and data["phase"] != inc["phase"]:
            conn.execute(
                "INSERT INTO incident_phase_log (incident_id, phase, started_at, completed_by) "
                "VALUES (?, ?, datetime('now','localtime'), ?)",
                (incident_id, data["phase"], actor or "api"),
            )

        # Notify the newly-assigned analyst (only if it's a real change, not empty→empty)
        if "assigned_to" in data:
            new_assignee = (data.get("assigned_to") or "").strip()
            old_assignee = (inc["assigned_to"] or "").strip()
            if new_assignee and new_assignee != old_assignee and new_assignee != actor:
                # Don't notify self-assignments
                conn.execute(
                    "INSERT INTO user_notifications "
                    "(username, type, incident_id, title, message) "
                    "VALUES (?, 'assignment', ?, ?, ?)",
                    (new_assignee, incident_id,
                     f"Incident #{incident_id} assigned to you",
                     f"{actor or 'system'} assigned you: {(inc['title'] or '')[:120]}"),
                )
        conn.commit()

        result = dict(conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone())
        conn.close()
        return result

    # ------------------------------------------------------------------
    # Reopen a closed incident
    # ------------------------------------------------------------------
    @app.post("/api/incidents/<incident_id:int>/reopen")
    def reopen_incident(incident_id):
        conn = get_db()
        inc = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not inc:
            conn.close(); response.status = 404
            return {"error": "Incident not found"}
        if inc["status"] != "closed":
            conn.close(); response.status = 400
            return {"error": "Incident is not closed"}
        actor = ""
        try:
            actor = (getattr(request, "user", {}) or {}).get("username", "") or ""
        except Exception:
            pass
        conn.execute(
            "UPDATE incidents SET status='open', verdict=NULL, resolved_at=NULL, "
            "closed_by='', updated_at=datetime('now','localtime'), "
            "phase='triage', phase_started_at=datetime('now','localtime') "
            "WHERE id=?", (incident_id,)
        )
        conn.execute(
            "INSERT INTO incident_phase_log (incident_id, phase, started_at, completed_by) "
            "VALUES (?, 'triage', datetime('now','localtime'), ?)",
            (incident_id, actor or "api-reopen"),
        )
        conn.commit()
        result = dict(conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone())
        conn.close()
        return {"ok": True, "incident": result}

    # ------------------------------------------------------------------
    # Related history — for triage helper "closed N times, X TP, Y FP"
    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # LLM triage assistant — runs a local Ollama model against incident
    # context and returns a verdict recommendation + suggested action.
    # ------------------------------------------------------------------
    @app.post("/api/incidents/<incident_id:int>/ai-analysis")
    def ai_analysis(incident_id):
        try:
            from analyzers.llm_assistant import analyze_incident
        except Exception as e:
            response.status = 500
            return {"error": f"LLM module unavailable: {e}"}
        result = analyze_incident(incident_id)
        if "error" in result:
            response.status = 503
            return result
        return result

    @app.get("/api/ai/health")
    def ai_health():
        try:
            from analyzers.llm_assistant import health
        except Exception as e:
            return {"ok": False, "error": f"LLM module unavailable: {e}"}
        return health()

    # ── AI: explain a Suricata rule (by SID) ──
    @app.get("/api/ai/explain-rule")
    def ai_explain_rule():
        try:
            from analyzers.llm_assistant import explain_rule
        except Exception as e:
            response.status = 503
            return {"error": f"LLM unavailable: {e}"}
        sid = request.query.get("sid", "").strip()
        signature = request.query.get("signature", "").strip()
        rule_text = ""
        # Load the real rule text from the Suricata rule files (via the
        # shared rules index) so the LLM has actual content to explain.
        if sid and sid.isdigit():
            try:
                from analyzers.suricata_rules import get_rules_by_sids
                rmap = get_rules_by_sids({int(sid)})
                rule = rmap.get(int(sid))
                if rule:
                    rule_text = rule.get("raw_line") or ""
                    if not signature:
                        signature = rule.get("msg", "")
            except Exception:
                pass
        result = explain_rule(
            signature_id=int(sid) if sid.isdigit() else None,
            signature=signature or None,
            rule_text=rule_text or None,
        )
        if "error" in result:
            response.status = 503
        return result

    # ── AI: generate a Suricata rule from plain English ──
    @app.post("/api/ai/generate-rule")
    def ai_generate_rule():
        try:
            from analyzers.llm_assistant import generate_rule
        except Exception as e:
            response.status = 503
            return {"error": f"LLM unavailable: {e}"}
        data = request.json or {}
        desc = (data.get("description") or "").strip()
        if not desc:
            response.status = 400
            return {"error": "description required"}
        result = generate_rule(desc)
        if "error" in result:
            response.status = 503
        return result

    # ── AI: draft closure fields for an incident ──
    @app.post("/api/incidents/<incident_id:int>/ai-draft-closure")
    def ai_draft_closure(incident_id):
        try:
            from analyzers.llm_assistant import draft_closure
        except Exception as e:
            response.status = 503
            return {"error": f"LLM unavailable: {e}"}
        data = request.json or {}
        verdict = (data.get("verdict") or "").strip() or None
        result = draft_closure(incident_id, verdict=verdict)
        if "error" in result:
            response.status = 503
        return result

    # ── AI: rapid triage of a single alert ──
    @app.post("/api/ai/analyze-alert")
    def ai_analyze_alert():
        try:
            from analyzers.llm_assistant import analyze_alert
        except Exception as e:
            response.status = 503
            return {"error": f"LLM unavailable: {e}"}
        alert = request.json or {}
        if not alert.get("signature") and not alert.get("signature_id"):
            response.status = 400
            return {"error": "signature or signature_id required"}
        # Enrich with prior-verdict counts if not provided
        if "prior_tp" not in alert or "prior_fp" not in alert:
            sid = alert.get("signature_id")
            if sid:
                try:
                    conn = get_db()
                    rows = conn.execute(
                        "SELECT verdict, COUNT(*) as c FROM incidents "
                        "WHERE signature_id=? AND status='closed' GROUP BY verdict",
                        (sid,),
                    ).fetchall()
                    counts = {r["verdict"]: r["c"] for r in rows}
                    alert["prior_tp"] = counts.get("true_positive", 0)
                    alert["prior_fp"] = counts.get("false_positive", 0)
                    conn.close()
                except Exception:
                    alert["prior_tp"] = alert["prior_fp"] = 0
        result = analyze_alert(alert)
        if "error" in result:
            response.status = 503
        return result

    # ── AI: natural-language search ──
    @app.post("/api/ai/nl-search")
    def ai_nl_search():
        try:
            from analyzers.llm_assistant import parse_nl_search
        except Exception as e:
            response.status = 503
            return {"error": f"LLM unavailable: {e}"}
        data = request.json or {}
        query = (data.get("query") or "").strip()
        if not query:
            response.status = 400
            return {"error": "query required"}
        actor = ""
        try:
            actor = (getattr(request, "user", {}) or {}).get("username", "") or ""
        except Exception:
            pass
        filters = parse_nl_search(query, current_user=actor)
        if "error" in filters:
            response.status = 503
            return filters
        # Now execute the filter against incidents
        conn = get_db()
        q = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if filters.get("status"):
            q += " AND status=?"
            params.append(filters["status"])
        if filters.get("severity"):
            q += " AND severity=?"
            params.append(filters["severity"])
        if filters.get("verdict"):
            q += " AND verdict=?"
            params.append(filters["verdict"])
        if filters.get("assigned_to"):
            q += " AND assigned_to=?"
            params.append(filters["assigned_to"])
        if filters.get("q"):
            like = f"%{filters['q']}%"
            q += (" AND (title LIKE ? OR signature LIKE ? OR attacker_ip LIKE ? OR victim_ip LIKE ?)")
            params.extend([like, like, like, like])
        if filters.get("minutes"):
            q += f" AND created_at > datetime('now', '-{int(filters['minutes'])} minutes', 'localtime')"
        q += " ORDER BY created_at DESC LIMIT 200"
        try:
            rows = [dict(r) for r in conn.execute(q, params).fetchall()]
        except Exception as e:
            conn.close()
            response.status = 500
            return {"error": f"Query failed: {e}", "filters": filters}
        conn.close()
        return {
            "filters": filters,
            "count": len(rows),
            "incidents": rows,
        }

    # ═══════════════════════════════════════════════════════════════
    # SESSION 1 AI endpoints — enrichment narrators
    # ═══════════════════════════════════════════════════════════════

    # ── Dashboard: situation report (last 24h, timezone-safe) ──
    @app.get("/api/ai/dashboard-briefing")
    def ai_dash_briefing():
        """Situation Report. Accepts:
          ?minutes=<N>              (e.g. 60, 360, 1440, 10080, 43200)
          ?from=<ISO>&to=<ISO>      (both required if given)
        Defaults to last 24h (1440 min) for backwards compat.
        """
        try:
            from analyzers.llm_assistant import dashboard_briefing
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}

        # ── Parse time range ──
        from datetime import datetime as _dt, timedelta as _td
        minutes_q = request.query.get("minutes", "").strip()
        from_q = request.query.get("from", "").strip()
        to_q = request.query.get("to", "").strip()

        now = _dt.now()
        if from_q and to_q:
            # Explicit absolute range
            try:
                t_from = _dt.fromisoformat(from_q.replace("Z", ""))
                t_to = _dt.fromisoformat(to_q.replace("Z", ""))
                if t_to <= t_from:
                    response.status = 400
                    return {"error": "'to' must be after 'from'"}
            except ValueError:
                response.status = 400
                return {"error": "from/to must be ISO 8601 (YYYY-MM-DDTHH:MM:SS)"}
            window_label = f"between {t_from.strftime('%b %d %H:%M')} and {t_to.strftime('%b %d %H:%M')}"
        else:
            # Relative "last N minutes"
            try:
                mins = int(minutes_q) if minutes_q else 1440
            except ValueError:
                mins = 1440
            mins = max(1, min(mins, 60 * 24 * 90))  # cap at 90 days
            t_to = now
            t_from = now - _td(minutes=mins)
            # Human-friendly label
            if mins < 60:
                window_label = f"in the last {mins} minutes"
            elif mins < 60 * 24:
                window_label = f"in the last {mins // 60} hours"
            elif mins < 60 * 24 * 7:
                window_label = f"in the last {mins // (60 * 24)} days"
            else:
                window_label = f"in the last {mins // (60 * 24)} days"

        from_str = t_from.strftime("%Y-%m-%d %H:%M:%S")
        to_str = t_to.strftime("%Y-%m-%d %H:%M:%S")

        # ── Queries (all use bound params) ──
        conn = get_db()
        try:
            alerts_in_window = conn.execute(
                "SELECT COUNT(*) as c FROM ingested_alerts "
                "WHERE timestamp >= ? AND timestamp < ?",
                (from_str, to_str)
            ).fetchone()["c"]
        except Exception:
            alerts_in_window = 0
        open_total = conn.execute(
            "SELECT COUNT(*) as c FROM incidents WHERE status='open'"
        ).fetchone()["c"]
        closed_tp_in_window = conn.execute(
            "SELECT COUNT(*) as c FROM incidents WHERE status='closed' "
            "AND verdict='true_positive' AND resolved_at >= ? AND resolved_at < ?",
            (from_str, to_str)
        ).fetchone()["c"]
        closed_fp_in_window = conn.execute(
            "SELECT COUNT(*) as c FROM incidents WHERE status='closed' "
            "AND verdict='false_positive' AND resolved_at >= ? AND resolved_at < ?",
            (from_str, to_str)
        ).fetchone()["c"]
        top_open = [dict(r) for r in conn.execute(
            "SELECT title, severity FROM incidents WHERE status='open' "
            "ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
            "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, created_at DESC LIMIT 5"
        ).fetchall()]
        try:
            top_sigs = [{"name": r["signature"], "count": r["c"]} for r in conn.execute(
                "SELECT signature, COUNT(*) as c FROM ingested_alerts "
                "WHERE timestamp >= ? AND timestamp < ? "
                "AND signature IS NOT NULL AND signature != '' "
                "GROUP BY signature ORDER BY c DESC LIMIT 5",
                (from_str, to_str)
            ).fetchall()]
        except Exception:
            top_sigs = []
        conn.close()

        stats = {
            "window_label": window_label,
            "window_from": from_str,
            "window_to": to_str,
            "alerts_in_window": alerts_in_window,
            "open_incidents_total": open_total,
            "incidents_closed_tp_in_window": closed_tp_in_window,
            "incidents_closed_fp_in_window": closed_fp_in_window,
            "top_open_incidents": top_open,
            "top_signatures": top_sigs,
        }
        r = dashboard_briefing(stats)
        if "error" in r: response.status = 503
        r["_stats"] = stats
        return r

    # ── Dashboard: state-of-security summary ──
    @app.get("/api/ai/state-of-security")
    def ai_state_of_sec():
        try:
            from analyzers.llm_assistant import state_of_security
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        conn = get_db()
        open_c = conn.execute("SELECT COUNT(*) as c FROM incidents WHERE status='open'").fetchone()["c"]
        # Per-severity breakdown (used to render clickable quick-jump chips)
        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) as c FROM incidents WHERE status='open' GROUP BY severity"
        ).fetchall()
        open_by_sev = {r["severity"] or "unknown": r["c"] for r in sev_rows}
        open_crit = open_by_sev.get("critical", 0)
        recent_tp = conn.execute(
            "SELECT COUNT(*) as c FROM incidents WHERE verdict='true_positive' "
            "AND resolved_at > datetime('now','-1 day','localtime')"
        ).fetchone()["c"]
        try:
            alerts_last_hr = conn.execute(
                "SELECT COUNT(*) as c FROM ingested_alerts WHERE timestamp > datetime('now','-1 hour','localtime')"
            ).fetchone()["c"]
            # Baseline: alerts per hour, last 24h
            total_24h = conn.execute(
                "SELECT COUNT(*) as c FROM ingested_alerts WHERE timestamp > datetime('now','-1 day','localtime')"
            ).fetchone()["c"]
            baseline_hourly = total_24h // 24 if total_24h else 0
        except Exception:
            alerts_last_hr = baseline_hourly = 0
        try:
            active_blocks = conn.execute("SELECT COUNT(*) as c FROM blocklist WHERE active=1").fetchone()["c"]
            active_qs = conn.execute("SELECT COUNT(*) as c FROM quarantine WHERE active=1").fetchone()["c"]
        except Exception:
            active_blocks = active_qs = 0
        conn.close()
        stats = {
            "open_incidents": open_c, "open_critical": open_crit,
            "sla_breached": 0,  # placeholder
            "recent_tp": recent_tp,
            "alerts_last_hour": alerts_last_hr,
            "alerts_baseline_hourly": baseline_hourly,
            "active_blocks": active_blocks, "active_quarantines": active_qs,
        }
        r = state_of_security(stats)
        if "error" in r:
            response.status = 503
        else:
            # Frontend uses this to render clickable severity chips
            r["_open_by_severity"] = open_by_sev
            r["_open_total"] = open_c
        return r

    # ── Dashboard: anomaly narrator ──
    @app.get("/api/ai/anomaly-narrator")
    def ai_anomaly_narrator():
        try:
            from analyzers.llm_assistant import anomaly_narrator
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        conn = get_db()
        # Alerts in the last full hour, and a 23-hour baseline covering the
        # rest of the last 24 hours. Uses float average so a rate like
        # 6.9 alerts/hour is not truncated to 0.
        try:
            cur_alerts = conn.execute(
                "SELECT COUNT(*) as c FROM ingested_alerts "
                "WHERE timestamp > datetime('now','-1 hour','localtime')"
            ).fetchone()["c"]
            baseline_total = conn.execute(
                "SELECT COUNT(*) as c FROM ingested_alerts "
                "WHERE timestamp > datetime('now','-24 hours','localtime') "
                "AND timestamp < datetime('now','-1 hour','localtime')"
            ).fetchone()["c"]
            # How many hours of history do we actually have?
            # SQLite's julianday() rejects ISO timestamps with fractional seconds
            # or timezone offsets (e.g. "2026-08-11T10:39:35.881700+0530"), so
            # strip both before feeding it in.
            first_row = conn.execute(
                "SELECT MIN(timestamp) as t FROM ingested_alerts"
            ).fetchone()
            hours_of_data = None
            if first_row and first_row["t"]:
                import re as _re
                clean = _re.sub(r'([+-]\d{2}:?\d{2}|Z)$', '', first_row["t"]).split('.')[0]
                r_span = conn.execute(
                    "SELECT (julianday('now','localtime') - julianday(?)) * 24.0 AS h",
                    (clean,)
                ).fetchone()
                if r_span and r_span["h"] is not None:
                    hours_of_data = float(r_span["h"])
            baseline_hours = min(23.0, hours_of_data - 1.0) if hours_of_data else 0.0
            baseline_alerts = (baseline_total / baseline_hours) if baseline_hours > 0.5 else None
        except Exception:
            cur_alerts = 0
            baseline_alerts = None
            hours_of_data = 0
        conn.close()
        r = anomaly_narrator(
            current_metrics={"alerts_per_hour": cur_alerts},
            baseline_metrics={"alerts_per_hour": baseline_alerts},
            hours_of_history=hours_of_data or 0,
        )
        if "error" in r: response.status = 503
        return r

    # ── Incident: similar-incidents narrative ──
    @app.get("/api/incidents/<incident_id:int>/ai-similar")
    def ai_similar(incident_id):
        try:
            from analyzers.llm_assistant import similar_incidents_narrative
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        conn = get_db()
        cur = conn.execute("SELECT id, title, signature_id, signature FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not cur:
            conn.close(); response.status = 404; return {"error": "Incident not found"}
        cur = dict(cur)
        past = [dict(r) for r in conn.execute(
            "SELECT id, verdict, closure_summary FROM incidents "
            "WHERE signature_id=? AND status='closed' AND id != ? "
            "ORDER BY resolved_at DESC LIMIT 10",
            (cur["signature_id"], incident_id)
        ).fetchall()]
        conn.close()
        r = similar_incidents_narrative(cur, past)
        if "error" in r: response.status = 503
        return r

    # ── Incident: playbook recommendation ──
    @app.get("/api/incidents/<incident_id:int>/ai-playbook")
    def ai_playbook(incident_id):
        try:
            from analyzers.llm_assistant import playbook_recommendation
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        conn = get_db()
        inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not inc:
            conn.close(); response.status = 404; return {"error": "Incident not found"}
        inc = dict(inc)
        # Dest asset info if registered
        dst_asset = None
        if inc.get("victim_ip"):
            row = conn.execute("SELECT owner, asset_type, business_critical FROM assets WHERE ip=?",
                               (inc["victim_ip"],)).fetchone()
            dst_asset = dict(row) if row else None
        conn.close()
        src = inc.get("attacker_ip", "") or ""
        ctx = {
            "signature": inc.get("signature", ""),
            "severity": inc.get("severity", ""),
            "src_ip": src,
            "source_is_external": not (src.startswith("10.") or src.startswith("172.16.") or src.startswith("192.168.")),
            "dst_ip": inc.get("victim_ip", ""),
            "dst_asset": dst_asset,
        }
        r = playbook_recommendation(ctx)
        if "error" in r: response.status = 503
        return r

    # ── Incident: attack-chain narrative ──
    @app.get("/api/incidents/<incident_id:int>/ai-chain")
    def ai_chain(incident_id):
        try:
            from analyzers.llm_assistant import attack_chain_narrative
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        conn = get_db()
        events = [dict(r) for r in conn.execute(
            "SELECT src_ip, dest_ip, timestamp, event_summary, sid FROM incident_events "
            "WHERE incident_id=? ORDER BY timestamp LIMIT 40",
            (incident_id,)
        ).fetchall()]
        conn.close()
        if not events:
            return {"error": "No events to narrate for this incident"}
        r = attack_chain_narrative(events)
        if "error" in r: response.status = 503
        return r

    # ── Investigate: IP profile ──
    @app.get("/api/ai/profile-ip/<ip>")
    def ai_profile_ip(ip):
        try:
            from analyzers.llm_assistant import profile_ip
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        conn = get_db()
        is_internal = ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("192.168.")
        asset = conn.execute(
            "SELECT owner, hostname, asset_type, purdue_level, business_critical "
            "FROM assets WHERE ip=?", (ip,)
        ).fetchone()
        # From ingested_alerts, compute top dest ports for outbound + top peers
        top_dest_ports = [(r["p"], r["c"]) for r in conn.execute(
            "SELECT dest_port as p, COUNT(*) as c FROM ingested_alerts "
            "WHERE src_ip=? AND dest_port IS NOT NULL AND dest_port > 0 "
            "GROUP BY dest_port ORDER BY c DESC LIMIT 8",
            (ip,)
        ).fetchall()]
        top_dest_ips = [(r["d"], r["c"]) for r in conn.execute(
            "SELECT dest_ip as d, COUNT(*) as c FROM ingested_alerts "
            "WHERE src_ip=? GROUP BY dest_ip ORDER BY c DESC LIMIT 5",
            (ip,)
        ).fetchall()]
        top_sigs = [(r["s"], r["c"]) for r in conn.execute(
            "SELECT signature as s, COUNT(*) as c FROM ingested_alerts "
            "WHERE src_ip=? OR dest_ip=? GROUP BY signature ORDER BY c DESC LIMIT 5",
            (ip, ip)
        ).fetchall()]
        total_flows = conn.execute(
            "SELECT COUNT(*) as c FROM ingested_alerts WHERE src_ip=? OR dest_ip=?", (ip, ip)
        ).fetchone()["c"]
        # Reputation
        rep = conn.execute("SELECT abuse_score FROM ip_reputation WHERE ip=?", (ip,)).fetchone()
        conn.close()
        ctx = {
            "is_internal": is_internal,
            "asset_info": dict(asset) if asset else None,
            "top_dest_ports": top_dest_ports,
            "top_dest_ips": top_dest_ips,
            "top_signatures": top_sigs,
            "total_flows": total_flows,
            "abuse_score": rep["abuse_score"] if rep else None,
        }
        r = profile_ip(ip, ctx)
        if "error" in r: response.status = 503
        return r

    # ── Assets: profile + auto-classify ──
    # Note: ingested_alerts only contains alert events, not full flow data.
    # For richer asset profiling we also pull from flow-level tables via
    # iter_events, but for speed we use the alert index as a proxy.
    @app.get("/api/ai/profile-asset/<ip>")
    def ai_profile_asset(ip):
        try:
            from analyzers.llm_assistant import profile_asset
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        try:
            conn = get_db()
            asset = conn.execute("SELECT * FROM assets WHERE ip=?", (ip,)).fetchone()
            top_dest_ports = [(r["p"], r["c"]) for r in conn.execute(
                "SELECT dest_port as p, COUNT(*) as c FROM ingested_alerts "
                "WHERE src_ip=? AND dest_port IS NOT NULL AND dest_port > 0 "
                "GROUP BY dest_port ORDER BY c DESC LIMIT 8",
                (ip,)
            ).fetchall()]
            top_peers = [(r["d"], r["c"]) for r in conn.execute(
                "SELECT dest_ip as d, COUNT(*) as c FROM ingested_alerts "
                "WHERE src_ip=? AND dest_ip IS NOT NULL AND dest_ip != '' "
                "GROUP BY dest_ip ORDER BY c DESC LIMIT 5",
                (ip,)
            ).fetchall()]
            total_flows = conn.execute(
                "SELECT COUNT(*) as c FROM ingested_alerts WHERE src_ip=? OR dest_ip=?", (ip, ip)
            ).fetchone()["c"]
            conn.close()
        except Exception as e:
            response.status = 500
            return {"error": f"DB query failed: {e}"}
        if total_flows == 0 and not asset:
            return {
                "role_summary": "unknown — no data",
                "normal_behavior": f"No alert traffic observed for {ip} in the alert index and the IP is not a registered asset. There is nothing to profile.",
                "recent_changes": "no data available",
                "watch_for": "First step: register this IP in the Assets page if it's real, then wait for traffic to accumulate.",
                "_note": "no_data",
            }
        ctx = {
            "asset_info": dict(asset) if asset else {},
            "top_dest_ports": top_dest_ports,
            "top_peers": top_peers,
            "total_flows": total_flows,
        }
        r = profile_asset(ip, ctx)
        if "error" in r: response.status = 503
        return r

    @app.get("/api/ai/classify-asset/<ip>")
    def ai_classify_asset(ip):
        try:
            from analyzers.llm_assistant import auto_classify_asset
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        try:
            conn = get_db()
            top_dest_ports = [(r["p"], r["c"]) for r in conn.execute(
                "SELECT dest_port as p, COUNT(*) as c FROM ingested_alerts "
                "WHERE src_ip=? AND dest_port IS NOT NULL AND dest_port > 0 "
                "GROUP BY dest_port ORDER BY c DESC LIMIT 10",
                (ip,)
            ).fetchall()]
            # Listening ports = ports where THIS IP is dest (any proto)
            listening = [r["p"] for r in conn.execute(
                "SELECT dest_port as p FROM ingested_alerts "
                "WHERE dest_ip=? AND dest_port IS NOT NULL AND dest_port > 0 "
                "GROUP BY dest_port ORDER BY COUNT(*) DESC LIMIT 8",
                (ip,)
            ).fetchall()]
            total = conn.execute(
                "SELECT COUNT(*) as c FROM ingested_alerts WHERE src_ip=? OR dest_ip=?", (ip, ip)
            ).fetchone()["c"]
            conn.close()
        except Exception as e:
            response.status = 500
            return {"error": f"DB query failed: {e}"}
        if total == 0:
            return {
                "asset_type": "unknown",
                "specific_role": "unknown — no observed traffic",
                "confidence": "low",
                "reasoning": f"No traffic has been observed for {ip} in the alert index — cannot classify.",
                "_note": "no_data",
            }
        ctx = {
            "listening_ports": listening,
            "top_dest_ports": top_dest_ports,
            "total_flows": total,
        }
        r = auto_classify_asset(ip, ctx)
        if "error" in r: response.status = 503
        return r

    # ── Threat Intel: IOC narrative ──
    @app.post("/api/ai/ioc-narrative")
    def ai_ioc_narrative():
        try:
            from analyzers.llm_assistant import ioc_narrative
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        data = request.json or {}
        ind_type = data.get("type", "ip")
        value = (data.get("value") or "").strip()
        if not value:
            response.status = 400; return {"error": "value required"}
        # Assemble enrichment from cached TI + local history
        conn = get_db()
        enrichment = {}
        if ind_type == "ip":
            rep = conn.execute("SELECT * FROM ip_reputation WHERE ip=?", (value,)).fetchone()
            if rep:
                r = dict(rep)
                enrichment["abuseipdb"] = {
                    "abuse_score": r.get("abuse_score", 0),
                    "total_reports": r.get("total_reports", 0),
                    "country_code": r.get("country_code", ""),
                }
            geo = conn.execute("SELECT * FROM geo_cache WHERE ip=?", (value,)).fetchone()
            if geo:
                g = dict(geo)
                enrichment["geoip"] = {"country": g.get("country", ""), "isp": g.get("isp", ""), "org": g.get("org", "")}
            # Local history
            row = conn.execute(
                "SELECT COUNT(*) as fc, COUNT(DISTINCT src_ip)+COUNT(DISTINCT dest_ip) as pc FROM ingested_alerts WHERE src_ip=? OR dest_ip=?",
                (value, value)
            ).fetchone()
            if row:
                enrichment["local_history"] = {
                    "flow_count": row["fc"], "distinct_peers": row["pc"],
                    "alert_count": row["fc"],
                }
        conn.close()
        r = ioc_narrative(ind_type, value, enrichment)
        if "error" in r: response.status = 503
        return r

    @app.get("/api/incidents/<incident_id:int>/related-history")
    def related_history(incident_id):
        conn = get_db()
        inc = conn.execute("SELECT signature_id, attacker_ip FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not inc:
            conn.close(); response.status = 404
            return {"error": "Incident not found"}
        sid = inc["signature_id"]
        src = inc["attacker_ip"] or ""
        if not sid:
            conn.close()
            return {"total": 0, "tp": 0, "fp": 0, "recent": []}
        rows = conn.execute(
            "SELECT verdict, COUNT(*) as c FROM incidents "
            "WHERE signature_id=? AND status='closed' AND id != ? GROUP BY verdict",
            (sid, incident_id),
        ).fetchall()
        counts = {r["verdict"]: r["c"] for r in rows}
        tp = counts.get("true_positive", 0)
        fp = counts.get("false_positive", 0)
        # Same signature + same source, most recent 5
        recent = [dict(r) for r in conn.execute(
            "SELECT id, verdict, closure_summary, closed_by, resolved_at, attacker_ip, victim_ip "
            "FROM incidents WHERE signature_id=? AND status='closed' AND id != ? "
            "ORDER BY resolved_at DESC LIMIT 5", (sid, incident_id),
        ).fetchall()]
        # Same signature+source stats
        same_src = 0
        if src:
            r = conn.execute(
                "SELECT COUNT(*) as c FROM incidents WHERE signature_id=? AND attacker_ip=? "
                "AND status='closed' AND id != ?", (sid, src, incident_id)
            ).fetchone()
            same_src = r["c"] if r else 0
        conn.close()
        return {
            "signature_id": sid, "src_ip": src,
            "total": tp + fp, "tp": tp, "fp": fp,
            "same_src_count": same_src,
            "recent": recent,
        }

    # ------------------------------------------------------------------
    # Bulk actions on many incidents at once
    # ------------------------------------------------------------------
    @app.post("/api/incidents/bulk")
    def bulk_action():
        data = request.json or {}
        ids = data.get("ids") or []
        action = (data.get("action") or "").strip()
        if not ids or not isinstance(ids, list):
            response.status = 400
            return {"error": "ids (list) required"}
        try:
            ids = [int(x) for x in ids]
        except Exception:
            response.status = 400
            return {"error": "ids must be integers"}
        if not action:
            response.status = 400
            return {"error": "action required"}

        actor = ""
        try:
            actor = (getattr(request, "user", {}) or {}).get("username", "") or ""
        except Exception:
            pass

        # Belt-and-suspenders: refuse to run any bulk SQL without a concrete id list.
        # placeholders="" would produce "IN ()" which SQLite rejects, but let's be explicit.
        if not ids:
            response.status = 400
            return {"error": "ids must be a non-empty list"}

        conn = get_db()
        placeholders = ",".join("?" * len(ids))
        affected = 0

        if action in ("close_fp", "close_tp"):
            verdict = "false_positive" if action == "close_fp" else "true_positive"
            summary = (data.get("summary") or f"Bulk-closed as {verdict} by {actor or 'user'}").strip()
            cur = conn.execute(
                f"UPDATE incidents SET status='closed', verdict=?, closure_summary=?, "
                f"closed_by=?, resolved_at=datetime('now','localtime'), "
                f"updated_at=datetime('now','localtime'), phase='closed' "
                f"WHERE id IN ({placeholders}) AND status != 'closed'",
                [verdict, summary, actor or "bulk"] + ids
            )
            affected = cur.rowcount

        elif action == "assign":
            assignee = (data.get("assignee") or "").strip()
            cur = conn.execute(
                f"UPDATE incidents SET assigned_to=?, updated_at=datetime('now','localtime') "
                f"WHERE id IN ({placeholders})",
                [assignee] + ids
            )
            affected = cur.rowcount
            # Notify each assignee (skip self)
            if assignee and assignee != actor:
                for iid in ids:
                    conn.execute(
                        "INSERT INTO user_notifications (username, type, incident_id, title, message) "
                        "VALUES (?, 'assignment', ?, ?, ?)",
                        (assignee, iid,
                         f"Incident #{iid} assigned to you (bulk)",
                         f"{actor or 'system'} bulk-assigned {len(ids)} incidents to you"),
                    )

        elif action == "mark_investigating":
            cur = conn.execute(
                f"UPDATE incidents SET phase='investigate', "
                f"phase_started_at=datetime('now','localtime'), "
                f"updated_at=datetime('now','localtime') "
                f"WHERE id IN ({placeholders}) AND status='open'",
                ids
            )
            affected = cur.rowcount

        elif action == "delete":
            cur = conn.execute(f"DELETE FROM incidents WHERE id IN ({placeholders})", ids)
            affected = cur.rowcount

        else:
            conn.close()
            response.status = 400
            return {"error": f"Unknown action: {action}"}

        conn.commit()
        conn.close()
        return {"ok": True, "affected": affected, "action": action}

    # ------------------------------------------------------------------
    # Notifications for the current user
    # ------------------------------------------------------------------
    @app.get("/api/notifications")
    def list_notifications():
        actor = ""
        try:
            actor = (getattr(request, "user", {}) or {}).get("username", "") or ""
        except Exception:
            pass
        if not actor:
            response.status = 401
            return {"error": "Auth required"}
        unread_only = request.query.get("unread", "").lower() in ("1", "true", "yes")
        limit = min(int(request.query.get("limit", 50)), 200)
        conn = get_db()
        q = "SELECT * FROM user_notifications WHERE username = ?"
        params = [actor]
        if unread_only:
            q += " AND is_read = 0"
        q += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = [dict(r) for r in conn.execute(q, params).fetchall()]
        unread = conn.execute(
            "SELECT COUNT(*) as c FROM user_notifications WHERE username=? AND is_read=0",
            (actor,),
        ).fetchone()["c"]
        conn.close()
        return {"notifications": rows, "unread_count": unread}

    @app.post("/api/notifications/read")
    def mark_notifications_read():
        actor = ""
        try:
            actor = (getattr(request, "user", {}) or {}).get("username", "") or ""
        except Exception:
            pass
        if not actor:
            response.status = 401
            return {"error": "Auth required"}
        data = request.json or {}
        ids = data.get("ids")  # None = mark all read
        conn = get_db()
        if ids and isinstance(ids, list):
            placeholders = ",".join("?" * len(ids))
            conn.execute(
                f"UPDATE user_notifications SET is_read=1, read_at=datetime('now','localtime') "
                f"WHERE username=? AND id IN ({placeholders})",
                [actor] + ids
            )
        else:
            conn.execute(
                "UPDATE user_notifications SET is_read=1, read_at=datetime('now','localtime') "
                "WHERE username=? AND is_read=0",
                (actor,)
            )
        n = conn.total_changes
        conn.commit()
        conn.close()
        return {"ok": True, "marked": n}

    # ------------------------------------------------------------------
    # Analyst dashboard — current user's queue at a glance
    # ------------------------------------------------------------------
    @app.get("/api/incidents/my-dashboard")
    def my_dashboard():
        actor = ""
        try:
            actor = (getattr(request, "user", {}) or {}).get("username", "") or ""
        except Exception:
            pass
        if not actor:
            response.status = 401
            return {"error": "Auth required"}
        conn = get_db()
        # SLA hours by severity (industry defaults)
        SLA = {"critical": 4, "high": 8, "medium": 24, "low": 72, "info": 168}
        assigned = [dict(r) for r in conn.execute(
            "SELECT * FROM incidents WHERE assigned_to=? AND status='open' ORDER BY created_at",
            (actor,)
        ).fetchall()]
        now_row = conn.execute("SELECT datetime('now','localtime') as now").fetchone()
        # Aging counts
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        breached = 0
        oldest_age_hours = 0
        for inc in assigned:
            sev = inc.get("severity") or "medium"
            by_sev[sev] = by_sev.get(sev, 0) + 1
            # Age in hours
            try:
                from datetime import datetime as _dt
                created = _dt.fromisoformat((inc.get("created_at") or "").replace("Z", ""))
                now = _dt.fromisoformat(now_row["now"])
                age_h = (now - created).total_seconds() / 3600.0
                oldest_age_hours = max(oldest_age_hours, age_h)
                if age_h > SLA.get(sev, 24):
                    breached += 1
            except Exception:
                pass
        investigating = sum(1 for i in assigned if i.get("phase") in
                           ("investigate", "contain", "eradicate", "recover"))
        triage = len(assigned) - investigating
        # Recent closures by this analyst
        recent_closures = [dict(r) for r in conn.execute(
            "SELECT id, title, verdict, resolved_at FROM incidents "
            "WHERE closed_by=? AND status='closed' "
            "ORDER BY resolved_at DESC LIMIT 10",
            (actor,)
        ).fetchall()]
        conn.close()
        return {
            "user": actor,
            "assigned_open": len(assigned),
            "triage": triage,
            "investigating": investigating,
            "by_severity": by_sev,
            "sla_breached": breached,
            "oldest_age_hours": round(oldest_age_hours, 1),
            "recent_closures": recent_closures,
        }

    @app.delete("/api/incidents/<incident_id:int>")
    def delete_incident(incident_id):
        conn = get_db()
        conn.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
        conn.commit()
        conn.close()
        return {"ok": True}

    @app.post("/api/incidents/<incident_id:int>/events")
    def add_event(incident_id):
        data = request.json or {}
        conn = get_db()
        inc = conn.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not inc:
            conn.close()
            response.status = 404
            return {"error": "Incident not found"}

        event_data = data.get("event_data", "")
        if isinstance(event_data, dict):
            event_data = json.dumps(event_data)

        conn.execute(
            """INSERT INTO incident_events
               (incident_id, event_type, event_summary, event_data, src_ip, dest_ip, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (incident_id, data.get("event_type", ""), data.get("event_summary", ""),
             event_data, data.get("src_ip", ""), data.get("dest_ip", ""), data.get("timestamp", "")),
        )
        conn.execute("UPDATE incidents SET updated_at = datetime('now','localtime') WHERE id = ?", (incident_id,))
        conn.commit()
        conn.close()
        response.status = 201
        return {"ok": True}

    @app.delete("/api/incidents/<incident_id:int>/events/<event_id:int>")
    def remove_event(incident_id, event_id):
        conn = get_db()
        conn.execute("DELETE FROM incident_events WHERE id = ? AND incident_id = ?", (event_id, incident_id))
        conn.commit()
        conn.close()
        return {"ok": True}

    @app.post("/api/incidents/<incident_id:int>/notes")
    def add_note(incident_id):
        data = request.json or {}
        content = data.get("content", "").strip()
        if not content:
            response.status = 400
            return {"error": "Content is required"}

        conn = get_db()
        conn.execute(
            "INSERT INTO incident_notes (incident_id, content) VALUES (?, ?)",
            (incident_id, content),
        )
        conn.execute("UPDATE incidents SET updated_at = datetime('now','localtime') WHERE id = ?", (incident_id,))
        conn.commit()
        conn.close()
        response.status = 201
        return {"ok": True}

    # ── Incident Automation Rules ───────────────────────────────────────

    def _ip_in_subnet(ip_str, subnet_str):
        """Check if an IP matches a comma-separated list of IPs/CIDRs."""
        if not ip_str or not subnet_str:
            return False
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        for part in subnet_str.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                if "/" in part:
                    if addr in ipaddress.ip_network(part, strict=False):
                        return True
                else:
                    if addr == ipaddress.ip_address(part):
                        return True
            except ValueError:
                continue
        return False

    def _rule_matches(rule, inc):
        """Check if an automation rule matches an incident. All non-empty
        conditions must match (AND logic)."""
        checks = 0
        if rule["match_signature"]:
            checks += 1
            pat = rule["match_signature"].strip()
            sig = inc.get("signature") or inc.get("title") or ""
            if "*" in pat:
                regex = re.escape(pat).replace(r"\*", ".*")
                if not re.search(regex, sig, re.IGNORECASE):
                    return False
            elif pat.lower() not in sig.lower():
                return False

        if rule["match_sid"]:
            checks += 1
            inc_sid = inc.get("signature_id") or 0
            if not inc_sid:
                return False
            matched_sid = False
            for part in rule["match_sid"].split(","):
                part = part.strip()
                if "-" in part:
                    try:
                        lo, hi = part.split("-", 1)
                        if int(lo) <= int(inc_sid) <= int(hi):
                            matched_sid = True
                            break
                    except ValueError:
                        continue
                else:
                    try:
                        if int(part) == int(inc_sid):
                            matched_sid = True
                            break
                    except ValueError:
                        continue
            if not matched_sid:
                return False

        if rule["match_severity"]:
            checks += 1
            sevs = [s.strip().lower() for s in rule["match_severity"].split(",")]
            if (inc.get("severity") or "").lower() not in sevs:
                return False

        if rule["match_src_subnet"]:
            checks += 1
            if not _ip_in_subnet(inc.get("attacker_ip", ""), rule["match_src_subnet"]):
                return False

        if rule["match_dst_subnet"]:
            checks += 1
            if not _ip_in_subnet(inc.get("victim_ip", ""), rule["match_dst_subnet"]):
                return False

        if rule["match_title_pattern"]:
            checks += 1
            pat = rule["match_title_pattern"].strip()
            title = inc.get("title") or ""
            if "*" in pat:
                regex = re.escape(pat).replace(r"\*", ".*")
                if not re.search(regex, title, re.IGNORECASE):
                    return False
            elif pat.lower() not in title.lower():
                return False

        return checks > 0

    def _find_matching_rule(conn, inc):
        """Find the highest-priority enabled rule that matches this incident."""
        rules = conn.execute(
            "SELECT * FROM incident_auto_rules WHERE enabled=1 ORDER BY priority ASC, id ASC"
        ).fetchall()
        for r in rules:
            if _rule_matches(dict(r), dict(inc)):
                return dict(r)
        return None

    def _apply_auto_rule(conn, incident_id, rule, applied_by=None):
        """Apply a smart-resolve rule action to an incident."""
        if applied_by is None:
            applied_by = rule.get("created_by") or "system"
        action = rule["action"]
        if action in ("close_fp", "close_tp"):
            verdict = "false_positive" if action == "close_fp" else "true_positive"
            conn.execute("""
                UPDATE incidents SET
                    verdict=?, status='closed', phase='closed',
                    resolved_at=datetime('now','localtime'),
                    updated_at=datetime('now','localtime'),
                    closure_classification=?, closure_certin_category=?,
                    closure_impact=?, closure_mitre_tactic=?,
                    closure_mitre_technique=?, closure_summary=?,
                    closed_by=?
                WHERE id=?""",
                (verdict,
                 rule.get("auto_classification") or "",
                 rule.get("auto_certin_category") or "",
                 rule.get("auto_impact") or "",
                 rule.get("auto_mitre_tactic") or "",
                 rule.get("auto_mitre_technique") or "",
                 rule.get("auto_summary") or "",
                 applied_by,
                 incident_id))
            _close_active_phase(conn, incident_id, by=applied_by,
                                notes=f"Auto-closed as {verdict} by rule: {rule['name']}")
            _open_phase_log(conn, incident_id, "closed", by=applied_by)
            return {"result": "closed", "verdict": verdict}

        elif action == "escalate":
            conn.execute("""
                UPDATE incidents SET
                    severity = CASE WHEN severity IN ('low','medium') THEN 'high' ELSE severity END,
                    verdict='investigating',
                    updated_at=datetime('now','localtime')
                WHERE id=?""", (incident_id,))
            return {"result": "escalated"}

        elif action == "investigate":
            conn.execute("""
                UPDATE incidents SET
                    verdict='investigating',
                    phase = CASE WHEN phase='triage' THEN 'investigate' ELSE phase END,
                    updated_at=datetime('now','localtime')
                WHERE id=?""", (incident_id,))
            return {"result": "investigating"}

        return {"result": "no_action"}

    @app.get("/api/incident-auto-rules")
    def list_auto_rules():
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM incident_auto_rules ORDER BY priority ASC, id ASC"
        ).fetchall()
        conn.close()
        return {"rules": [dict(r) for r in rows]}

    @app.post("/api/incident-auto-rules")
    def create_auto_rule():
        data = request.json or {}
        name = (data.get("name") or "").strip()
        if not name:
            response.status = 400
            return {"error": "Rule name is required"}
        action = data.get("action", "close_fp")
        if action not in ("close_fp", "close_tp", "investigate", "escalate"):
            response.status = 400
            return {"error": "Invalid action"}

        conn = get_db()
        cur = conn.execute("""
            INSERT INTO incident_auto_rules
            (name, description, enabled, priority,
             match_signature, match_sid, match_severity,
             match_src_subnet, match_dst_subnet, match_title_pattern,
             action, auto_classification, auto_certin_category,
             auto_impact, auto_mitre_tactic, auto_mitre_technique,
             auto_summary, created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (name,
             data.get("description", ""),
             1 if data.get("enabled", True) else 0,
             int(data.get("priority", 100)),
             data.get("match_signature", ""),
             data.get("match_sid", ""),
             data.get("match_severity", ""),
             data.get("match_src_subnet", ""),
             data.get("match_dst_subnet", ""),
             data.get("match_title_pattern", ""),
             action,
             data.get("auto_classification", ""),
             data.get("auto_certin_category", ""),
             data.get("auto_impact", ""),
             data.get("auto_mitre_tactic", ""),
             data.get("auto_mitre_technique", ""),
             data.get("auto_summary", ""),
             data.get("created_by", "")))
        conn.commit()
        rule = dict(conn.execute(
            "SELECT * FROM incident_auto_rules WHERE id=?", (cur.lastrowid,)
        ).fetchone())
        conn.close()
        response.status = 201
        return {"ok": True, "rule": rule}

    @app.put("/api/incident-auto-rules/<rule_id:int>")
    def update_auto_rule(rule_id):
        data = request.json or {}
        conn = get_db()
        existing = conn.execute(
            "SELECT * FROM incident_auto_rules WHERE id=?", (rule_id,)
        ).fetchone()
        if not existing:
            conn.close()
            response.status = 404
            return {"error": "Rule not found"}

        fields = [
            "name", "description", "enabled", "priority",
            "match_signature", "match_sid", "match_severity",
            "match_src_subnet", "match_dst_subnet", "match_title_pattern",
            "action", "auto_classification", "auto_certin_category",
            "auto_impact", "auto_mitre_tactic", "auto_mitre_technique",
            "auto_summary",
        ]
        sets, params = [], []
        for f in fields:
            if f in data:
                sets.append(f"{f}=?")
                val = data[f]
                if f == "enabled":
                    val = 1 if val else 0
                elif f == "priority":
                    val = int(val)
                params.append(val)
        if sets:
            sets.append("updated_at=datetime('now','localtime')")
            params.append(rule_id)
            conn.execute(
                f"UPDATE incident_auto_rules SET {', '.join(sets)} WHERE id=?",
                params)
            conn.commit()
        rule = dict(conn.execute(
            "SELECT * FROM incident_auto_rules WHERE id=?", (rule_id,)
        ).fetchone())
        conn.close()
        return {"ok": True, "rule": rule}

    @app.delete("/api/incident-auto-rules/<rule_id:int>")
    def delete_auto_rule(rule_id):
        conn = get_db()
        conn.execute("DELETE FROM incident_auto_rules WHERE id=?", (rule_id,))
        conn.commit()
        conn.close()
        return {"ok": True}

    @app.post("/api/incidents/<incident_id:int>/auto-resolve")
    def auto_resolve_incident(incident_id):
        """Run a single incident through automation rules.
        If dry_run=true in body, returns the recommendation without applying."""
        data = request.json or {}
        dry_run = data.get("dry_run", False)

        conn = get_db()
        inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not inc:
            conn.close()
            response.status = 404
            return {"error": "Incident not found"}
        if inc["status"] == "closed":
            conn.close()
            return {"ok": False, "reason": "already_closed", "message": "Incident is already closed"}

        rule = _find_matching_rule(conn, inc)
        if not rule:
            conn.close()
            return {"ok": False, "reason": "no_match",
                    "message": "No matching smart rule for this incident"}

        if dry_run:
            conn.close()
            return {"ok": True, "dry_run": True, "rule": rule,
                    "action": rule["action"], "rule_name": rule["name"]}

        result = _apply_auto_rule(conn, incident_id, rule)
        conn.commit()
        updated = dict(conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone())
        conn.close()
        return {"ok": True, "rule": rule, "action": rule["action"],
                "rule_name": rule["name"], "result": result, "incident": updated}

    @app.post("/api/incidents/auto-resolve-bulk")
    def auto_resolve_bulk():
        """Run all open/investigating incidents through automation rules.
        Body: {dry_run: bool, limit: int}"""
        data = request.json or {}
        dry_run = data.get("dry_run", False)
        limit = min(int(data.get("limit", 500)), 500)

        conn = get_db()
        open_incidents = conn.execute(
            "SELECT * FROM incidents WHERE status != 'closed' ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()

        results = []
        for inc in open_incidents:
            inc_d = dict(inc)
            rule = _find_matching_rule(conn, inc)
            if not rule:
                continue
            entry = {
                "incident_id": inc_d["id"],
                "title": inc_d["title"],
                "severity": inc_d["severity"],
                "rule_name": rule["name"],
                "action": rule["action"],
            }
            if not dry_run:
                result = _apply_auto_rule(conn, inc_d["id"], rule)
                entry["result"] = result
            results.append(entry)

        if not dry_run:
            conn.commit()
        conn.close()
        return {
            "ok": True,
            "dry_run": dry_run,
            "total_scanned": len(open_incidents),
            "total_matched": len(results),
            "results": results,
        }

    @app.post("/api/incident-auto-rules/seed-defaults")
    def seed_default_rules():
        """Insert default automation rules if none exist."""
        conn = get_db()
        count = conn.execute("SELECT COUNT(*) FROM incident_auto_rules").fetchone()[0]
        if count > 0:
            conn.close()
            return {"ok": True, "message": "Rules already exist", "seeded": 0}

        defaults = [
            {
                "name": "Cross-VLAN Scan Noise",
                "description": "Port scans from non-monitored subnets (10.2-5.x) to monitored VLAN are normal cross-VLAN traffic",
                "priority": 10,
                "match_signature": "*SCAN*",
                "match_src_subnet": "10.2.0.0/16,10.3.0.0/16,10.4.0.0/16,10.5.0.0/16",
                "action": "close_fp",
                "auto_classification": "Reconnaissance / Scanning",
                "auto_certin_category": "Network Scanning / Probing",
                "auto_impact": "None",
                "auto_mitre_tactic": "Reconnaissance",
                "auto_mitre_technique": "T1046",
                "auto_summary": "Cross-VLAN scan noise from non-monitored subnet. Auto-closed as false positive.",
            },
            {
                "name": "Excessive Outbound to Google/CDN",
                "description": "Excessive outbound connections to known Google/CDN IPs are normal browsing",
                "priority": 20,
                "match_signature": "*Excessive Outbound*",
                "match_dst_subnet": "142.250.0.0/15,142.251.0.0/16,172.217.0.0/16,173.194.0.0/16,216.58.0.0/16",
                "action": "close_fp",
                "auto_classification": "Policy Violation",
                "auto_certin_category": "Other",
                "auto_impact": "None",
                "auto_mitre_tactic": "Exfiltration",
                "auto_mitre_technique": "T1041",
                "auto_summary": "Outbound connections to Google/CDN infrastructure. Normal browsing activity.",
            },
            {
                "name": "DNS Queries to Internal DNS Server",
                "description": "DNS tunnel alerts to the internal DNS server are normal recursive resolution",
                "priority": 25,
                "match_signature": "*DNS Tunnel*",
                "match_dst_subnet": "10.4.20.21",
                "action": "close_fp",
                "auto_classification": "Other",
                "auto_certin_category": "Other",
                "auto_impact": "None",
                "auto_mitre_tactic": "Command and Control",
                "auto_mitre_technique": "T1071.004",
                "auto_summary": "DNS queries to internal DNS server. Normal recursive resolution, not tunneling.",
            },
            {
                "name": "DHCP/NetBIOS/mDNS Protocol Noise",
                "description": "Common protocol noise from DHCP, NetBIOS, mDNS",
                "priority": 30,
                "match_sid": "1000522,1000528,1000523",
                "action": "close_fp",
                "auto_classification": "Other",
                "auto_certin_category": "Other",
                "auto_impact": "None",
                "auto_summary": "Normal network protocol activity (DHCP/NetBIOS/mDNS). Auto-closed as false positive.",
            },
            {
                "name": "Critical External Attack on Monitored Assets",
                "description": "Critical alerts from external IPs targeting monitored assets",
                "priority": 50,
                "match_severity": "critical",
                "match_dst_subnet": "10.1.96.0/23",
                "action": "escalate",
                "auto_summary": "Critical-severity alert targeting monitored infrastructure. Escalated for immediate review.",
            },
            {
                "name": "Low Severity Internal Traffic",
                "description": "Low severity alerts between internal assets need analyst review",
                "priority": 90,
                "match_severity": "low",
                "match_src_subnet": "10.0.0.0/8",
                "match_dst_subnet": "10.0.0.0/8",
                "action": "investigate",
                "auto_summary": "Low-severity internal traffic. Moved to investigation for analyst review.",
            },
        ]

        for d in defaults:
            conn.execute("""
                INSERT INTO incident_auto_rules
                (name, description, priority, match_signature, match_sid,
                 match_severity, match_src_subnet, match_dst_subnet,
                 match_title_pattern, action, auto_classification,
                 auto_certin_category, auto_impact, auto_mitre_tactic,
                 auto_mitre_technique, auto_summary, enabled, created_by)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,'system')""",
                (d["name"], d.get("description", ""), d.get("priority", 100),
                 d.get("match_signature", ""), d.get("match_sid", ""),
                 d.get("match_severity", ""), d.get("match_src_subnet", ""),
                 d.get("match_dst_subnet", ""), d.get("match_title_pattern", ""),
                 d["action"], d.get("auto_classification", ""),
                 d.get("auto_certin_category", ""), d.get("auto_impact", ""),
                 d.get("auto_mitre_tactic", ""), d.get("auto_mitre_technique", ""),
                 d.get("auto_summary", "")))
        conn.commit()
        conn.close()
        return {"ok": True, "seeded": len(defaults)}

    # ══════════════════════════════════════════════════════════════════
    # Session 2 AI endpoints
    # ══════════════════════════════════════════════════════════════════

    # ── Alerts: bulk-triage suggestion for a signature-cluster ──
    @app.get("/api/ai/bulk-triage/<sid:int>")
    def ai_bulk_triage(sid):
        try:
            from analyzers.llm_assistant import bulk_triage_suggestion
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        conn = get_db()
        row = conn.execute(
            "SELECT signature, severity, COUNT(*) as c FROM ingested_alerts WHERE signature_id=? "
            "AND timestamp > datetime('now','-7 days','localtime') GROUP BY signature, severity "
            "ORDER BY c DESC LIMIT 1",
            (sid,)
        ).fetchone()
        if not row or row["c"] == 0:
            conn.close(); return {"error": f"no recent alerts for sid={sid}"}
        src_ips = [r["src_ip"] for r in conn.execute(
            "SELECT DISTINCT src_ip FROM ingested_alerts WHERE signature_id=? "
            "AND timestamp > datetime('now','-7 days','localtime') LIMIT 8", (sid,)
        ).fetchall()]
        dst_ips = [r["dest_ip"] for r in conn.execute(
            "SELECT DISTINCT dest_ip FROM ingested_alerts WHERE signature_id=? "
            "AND timestamp > datetime('now','-7 days','localtime') LIMIT 8", (sid,)
        ).fetchall()]
        # Prior verdict split for the signature
        v_rows = conn.execute(
            "SELECT verdict, COUNT(*) as c FROM incidents WHERE signature_id=? "
            "AND status='closed' GROUP BY verdict", (sid,)
        ).fetchall()
        v_total = sum(r["c"] for r in v_rows) or 1
        tp = sum(r["c"] for r in v_rows if r["verdict"] == "true_positive")
        fp = sum(r["c"] for r in v_rows if r["verdict"] == "false_positive")
        conn.close()
        source_external = any(not (s or "").startswith(("10.","172.16.","172.17.","172.18.","172.19.",
                                                         "172.2","172.30.","172.31.","192.168."))
                              for s in src_ips)
        r = bulk_triage_suggestion({
            "sid": sid, "signature": row["signature"], "count": row["c"],
            "src_ips_sample": src_ips, "dst_ips_sample": dst_ips,
            "severity": row["severity"], "source_is_external": source_external,
            "prior_tp_pct": round(tp * 100 / v_total) if v_total else 0,
            "prior_fp_pct": round(fp * 100 / v_total) if v_total else 0,
        })
        if "error" in r: response.status = 503
        return r

    # ── Alerts: cluster story for a signature (enriched context) ──
    @app.get("/api/ai/alert-cluster-story/<sid:int>")
    def ai_alert_cluster_story(sid):
        try:
            from analyzers.llm_assistant import alert_cluster_story
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        conn = get_db()
        r = conn.execute(
            "SELECT signature, COUNT(*) as c, MIN(timestamp) as first_seen, "
            "MAX(timestamp) as last_seen, COUNT(DISTINCT src_ip) as usrc, "
            "COUNT(DISTINCT dest_ip) as udst "
            "FROM ingested_alerts WHERE signature_id=? "
            "AND timestamp > datetime('now','-24 hours','localtime')", (sid,)
        ).fetchone()
        if not r or r["c"] == 0:
            conn.close(); return {"error": f"no alerts in last 24h for sid={sid}"}
        port_row = conn.execute(
            "SELECT dest_port, COUNT(*) as c FROM ingested_alerts WHERE signature_id=? "
            "AND timestamp > datetime('now','-24 hours','localtime') "
            "AND dest_port IS NOT NULL GROUP BY dest_port ORDER BY c DESC LIMIT 1", (sid,)
        ).fetchone()
        # Enrichment: top 3 src / dst IPs, prior verdict %, whether victims are registered assets
        top_src = [row["src_ip"] for row in conn.execute(
            "SELECT src_ip, COUNT(*) as c FROM ingested_alerts WHERE signature_id=? "
            "AND timestamp > datetime('now','-24 hours','localtime') "
            "GROUP BY src_ip ORDER BY c DESC LIMIT 3", (sid,)
        ).fetchall()]
        top_dst = [row["dest_ip"] for row in conn.execute(
            "SELECT dest_ip, COUNT(*) as c FROM ingested_alerts WHERE signature_id=? "
            "AND timestamp > datetime('now','-24 hours','localtime') "
            "GROUP BY dest_ip ORDER BY c DESC LIMIT 3", (sid,)
        ).fetchall()]
        # Prior verdict split for this sig (closed incidents)
        v_rows = conn.execute(
            "SELECT verdict, COUNT(*) as c FROM incidents WHERE signature_id=? "
            "AND status='closed' GROUP BY verdict", (sid,)
        ).fetchall()
        v_total = sum(row["c"] for row in v_rows) or 0
        tp = sum(row["c"] for row in v_rows if row["verdict"] == "true_positive")
        fp = sum(row["c"] for row in v_rows if row["verdict"] == "false_positive")
        # How many top-dst IPs are registered/critical assets?
        registered_dsts = 0
        critical_dsts = 0
        for ip in top_dst:
            row = conn.execute(
                "SELECT business_critical FROM assets WHERE ip=?", (ip,)
            ).fetchone()
            if row:
                registered_dsts += 1
                if row["business_critical"]:
                    critical_dsts += 1
        conn.close()
        from datetime import datetime as _dt
        span_min = 0
        try:
            f_ts = _dt.fromisoformat((r["first_seen"] or "").replace("Z", "").split("+")[0].split(".")[0])
            l_ts = _dt.fromisoformat((r["last_seen"]  or "").replace("Z", "").split("+")[0].split(".")[0])
            span_min = int((l_ts - f_ts).total_seconds() / 60)
        except Exception:
            pass
        out = alert_cluster_story({
            "sid": sid, "signature": r["signature"], "count": r["c"],
            "first_seen": r["first_seen"], "last_seen": r["last_seen"],
            "span_minutes": span_min,
            "unique_src_ips": r["usrc"], "unique_dst_ips": r["udst"],
            "common_dst_port": port_row["dest_port"] if port_row else "n/a",
            "top_src_ips": top_src,
            "top_dst_ips": top_dst,
            "prior_verdicts_total": v_total,
            "prior_tp_pct": round(tp * 100 / v_total) if v_total else None,
            "prior_fp_pct": round(fp * 100 / v_total) if v_total else None,
            "registered_dst_assets": registered_dsts,
            "critical_dst_assets": critical_dsts,
        })
        if "error" in out: response.status = 503
        return out

    # ── Incidents: auto-promote reasoning ──
    @app.get("/api/ai/auto-promote-reasoning/<incident_id:int>")
    def ai_auto_promote_reasoning(incident_id):
        try:
            from analyzers.llm_assistant import auto_promote_reasoning
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        conn = get_db()
        inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not inc:
            conn.close(); response.status = 404; return {"error": "Incident not found"}
        inc = dict(inc)
        # Best-effort factors: severity, whether source external, whether victim is critical asset,
        # burst count for this sig in last 15 min, prior TP/FP ratio.
        src = inc.get("attacker_ip") or ""
        source_external = not (src.startswith(("10.","172.16.","172.17.","172.18.","172.19.",
                                                "172.2","172.30.","172.31.","192.168.")))
        burst = conn.execute(
            "SELECT COUNT(*) as c FROM ingested_alerts WHERE signature_id=? "
            "AND timestamp > datetime('now','-15 minutes','localtime')",
            (inc.get("signature_id"),)
        ).fetchone()["c"] if inc.get("signature_id") else 0
        crit_asset = False
        if inc.get("victim_ip"):
            row = conn.execute(
                "SELECT business_critical FROM assets WHERE ip=?", (inc["victim_ip"],)
            ).fetchone()
            crit_asset = bool(row and row["business_critical"])
        conn.close()
        # Prior verdict history for this signature — helps the LLM ground the answer
        prior_tp = prior_fp = 0
        if inc.get("signature_id"):
            conn2 = get_db()
            v_rows = conn2.execute(
                "SELECT verdict, COUNT(*) as c FROM incidents WHERE signature_id=? "
                "AND status='closed' GROUP BY verdict",
                (inc["signature_id"],)
            ).fetchall()
            prior_tp = sum(r["c"] for r in v_rows if r["verdict"] == "true_positive")
            prior_fp = sum(r["c"] for r in v_rows if r["verdict"] == "false_positive")
            conn2.close()
        rule_hits = {
            "severity": inc.get("severity",""),
            "severity_qualifies": inc.get("severity") in ("critical","high"),
            "source_is_external": source_external,
            "burst_last_15min": burst,
            "burst_qualifies": burst >= 3,
            "victim_is_critical_asset": crit_asset,
            "kill_chain_phase": inc.get("phase",""),
            "prior_tp_for_sig": prior_tp,
            "prior_fp_for_sig": prior_fp,
        }
        r = auto_promote_reasoning({
            "signature": inc.get("signature",""),
            "sid": inc.get("signature_id",""),
            "severity": inc.get("severity",""),
            "src_ip": src, "dest_ip": inc.get("victim_ip",""),
            "phase": inc.get("phase",""),
        }, rule_hits)
        if "error" in r: response.status = 503
        return r

    # ── Assets: missing asset finder ──
    @app.get("/api/ai/missing-assets")
    def ai_missing_assets():
        try:
            from analyzers.llm_assistant import missing_asset_finder
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        conn = get_db()
        # IPs that appear in alerts but aren't in assets
        rows = conn.execute("""
            SELECT ip, alert_count, days_seen FROM (
                SELECT src_ip AS ip, COUNT(*) AS alert_count,
                       COUNT(DISTINCT date(timestamp)) AS days_seen
                FROM ingested_alerts
                WHERE timestamp > datetime('now','-7 days','localtime')
                  AND (src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '172.17.%'
                       OR src_ip LIKE '172.18.%' OR src_ip LIKE '172.19.%'
                       OR src_ip LIKE '172.2%.' OR src_ip LIKE '172.30.%'
                       OR src_ip LIKE '172.31.%' OR src_ip LIKE '192.168.%')
                GROUP BY src_ip
                UNION ALL
                SELECT dest_ip AS ip, COUNT(*) AS alert_count,
                       COUNT(DISTINCT date(timestamp)) AS days_seen
                FROM ingested_alerts
                WHERE timestamp > datetime('now','-7 days','localtime')
                  AND (dest_ip LIKE '10.%' OR dest_ip LIKE '172.16.%' OR dest_ip LIKE '192.168.%')
                GROUP BY dest_ip
            )
            WHERE ip NOT IN (SELECT ip FROM assets)
            GROUP BY ip
            ORDER BY SUM(alert_count) DESC LIMIT 15
        """).fetchall()
        candidates = []
        for r in rows:
            candidates.append({
                "ip": r["ip"],
                "alert_count": r["alert_count"],
                "days_seen": r["days_seen"],
                "flow_count": r["alert_count"],
                "listening_ports": [],
            })
        conn.close()
        r = missing_asset_finder(candidates)
        if "error" in r: response.status = 503
        return r

    # ── Anomalies: WHY hypothesis ──
    @app.post("/api/ai/anomaly-why")
    def ai_anomaly_why():
        try:
            from analyzers.llm_assistant import anomaly_why
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        data = request.json or {}
        r = anomaly_why({
            "type": data.get("type", "unknown"),
            "endpoint": data.get("endpoint", ""),
            "description": data.get("description", ""),
            "sample_indicators": data.get("sample_indicators", ""),
        })
        if "error" in r: response.status = 503
        return r

    # ── Anomalies: action recommendation ──
    @app.post("/api/ai/anomaly-action")
    def ai_anomaly_action():
        try:
            from analyzers.llm_assistant import anomaly_action_recommendation
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        data = request.json or {}
        endpoint = data.get("endpoint", "")
        conn = get_db()
        row = None
        if endpoint:
            row = conn.execute(
                "SELECT asset_type, owner, business_critical FROM assets WHERE ip=?", (endpoint,)
            ).fetchone()
        conn.close()
        ctx = {
            "is_registered_asset": bool(row),
            "asset_type": row["asset_type"] if row else "unknown",
            "asset_owner": row["owner"] if row else "unknown",
            "prior_anomalies_dismissed": 0,
        }
        r = anomaly_action_recommendation({
            "type": data.get("type", "unknown"),
            "endpoint": endpoint,
            "description": data.get("description", ""),
        }, ctx)
        if "error" in r: response.status = 503
        return r

    # ── Sessions: narrator ──
    @app.post("/api/ai/session-narrator")
    def ai_session_narrator():
        try:
            from analyzers.llm_assistant import session_narrator
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        data = request.json or {}
        r = session_narrator(data)
        if "error" in r: response.status = 503
        return r

    # ── Monitoring: Suricata stats interpreter ──
    @app.get("/api/ai/suricata-stats")
    def ai_suricata_stats():
        try:
            from analyzers.llm_assistant import suricata_stats_interpreter
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        # Best-effort: read stats.log if configured, else use a small aggregate from the DB.
        stats = {}
        stats_path = os.environ.get("SURICATA_STATS_LOG", "/var/log/suricata/stats.log")
        try:
            if os.path.exists(stats_path):
                with open(stats_path, "r") as f:
                    lines = f.readlines()[-200:]  # tail
                for ln in lines:
                    if "|" in ln and "." in ln:
                        parts = [p.strip() for p in ln.split("|")]
                        if len(parts) >= 3:
                            key, _, val = parts[0], parts[1], parts[-1]
                            if key and val and val.strip().replace(".","").isdigit():
                                stats[key] = val
        except Exception:
            pass
        if not stats:
            # Fallback: derive rough numbers from the alert index.
            conn = get_db()
            try:
                stats["alerts_last_hour"] = conn.execute(
                    "SELECT COUNT(*) as c FROM ingested_alerts WHERE timestamp > datetime('now','-1 hour','localtime')"
                ).fetchone()["c"]
                stats["alerts_last_24h"] = conn.execute(
                    "SELECT COUNT(*) as c FROM ingested_alerts WHERE timestamp > datetime('now','-24 hours','localtime')"
                ).fetchone()["c"]
                stats["_note"] = "stats.log not found — showing DB-derived alert counts only"
            except Exception:
                pass
            conn.close()
        r = suricata_stats_interpreter(stats)
        if "error" in r: response.status = 503
        r["_raw_sample"] = dict(list(stats.items())[:8])
        return r

    # ── Monitoring: MITRE gap analysis ──
    @app.get("/api/ai/mitre-gaps")
    def ai_mitre_gaps():
        try:
            from analyzers.llm_assistant import mitre_gap_analysis
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        conn = get_db()
        # Simple coverage read: from incidents table's mitre_tactic column, count distinct tactics.
        rows = conn.execute(
            "SELECT closure_mitre_tactic AS tactic, closure_mitre_technique AS technique_id, "
            "COUNT(*) AS c FROM incidents WHERE closure_mitre_technique IS NOT NULL "
            "AND closure_mitre_technique != '' GROUP BY closure_mitre_tactic, closure_mitre_technique"
        ).fetchall()
        conn.close()
        covered = [{"technique_id": r["technique_id"], "tactic": r["tactic"], "rule_count": r["c"]}
                   for r in rows]
        tactics = ["Reconnaissance", "Initial Access", "Execution", "Persistence",
                   "Privilege Escalation", "Defense Evasion", "Credential Access",
                   "Discovery", "Lateral Movement", "Collection", "Command and Control",
                   "Exfiltration", "Impact"]
        r = mitre_gap_analysis(covered, tactics)
        if "error" in r: response.status = 503
        r["_covered_count"] = len(covered)
        return r

    # ── Rules: improvement suggestion for a single rule ──
    @app.get("/api/ai/rule-improvement/<sid:int>")
    def ai_rule_improvement(sid):
        try:
            from analyzers.llm_assistant import rule_improvement
            from analyzers.suricata_rules import get_rule_by_sid
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        rule = get_rule_by_sid(sid)
        if not rule:
            response.status = 404; return {"error": f"no rule with sid={sid}"}
        rule_text = rule.get("raw") or rule.get("raw_line") or ""
        conn = get_db()
        total_hits = conn.execute(
            "SELECT COUNT(*) as c FROM ingested_alerts WHERE signature_id=? "
            "AND timestamp > datetime('now','-30 days','localtime')", (sid,)
        ).fetchone()["c"]
        v_rows = conn.execute(
            "SELECT verdict, COUNT(*) as c FROM incidents WHERE signature_id=? "
            "AND status='closed' AND resolved_at > datetime('now','-30 days','localtime') "
            "GROUP BY verdict", (sid,)
        ).fetchall()
        tp = sum(r["c"] for r in v_rows if r["verdict"] == "true_positive")
        fp = sum(r["c"] for r in v_rows if r["verdict"] == "false_positive")
        top_src = [r["src_ip"] for r in conn.execute(
            "SELECT src_ip, COUNT(*) as c FROM ingested_alerts WHERE signature_id=? "
            "AND timestamp > datetime('now','-30 days','localtime') "
            "GROUP BY src_ip ORDER BY c DESC LIMIT 5", (sid,)
        ).fetchall()]
        top_dst = [r["dest_ip"] for r in conn.execute(
            "SELECT dest_ip, COUNT(*) as c FROM ingested_alerts WHERE signature_id=? "
            "AND timestamp > datetime('now','-30 days','localtime') "
            "GROUP BY dest_ip ORDER BY c DESC LIMIT 5", (sid,)
        ).fetchall()]
        conn.close()
        r = rule_improvement(rule_text, {
            "total_hits": total_hits, "tp": tp, "fp": fp,
            "avg_hits_per_day": round(total_hits / 30, 1),
            "top_src_ips": top_src, "top_dst_ips": top_dst,
        })
        if "error" in r: response.status = 503
        return r

    # ── Rules: overall health check ──
    @app.get("/api/ai/rule-health")
    def ai_rule_health():
        try:
            from analyzers.llm_assistant import rule_health_check
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        conn = get_db()
        # Silent rules = rules that appeared in the DB but had 0 alerts in 30d.
        # We approximate: total distinct sids known = alerts + user_rules, silent = user_rules with no alerts.
        try:
            total_user_rules = conn.execute("SELECT COUNT(*) as c FROM user_rules").fetchone()["c"]
        except Exception:
            total_user_rules = 0
        try:
            active_sids = {r["sid"] for r in conn.execute(
                "SELECT DISTINCT signature_id as sid FROM ingested_alerts "
                "WHERE timestamp > datetime('now','-30 days','localtime')"
            ).fetchall()}
        except Exception:
            active_sids = set()
        try:
            user_sids = [r["sid"] for r in conn.execute("SELECT sid FROM user_rules").fetchall()]
        except Exception:
            user_sids = []
        silent = sum(1 for s in user_sids if s not in active_sids)
        # noisy_fp: rules with all closures = FP in last 30d
        noisy = 0
        try:
            noisy_rows = conn.execute(
                "SELECT signature_id, "
                "SUM(CASE WHEN verdict='false_positive' THEN 1 ELSE 0 END) as fp, "
                "COUNT(*) as tot FROM incidents "
                "WHERE status='closed' AND signature_id IS NOT NULL "
                "AND resolved_at > datetime('now','-30 days','localtime') "
                "GROUP BY signature_id HAVING tot >= 3 AND fp = tot"
            ).fetchall()
            noisy = len(noisy_rows)
        except Exception:
            pass
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        try:
            for r in conn.execute(
                "SELECT severity, COUNT(*) as c FROM ingested_alerts "
                "WHERE timestamp > datetime('now','-30 days','localtime') GROUP BY severity"
            ).fetchall():
                lvl = "critical" if r["severity"] == 1 else "high" if r["severity"] == 2 else "medium" if r["severity"] == 3 else "low"
                by_sev[lvl] += r["c"]
        except Exception:
            pass
        conn.close()
        r = rule_health_check({
            "total_rules": total_user_rules + len(active_sids),
            "silent_rules": silent,
            "noisy_fp_rules": noisy,
            "by_severity": by_sev,
            "mitre_coverage_pct": 0,  # would need a full MITRE map to compute honestly
            "last_updated": "unknown",
        })
        if "error" in r: response.status = 503
        return r

    # ── Rules: near-duplicate finder ──
    @app.get("/api/ai/rule-dedup")
    def ai_rule_dedup():
        try:
            from analyzers.llm_assistant import rule_dedup_finder
        except Exception as e:
            response.status = 503; return {"error": f"LLM unavailable: {e}"}
        conn = get_db()
        rules = []
        try:
            rows = conn.execute(
                "SELECT sid, msg, protocol, content, action, direction FROM user_rules "
                "WHERE enabled=1 ORDER BY sid LIMIT 80"
            ).fetchall()
            rules = [dict(r) for r in rows]
        except Exception:
            pass
        conn.close()
        if not rules:
            return {"duplicate_groups": [], "consolidation_savings": "no user rules to analyse"}
        r = rule_dedup_finder(rules)
        if "error" in r: response.status = 503
        return r
