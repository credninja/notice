"""
Auto-promote engine: evaluates recent alerts against `auto_promote_rules`
and creates incidents automatically when criteria are met.

Criteria (criterion column in auto_promote_rules):

  ti_malicious    — alert's external IP scored >= threshold by TI
                    (cache-only, never blocks on VT/AbuseIPDB API)
  alert_burst     — same (sid, src_ip) fired >= threshold times in
                    window_minutes
  killchain_phase — signature maps to phase >= threshold
  critical_asset  — alert hits a business_critical asset (threshold ignored;
                    1 hit is enough)

Every decision (promoted / skipped / failed) is logged to
auto_promote_decisions for transparency. The sweeper runs in a daemon
thread launched from app.py; the engine never deduplicates against the
file system, the engine relies on the DB-side idempotency in
promote-from-alert (same sid+src+dst within 24h returns the existing
incident) so re-runs are safe.
"""

import json
from collections import defaultdict
from datetime import datetime

from db import get_db
from eve_reader import iter_events, is_internal
from analyzers.correlation import SIGNATURE_MAP
from analyzers.ti_score import quick_chip_for_ip


SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _phase_for_signature(sig):
    s = (sig or "").lower()
    for m in SIGNATURE_MAP:
        if m["pattern"] in s:
            return int(m.get("phase") or 0)
    return 0


def _severity_label(sev):
    return {1: "critical", 2: "high", 3: "medium"}.get(sev, "low")


def _passes_severity_floor(sev_label, floor):
    return SEVERITY_RANK.get(sev_label, 0) >= SEVERITY_RANK.get(floor, 1)


def _critical_assets():
    conn = get_db()
    rows = conn.execute("SELECT ip FROM assets WHERE business_critical=1").fetchall()
    conn.close()
    return {r["ip"] for r in rows}


def _load_rules():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM auto_promote_rules WHERE enabled=1 ORDER BY id"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _log_decision(rule, alert_summary, decision, reason, incident_id=None):
    conn = get_db()
    conn.execute(
        """INSERT INTO auto_promote_decisions
           (rule_id, rule_name, signature_id, src_ip, dest_ip, decision, reason, incident_id)
           VALUES (?,?,?,?,?,?,?,?)""",
        (
            rule.get("id"), rule.get("name"),
            alert_summary.get("sid"),
            alert_summary.get("src_ip"),
            alert_summary.get("dest_ip"),
            decision,
            reason,
            incident_id,
        ),
    )
    conn.commit()
    conn.close()


def _scan_window(minutes):
    """One pass over eve.json producing per-(sid, src_ip) summaries.

    Returns:
      summaries: list of dicts (newest-first), each with sid, src_ip, dest_ip,
                 signature, severity_label, count, latest, attacker_external
    """
    bucket = defaultdict(lambda: {
        "sid": None, "src_ip": "", "dest_ip": "",
        "signature": "", "severity": 3, "count": 0,
        "phase": 0, "latest": "", "earliest": "",
    })
    for ev in iter_events(event_types={"alert"}, minutes=minutes):
        a = ev.get("alert") or {}
        sid = a.get("signature_id") or 0
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        sig = a.get("signature", "")
        sev = a.get("severity", 3)
        ts = ev.get("timestamp", "")
        key = (sid, src, dst)
        b = bucket[key]
        b["sid"] = sid
        b["src_ip"] = src
        b["dest_ip"] = dst
        b["signature"] = sig
        b["severity"] = sev
        b["count"] += 1
        b["latest"] = ts if ts > b["latest"] else b["latest"]
        b["earliest"] = ts if (not b["earliest"] or ts < b["earliest"]) else b["earliest"]
        if not b["phase"]:
            b["phase"] = _phase_for_signature(sig)
    return list(bucket.values())


FP_SUPPRESSION_DAYS = 7   # If (sid, src) was marked FP in last 7 days, skip re-promotion
FP_SUPPRESSION_THRESHOLD = 2  # Need >= 2 prior FPs to suppress (single FP could be a mistake)


def _was_recently_marked_fp(conn, sid, src):
    """True if (sid, src) has been marked false_positive >= threshold times in the
    suppression window. Prevents endless auto-promotion of alerts that analysts
    have repeatedly closed as FP.
    """
    row = conn.execute(
        """SELECT COUNT(*) as c FROM incidents
           WHERE signature_id=? AND attacker_ip=? AND verdict='false_positive'
             AND resolved_at > datetime('now', ?)""",
        (sid, src, f'-{FP_SUPPRESSION_DAYS} days'),
    ).fetchone()
    return (row["c"] or 0) >= FP_SUPPRESSION_THRESHOLD


def _promote(seed):
    """Call promote-from-alert path. Returns incident_id or None (None if suppressed)."""
    # We import lazily to avoid circular imports at module load
    from db import get_db as _db
    conn = _db()
    sid = seed.get("sid") or 0
    src = seed.get("src_ip") or ""
    dst = seed.get("dest_ip") or ""
    sig = seed.get("signature") or ""
    sev_label = _severity_label(seed.get("severity") or 3)
    title = seed.get("title") or (sig[:90] if sig else f"Alert {sid} from {src}")

    # FP suppression: if analysts have repeatedly closed this (sid, src) as FP
    # in the recent window, don't auto-promote again. They can still manually
    # promote from the Alerts tab if the situation actually changed.
    if _was_recently_marked_fp(conn, sid, src):
        conn.close()
        return None

    # Idempotency: same sid+src+dst within last 24h?
    existing = conn.execute(
        "SELECT id FROM incidents WHERE signature_id=? AND attacker_ip=? AND victim_ip=? "
        "AND created_at > datetime('now','-1 day') ORDER BY id DESC LIMIT 1",
        (sid, src, dst),
    ).fetchone()
    if existing:
        conn.close()
        return existing["id"]
    cur = conn.execute(
        """INSERT INTO incidents
           (title, description, severity, status, phase, phase_started_at,
            attacker_ip, victim_ip, signature_id, signature, assigned_to)
           VALUES (?,?,?,?,?,datetime('now','localtime'),?,?,?,?,?)""",
        (title, "[auto-promoted]", sev_label, "open", "triage",
         src, dst, sid, sig, "auto"),
    )
    incident_id = cur.lastrowid
    # Seed IOCs (primary)
    seed_iocs = [("src_ip", src), ("dest_ip", dst), ("signature_id", sid), ("signature", sig)]
    seen = set()
    for t, v in seed_iocs:
        if not v or (t, str(v)) in seen:
            continue
        seen.add((t, str(v)))
        conn.execute(
            "INSERT INTO incident_iocs (incident_id, ioc_type, ioc_value, is_primary, frequency) "
            "VALUES (?,?,?,1,1)",
            (incident_id, t, str(v)),
        )
    conn.execute(
        "INSERT INTO incident_phase_log (incident_id, phase, started_at, completed_by) "
        "VALUES (?, 'triage', datetime('now','localtime'), 'auto-promote')",
        (incident_id,),
    )
    conn.commit()
    conn.close()
    # Now fire the cluster (using the same logic as manual promote)
    try:
        from routes.incidents import _scan_related_alerts, _attach_cluster
        related, freq = _scan_related_alerts(
            120,
            attacker_ip=src or None,
            signature_id=sid,
            mode="attacker",
        )
        conn = _db()
        # Pre-load primary IOC seen set so they don't duplicate
        existing_iocs = conn.execute(
            "SELECT ioc_type, ioc_value FROM incident_iocs WHERE incident_id=?",
            (incident_id,),
        ).fetchall()
        seen2 = {(r["ioc_type"], str(r["ioc_value"])) for r in existing_iocs}
        _attach_cluster(conn, incident_id, related, freq, primary_seen=seen2)
        conn.commit()
        conn.close()
    except Exception:
        pass
    return incident_id


def _evaluate_rule(rule, summaries, critical_set):
    """Apply one rule to the current scan and produce promotion decisions.

    Returns a list of (seed, reason) tuples to promote. Skipped alerts are
    logged with reason for transparency, but only matched ones are promoted.
    """
    matches = []
    crit = (rule.get("criterion") or "").strip()
    threshold = float(rule.get("threshold") or 0)
    floor = (rule.get("severity_floor") or "medium").lower()

    for s in summaries:
        sev_label = _severity_label(s.get("severity") or 3)
        if not _passes_severity_floor(sev_label, floor):
            continue

        reason = None
        if crit == "alert_burst":
            if s["count"] >= threshold:
                reason = f"alert_burst: same (sid {s['sid']}, src {s['src_ip']}) fired {s['count']} times in {rule.get('window_minutes')}m (≥ {int(threshold)})"
        elif crit == "killchain_phase":
            if s["phase"] >= threshold:
                reason = f"killchain_phase: signature maps to phase {s['phase']} (≥ {int(threshold)})"
        elif crit == "critical_asset":
            dst = s.get("dest_ip") or ""
            src = s.get("src_ip") or ""
            if dst in critical_set or src in critical_set:
                reason = f"critical_asset: alert touches business-critical asset ({dst if dst in critical_set else src})"
        elif crit == "ti_malicious":
            # Cache-only TI lookup — never blocks. If the chip says malicious
            # OR (suspicious AND score >= threshold), promote.
            for cand in (s.get("src_ip"), s.get("dest_ip")):
                if not cand or is_internal(cand):
                    continue
                chip = quick_chip_for_ip(cand)
                if chip.get("classification") == "malicious":
                    reason = f"ti_malicious: {cand} classified malicious by TI ({chip.get('score')})"
                    break
                if chip.get("classification") == "suspicious" and chip.get("score", 0) >= threshold:
                    reason = f"ti_malicious: {cand} suspicious score {chip.get('score')} ≥ {int(threshold)}"
                    break
        if reason:
            matches.append((s, reason))
    return matches


def evaluate_and_promote(window_minutes=10, dry_run=False):
    """Main entrypoint. Scans recent alerts, evaluates every enabled rule,
    promotes matches into incidents, and writes a decision audit log.

    dry_run=True returns what *would* be promoted without writing.
    """
    rules = _load_rules()
    if not rules:
        return {"evaluated": 0, "promoted": 0, "skipped": 0, "rules": 0}

    # Use the largest window any rule needs so we scan eve.json once
    longest = max([int(r.get("window_minutes") or 10) for r in rules] + [window_minutes])
    summaries = _scan_window(longest)
    critical_set = _critical_assets()

    promoted_count = 0
    skipped_count = 0
    promoted_seeds = []
    seen_keys = set()  # de-dupe within this run

    for rule in rules:
        for seed, reason in _evaluate_rule(rule, summaries, critical_set):
            key = (seed.get("sid"), seed.get("src_ip"), seed.get("dest_ip"))
            if key in seen_keys:
                skipped_count += 1
                _log_decision(rule, seed, "skipped", "already-handled-this-run")
                continue
            seen_keys.add(key)
            if dry_run:
                promoted_seeds.append({**seed, "_rule": rule["name"], "_reason": reason})
                continue
            try:
                incident_id = _promote(seed)
                if incident_id is None:
                    _log_decision(rule, seed, "skipped",
                                  f"{reason} | fp-suppressed (>={FP_SUPPRESSION_THRESHOLD} prior FPs "
                                  f"in {FP_SUPPRESSION_DAYS}d)")
                    continue
                _log_decision(rule, seed, "promoted", reason, incident_id=incident_id)
                promoted_count += 1
                promoted_seeds.append({**seed, "_rule": rule["name"],
                                       "_reason": reason, "_incident_id": incident_id})
            except Exception as e:
                _log_decision(rule, seed, "failed", f"{reason} | error: {e}")

    return {
        "rules": len(rules),
        "evaluated": len(summaries),
        "promoted": promoted_count,
        "skipped": skipped_count,
        "results": promoted_seeds,
    }


def recent_decisions(minutes=60, limit=50):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM auto_promote_decisions WHERE created_at > datetime('now', '-' || ? || ' minutes') "
        "ORDER BY id DESC LIMIT ?",
        (minutes, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
