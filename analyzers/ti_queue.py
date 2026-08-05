"""
Threat-intelligence enrichment queue.

Every alert NIDS fires gets its indicators (external IPs, DNS query name,
HTTP hostname/URL, TLS SNI) pushed onto `ti_lookup_queue`. A daemon worker
drains the queue continuously, calling VirusTotal + AbuseIPDB through the
existing rate-limited clients (analyzers/virustotal.py + reputation.py)
and writing results to the local reputation tables.

This is the only place in NOTICE that automatically performs TI lookups —
the alert-log chips, knowledge-graph node colors, and auto-promote
ti_malicious rule all read from the cache that this worker populates.

Design rules:
  - Cache TTL is 7 days; the queue's UNIQUE constraint + a freshness check
    skip indicators that are already current.
  - Worker sleeps short (1s) when queue is empty, so freshly-queued
    indicators get picked up almost immediately.
  - Each indicator type has its own daily-soft-cap so one chatty source
    can't burn the whole VT quota.
  - Workers swallow exceptions and mark the row 'failed' rather than
    crashing the thread.
"""

import os
import time
import threading
from datetime import datetime, timedelta

from db import get_db
from eve_reader import is_internal, is_ipv4


# ── Config ──────────────────────────────────────────────────────────────

# How fresh does the cache need to be for us to skip a re-queue?
FRESH_DAYS = 7

# Soft daily caps — prevents one noisy alert source from burning the API
# quota; new indicators beyond the cap just stay 'pending' until tomorrow.
DAILY_CAP_IP = 400      # well under VT's 500/day public-tier
DAILY_CAP_DOMAIN = 80
DAILY_CAP_URL = 20

# Worker poll interval when queue empty
IDLE_SLEEP_SECONDS = 1.0
# Inter-task delay when queue has work — keeps us under VT's 4/min
WORK_DELAY_SECONDS = 16.0


# ── Indicator extraction ────────────────────────────────────────────────

def _extract_indicators(ev):
    """Pull every TI-relevant indicator out of one eve.json event.

    Returns a list of (type, value) tuples, deduped within the call.
    Internal IPs are skipped (they're assets, not IOCs).
    """
    out = []
    seen = set()

    def _add(t, v):
        if not v:
            return
        v = str(v).strip().lower() if t in ("domain", "url") else str(v).strip()
        if not v or (t, v) in seen:
            return
        seen.add((t, v))
        out.append((t, v))

    # IPs from src/dst (external only)
    for ip in (ev.get("src_ip"), ev.get("dest_ip")):
        if ip and is_ipv4(ip) and not is_internal(ip):
            _add("ip", ip)

    # DNS rrname (the looked-up domain) — alerts often fire on DNS, this
    # is the "actual indicator" for malware C2 / phishing detections.
    dns = ev.get("dns") or {}
    for k in ("rrname", "query"):
        if dns.get(k):
            _add("domain", dns[k])

    # HTTP hostname (host header) + URL
    http = ev.get("http") or {}
    if http.get("hostname"):
        _add("domain", http["hostname"])
    if http.get("url"):
        url = http["url"]
        if not url.startswith(("http://", "https://")):
            host = http.get("hostname") or ""
            url = ("https://" if (ev.get("dest_port") == 443) else "http://") + host + url
        _add("url", url)

    # TLS SNI
    tls = ev.get("tls") or {}
    if tls.get("sni"):
        _add("domain", tls["sni"])

    # Some alert payloads include hostname or extracted_url in metadata —
    # check the alert dict too
    a = ev.get("alert") or {}
    md = a.get("metadata") or {}
    for v in (md.get("former_category") or []):
        # Don't try to resolve category strings as domains
        pass
    for k in ("hostname", "domain"):
        if a.get(k):
            _add("domain", a[k])

    return out


# ── Queue ops ───────────────────────────────────────────────────────────

def _is_fresh_in_cache(t, value):
    """Return True if we already have a recent (within FRESH_DAYS) lookup."""
    conn = get_db()
    try:
        cutoff = (datetime.now() - timedelta(days=FRESH_DAYS)).isoformat(sep=" ", timespec="seconds")
        if t == "ip":
            row = conn.execute(
                "SELECT 1 FROM ip_reputation WHERE ip=? AND vt_total_engines>0 AND checked_at>?",
                (value, cutoff),
            ).fetchone()
        elif t == "domain":
            row = conn.execute(
                "SELECT 1 FROM domain_reputation WHERE domain=? AND last_checked>?",
                (value, cutoff),
            ).fetchone()
        elif t == "url":
            row = conn.execute(
                "SELECT 1 FROM url_reputation WHERE url=? AND last_checked>?",
                (value, cutoff),
            ).fetchone()
        else:
            row = None
        return row is not None
    finally:
        conn.close()


def enqueue(indicator_type, value, priority=5, source="alert"):
    """Add a single indicator to the queue. No-op if already fresh in cache.
    UNIQUE constraint on (type,value) means a re-enqueue is a cheap upsert
    that just bumps priority if the new request is more urgent."""
    if not value:
        return False
    if _is_fresh_in_cache(indicator_type, value):
        return False
    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO ti_lookup_queue (indicator_type, indicator_value, priority, source)
               VALUES (?,?,?,?)
               ON CONFLICT(indicator_type, indicator_value) DO UPDATE SET
                 priority = MIN(priority, excluded.priority),
                 status   = CASE WHEN status='failed' THEN 'pending' ELSE status END""",
            (indicator_type, value, int(priority), source),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def enrich_event(ev, source="alert"):
    """Convenience: extract every indicator from one alert and enqueue them.
    Returns the count of newly-enqueued indicators."""
    n = 0
    for t, v in _extract_indicators(ev):
        if enqueue(t, v, priority=3 if t == "ip" else 5, source=source):
            n += 1
    return n


def queue_status():
    conn = get_db()
    try:
        pending = conn.execute("SELECT COUNT(*) FROM ti_lookup_queue WHERE status='pending'").fetchone()[0]
        done_today = conn.execute(
            "SELECT COUNT(*) FROM ti_lookup_queue WHERE status='done' AND last_attempt_at > date('now','-1 day')"
        ).fetchone()[0]
        failed_today = conn.execute(
            "SELECT COUNT(*) FROM ti_lookup_queue WHERE status='failed' AND last_attempt_at > date('now','-1 day')"
        ).fetchone()[0]
        oldest_pending = conn.execute(
            "SELECT MIN(queued_at) FROM ti_lookup_queue WHERE status='pending'"
        ).fetchone()[0]
        by_type = {
            r["indicator_type"]: r["c"] for r in conn.execute(
                "SELECT indicator_type, COUNT(*) AS c FROM ti_lookup_queue WHERE status='pending' GROUP BY indicator_type"
            ).fetchall()
        }
    finally:
        conn.close()
    return {
        "pending": pending,
        "done_today": done_today,
        "failed_today": failed_today,
        "oldest_pending_at": oldest_pending,
        "by_type": by_type,
    }


def _count_done_today(t):
    conn = get_db()
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM ti_lookup_queue WHERE indicator_type=? AND status='done' "
            "AND last_attempt_at > date('now')",
            (t,),
        ).fetchone()[0]
    finally:
        conn.close()


def _next_pending(skip_types=None):
    """Pull the highest-priority pending row whose type is not in skip_types.
    Returns dict or None."""
    conn = get_db()
    try:
        skip_types = skip_types or set()
        if skip_types:
            placeholders = ",".join("?" for _ in skip_types)
            row = conn.execute(
                f"SELECT * FROM ti_lookup_queue WHERE status='pending' "
                f"AND indicator_type NOT IN ({placeholders}) "
                f"ORDER BY priority ASC, queued_at ASC LIMIT 1",
                tuple(skip_types),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM ti_lookup_queue WHERE status='pending' "
                "ORDER BY priority ASC, queued_at ASC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _mark_done(row_id, error=None):
    conn = get_db()
    try:
        if error:
            conn.execute(
                "UPDATE ti_lookup_queue SET status='failed', last_attempt_at=datetime('now','localtime'), "
                "attempts=attempts+1, last_error=? WHERE id=?",
                (str(error)[:200], row_id),
            )
        else:
            conn.execute(
                "UPDATE ti_lookup_queue SET status='done', last_attempt_at=datetime('now','localtime'), "
                "attempts=attempts+1, last_error='' WHERE id=?",
                (row_id,),
            )
        conn.commit()
    finally:
        conn.close()


# ── Worker ──────────────────────────────────────────────────────────────

def _process_one(row):
    """Look up one indicator. The lookup_* helpers handle their own caching
    + rate-limiting; we just call them and persist the queue row's status."""
    t = row["indicator_type"]
    v = row["indicator_value"]
    try:
        if t == "ip":
            # score_ip composes VT + AbuseIPDB + Tor in one call, writes both
            # caches as a side-effect.
            from analyzers.ti_score import score_ip
            r = score_ip(v)
            if r.get("vt", {}).get("error") and r.get("abuse", {}).get("error"):
                _mark_done(row["id"], error=str(r["vt"]["error"])[:120])
                return
        elif t == "domain":
            from analyzers.virustotal import lookup_domain
            r = lookup_domain(v)
            if r.get("error"):
                _mark_done(row["id"], error=r["error"])
                return
        elif t == "url":
            from analyzers.virustotal import lookup_url
            r = lookup_url(v)
            if r.get("error"):
                _mark_done(row["id"], error=r["error"])
                return
        else:
            _mark_done(row["id"], error=f"unknown type '{t}'")
            return
        _mark_done(row["id"])
    except Exception as e:
        _mark_done(row["id"], error=str(e)[:120])


def _worker_loop():
    """Daemon thread body. Pops one indicator at a time, respects per-type
    daily caps + the inter-call delay so we stay under provider rate limits.
    """
    while True:
        try:
            # Skip types that have hit their daily soft-cap
            skip = set()
            if _count_done_today("ip") >= DAILY_CAP_IP:
                skip.add("ip")
            if _count_done_today("domain") >= DAILY_CAP_DOMAIN:
                skip.add("domain")
            if _count_done_today("url") >= DAILY_CAP_URL:
                skip.add("url")

            row = _next_pending(skip_types=skip)
            if not row:
                time.sleep(IDLE_SLEEP_SECONDS)
                continue
            _process_one(row)
            time.sleep(WORK_DELAY_SECONDS)
        except Exception:
            # Never let the worker die; sleep a bit and continue.
            time.sleep(5)


_worker_thread = None


def start_worker():
    """Start the daemon. Idempotent."""
    global _worker_thread
    if _worker_thread and _worker_thread.is_alive():
        return _worker_thread
    _worker_thread = threading.Thread(target=_worker_loop, daemon=True, name="ti-queue-worker")
    _worker_thread.start()
    return _worker_thread


# ── Catch-up sweeper (called by the auto-promote loop) ──────────────────

def bulk_enrich_recent_alerts(minutes=30, max_events=500):
    """Walk the last N minutes of eve.json alerts and enqueue every
    indicator we find. Used to catch up after a restart, since the SSE
    stream only catches alerts that arrive AFTER it connected."""
    from eve_reader import iter_events
    n_seen = 0
    n_queued = 0
    for ev in iter_events(event_types={"alert"}, minutes=minutes):
        n_seen += 1
        n_queued += enrich_event(ev, source="sweeper")
        if n_seen >= max_events:
            break
    return {"events_scanned": n_seen, "indicators_queued": n_queued}
