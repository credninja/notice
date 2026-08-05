"""
Tor exit-node list management.

Fetches the canonical list from check.torproject.org and stores it in the
SQLite `tor_exits` table. The list is loaded into an in-memory set for
zero-latency `is_tor_exit(ip)` lookups during alert/flow iteration.

Refresh is on a 24h cadence (the list changes daily as new exits join and
old ones rotate out). A background thread in app.py kicks the refresh on
startup and once a day thereafter.
"""

import time
import socket
import urllib.request
from db import get_db

TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
DEFAULT_TTL_SECONDS = 15 * 60  # refresh every 15 minutes

# In-memory cache for fast lookups. Loaded from DB on first use and after refresh.
_tor_set = None
_loaded_at = 0.0


def _load_from_db():
    """Pull the persisted list into the in-memory set."""
    global _tor_set, _loaded_at
    conn = get_db()
    rows = conn.execute("SELECT ip FROM tor_exits").fetchall()
    conn.close()
    _tor_set = {r["ip"] for r in rows}
    _loaded_at = time.time()
    return _tor_set


def is_tor_exit(ip):
    """O(1) check whether `ip` is a known Tor exit node."""
    global _tor_set
    if _tor_set is None:
        _load_from_db()
    return ip in _tor_set


def get_count():
    """Return the size of the loaded Tor exit set."""
    if _tor_set is None:
        _load_from_db()
    return len(_tor_set or set())


def get_last_refresh():
    """Return the most recent refreshed_at timestamp (string), or None if empty."""
    conn = get_db()
    row = conn.execute("SELECT MAX(refreshed_at) AS ts FROM tor_exits").fetchone()
    conn.close()
    return row["ts"] if row and row["ts"] else None


def refresh_tor_exits(timeout=15):
    """Download the official Tor exit list and replace the cached copy.

    Returns dict with `count`, `fetched_at`, and `error` (None on success).
    Network failures are non-fatal — the previous snapshot keeps working.
    """
    try:
        req = urllib.request.Request(
            TOR_LIST_URL,
            headers={"User-Agent": "NOTICE-NSM/1.0 (Tor exit list refresh)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        return {"count": get_count(), "fetched_at": None, "error": f"fetch failed: {e}"}

    ips = [line.strip() for line in body.splitlines() if line.strip() and not line.startswith("#")]
    if not ips:
        return {"count": get_count(), "fetched_at": None, "error": "empty list returned"}

    # Replace atomically — DELETE+INSERT inside one transaction
    conn = get_db()
    try:
        conn.execute("BEGIN")
        conn.execute("DELETE FROM tor_exits")
        conn.executemany("INSERT INTO tor_exits (ip) VALUES (?)", [(ip,) for ip in ips])
        conn.execute("COMMIT")
    except Exception as e:
        conn.execute("ROLLBACK")
        conn.close()
        return {"count": get_count(), "fetched_at": None, "error": f"db error: {e}"}
    conn.close()

    # Reload into memory
    _load_from_db()
    return {"count": len(ips), "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "error": None}


def needs_refresh(ttl_seconds=DEFAULT_TTL_SECONDS):
    """True if the persisted list is older than ttl_seconds (or empty)."""
    last = get_last_refresh()
    if not last:
        return True
    try:
        # SQLite default datetime() format: 'YYYY-MM-DD HH:MM:SS' UTC
        from datetime import datetime
        last_dt = datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
        age = (datetime.now() - last_dt).total_seconds()
        return age >= ttl_seconds
    except Exception:
        return True
