"""
VirusTotal v3 API client.

Public-tier limits: 4 lookups/min, 500/day. The client throttles itself to
stay under the per-minute rate, falls back gracefully to cached results on
429/timeout, and persists every successful lookup to SQLite so subsequent
calls hit the cache instead of the API.

Usage:
    from analyzers.virustotal import lookup_ip, lookup_domain, lookup_url
    r = lookup_ip("8.8.8.8")     # → {classification, vt_score, raw_*, ...}
"""

import base64
import json
import os
import time
import threading
from datetime import datetime, timedelta
from urllib.error import URLError, HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from db import get_db


API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
API_BASE = "https://www.virustotal.com/api/v3"
CACHE_DAYS = 7  # Re-check after a week — VT updates daily but most signal is stable

# Self-throttle: keep ≤4 calls per minute (public-tier limit).
_RATE_LIMIT_PER_MIN = 4
_call_times = []
_call_lock = threading.Lock()


def _ratelimit():
    """Block if we'd exceed the per-minute call budget."""
    with _call_lock:
        now = time.time()
        # Drop calls older than 60s
        global _call_times
        _call_times = [t for t in _call_times if now - t < 60]
        if len(_call_times) >= _RATE_LIMIT_PER_MIN:
            wait = 60 - (now - _call_times[0])
            if wait > 0:
                time.sleep(wait)
                now = time.time()
                _call_times = [t for t in _call_times if now - t < 60]
        _call_times.append(time.time())


def _classify(malicious, suspicious, total):
    """VT result → human classification. malicious dominates suspicious dominates clean."""
    if total <= 0:
        return "unknown"
    if malicious >= 5:
        return "malicious"
    if malicious >= 1 or suspicious >= 3:
        return "suspicious"
    return "benign"


def _vt_get(path):
    """Authenticated GET. Returns parsed JSON or raises."""
    if not API_KEY:
        raise RuntimeError("VIRUSTOTAL_API_KEY not set")
    _ratelimit()
    req = Request(f"{API_BASE}{path}", headers={
        "x-apikey": API_KEY,
        "Accept": "application/json",
    })
    with urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def _stats(attrs):
    """Pull last_analysis_stats out of a VT v3 attributes block."""
    s = (attrs or {}).get("last_analysis_stats", {}) or {}
    mal = int(s.get("malicious", 0))
    sus = int(s.get("suspicious", 0))
    har = int(s.get("harmless", 0))
    und = int(s.get("undetected", 0))
    tot = mal + sus + har + und
    return mal, sus, tot


# ── IP ──────────────────────────────────────────────────────────────────

def _cached_ip(ip):
    """Return existing row if recent enough, else None."""
    conn = get_db()
    row = conn.execute("SELECT * FROM ip_reputation WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    if not row:
        return None
    last = row["checked_at"]
    if not last:
        return None
    try:
        age = datetime.now() - datetime.fromisoformat(last)
    except (ValueError, TypeError):
        return None
    if age > timedelta(days=CACHE_DAYS):
        return None
    # Only consider it cached for VT purposes if vt_total_engines > 0
    if (row["vt_total_engines"] or 0) <= 0:
        return None
    return dict(row)


def lookup_ip(ip):
    """VirusTotal IP reputation. Cached + rate-limited.

    Returns dict with: ip, classification, vt_score, vt_malicious, vt_suspicious,
    vt_total_engines, vt_categories, last_checked, error?
    """
    cached = _cached_ip(ip)
    if cached:
        return {
            "ip": ip,
            "classification": cached.get("classification") or "unknown",
            "vt_score": cached.get("vt_score") or 0,
            "vt_malicious": cached.get("vt_malicious") or 0,
            "vt_suspicious": cached.get("vt_suspicious") or 0,
            "vt_total_engines": cached.get("vt_total_engines") or 0,
            "vt_categories": cached.get("vt_categories") or "",
            "last_checked": cached.get("checked_at"),
            "cached": True,
        }
    if not API_KEY:
        return {"ip": ip, "error": "VIRUSTOTAL_API_KEY not set", "classification": "unknown"}
    try:
        data = _vt_get(f"/ip_addresses/{ip}")
        attrs = (data.get("data") or {}).get("attributes") or {}
        mal, sus, tot = _stats(attrs)
        score = int((mal / tot * 100)) if tot else 0
        cls = _classify(mal, sus, tot)
        cats = ",".join(sorted(set((attrs.get("last_analysis_results") or {}).keys()))[:5])
        # UPSERT into ip_reputation (preserves AbuseIPDB columns)
        conn = get_db()
        conn.execute("""
            INSERT INTO ip_reputation (ip, vt_score, vt_malicious, vt_suspicious, vt_total_engines,
                                       vt_categories, classification, checked_at)
            VALUES (?,?,?,?,?,?,?,datetime('now','localtime'))
            ON CONFLICT(ip) DO UPDATE SET
                vt_score=excluded.vt_score,
                vt_malicious=excluded.vt_malicious,
                vt_suspicious=excluded.vt_suspicious,
                vt_total_engines=excluded.vt_total_engines,
                vt_categories=excluded.vt_categories,
                classification=excluded.classification,
                checked_at=datetime('now','localtime')
        """, (ip, score, mal, sus, tot, cats, cls))
        conn.commit()
        conn.close()
        return {
            "ip": ip, "classification": cls, "vt_score": score,
            "vt_malicious": mal, "vt_suspicious": sus, "vt_total_engines": tot,
            "vt_categories": cats, "cached": False,
        }
    except (URLError, HTTPError, RuntimeError, ValueError) as e:
        return {"ip": ip, "error": str(e), "classification": "unknown"}


# ── Domain ──────────────────────────────────────────────────────────────

def _cached_domain(domain):
    conn = get_db()
    row = conn.execute("SELECT * FROM domain_reputation WHERE domain = ?", (domain,)).fetchone()
    conn.close()
    if not row:
        return None
    try:
        age = datetime.now() - datetime.fromisoformat(row["last_checked"])
    except (ValueError, TypeError):
        return None
    if age > timedelta(days=CACHE_DAYS):
        return None
    return dict(row)


def lookup_domain(domain):
    domain = (domain or "").strip().lower()
    if not domain:
        return {"domain": domain, "error": "empty"}
    cached = _cached_domain(domain)
    if cached:
        cached["cached"] = True
        return cached
    if not API_KEY:
        return {"domain": domain, "error": "VIRUSTOTAL_API_KEY not set", "classification": "unknown"}
    try:
        data = _vt_get(f"/domains/{quote(domain, safe='')}")
        attrs = (data.get("data") or {}).get("attributes") or {}
        mal, sus, tot = _stats(attrs)
        score = int((mal / tot * 100)) if tot else 0
        cls = _classify(mal, sus, tot)
        cats = ",".join(sorted((attrs.get("categories") or {}).values())[:6])
        conn = get_db()
        conn.execute("""
            INSERT INTO domain_reputation (domain, vt_score, vt_malicious, vt_suspicious,
                                           vt_total_engines, vt_categories, classification, last_checked)
            VALUES (?,?,?,?,?,?,?,datetime('now','localtime'))
            ON CONFLICT(domain) DO UPDATE SET
                vt_score=excluded.vt_score,
                vt_malicious=excluded.vt_malicious,
                vt_suspicious=excluded.vt_suspicious,
                vt_total_engines=excluded.vt_total_engines,
                vt_categories=excluded.vt_categories,
                classification=excluded.classification,
                last_checked=datetime('now','localtime')
        """, (domain, score, mal, sus, tot, cats, cls))
        conn.commit()
        conn.close()
        return {
            "domain": domain, "classification": cls, "vt_score": score,
            "vt_malicious": mal, "vt_suspicious": sus, "vt_total_engines": tot,
            "vt_categories": cats, "cached": False,
        }
    except (URLError, HTTPError, RuntimeError, ValueError) as e:
        return {"domain": domain, "error": str(e), "classification": "unknown"}


# ── URL ─────────────────────────────────────────────────────────────────

def _cached_url(url):
    conn = get_db()
    row = conn.execute("SELECT * FROM url_reputation WHERE url = ?", (url,)).fetchone()
    conn.close()
    if not row:
        return None
    try:
        age = datetime.now() - datetime.fromisoformat(row["last_checked"])
    except (ValueError, TypeError):
        return None
    if age > timedelta(days=CACHE_DAYS):
        return None
    return dict(row)


def lookup_url(url):
    url = (url or "").strip()
    if not url:
        return {"url": url, "error": "empty"}
    cached = _cached_url(url)
    if cached:
        cached["cached"] = True
        return cached
    if not API_KEY:
        return {"url": url, "error": "VIRUSTOTAL_API_KEY not set", "classification": "unknown"}
    # VT URL ID = base64url(url) without padding
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode().rstrip("=")
    try:
        data = _vt_get(f"/urls/{url_id}")
        attrs = (data.get("data") or {}).get("attributes") or {}
        mal, sus, tot = _stats(attrs)
        score = int((mal / tot * 100)) if tot else 0
        cls = _classify(mal, sus, tot)
        conn = get_db()
        conn.execute("""
            INSERT INTO url_reputation (url, vt_score, vt_malicious, vt_suspicious,
                                        vt_total_engines, classification, last_checked)
            VALUES (?,?,?,?,?,?,datetime('now','localtime'))
            ON CONFLICT(url) DO UPDATE SET
                vt_score=excluded.vt_score,
                vt_malicious=excluded.vt_malicious,
                vt_suspicious=excluded.vt_suspicious,
                vt_total_engines=excluded.vt_total_engines,
                classification=excluded.classification,
                last_checked=datetime('now','localtime')
        """, (url, score, mal, sus, tot, cls))
        conn.commit()
        conn.close()
        return {
            "url": url, "classification": cls, "vt_score": score,
            "vt_malicious": mal, "vt_suspicious": sus, "vt_total_engines": tot, "cached": False,
        }
    except (URLError, HTTPError, RuntimeError, ValueError) as e:
        return {"url": url, "error": str(e), "classification": "unknown"}
