"""
IP Reputation lookup via AbuseIPDB free API.
Caches results in SQLite to avoid hitting rate limits.
"""

import json
import os
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.error import URLError
from db import get_db

# AbuseIPDB free tier: 1000 checks/day
# Set via environment variable: ABUSEIPDB_KEY=<your-key>
API_KEY = os.environ.get("ABUSEIPDB_KEY", "")
API_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_DAYS = 7  # Re-check after 7 days


def lookup_reputation(ip):
    """Check IP reputation. Returns cached data or fetches from AbuseIPDB."""
    # Check cache first
    conn = get_db()
    row = conn.execute("SELECT * FROM ip_reputation WHERE ip = ?", (ip,)).fetchone()
    conn.close()

    if row:
        checked = row["checked_at"]
        if checked:
            try:
                age = datetime.now() - datetime.fromisoformat(checked)
                if age < timedelta(days=CACHE_DAYS):
                    return dict(row)
            except (ValueError, TypeError):
                pass

    # Fetch from API
    if not API_KEY:
        return {"ip": ip, "abuse_score": -1, "error": "ABUSEIPDB_KEY not set"}

    try:
        req = Request(
            f"{API_URL}?ipAddress={ip}&maxAgeInDays=90&verbose",
            headers={
                "Key": API_KEY,
                "Accept": "application/json",
            },
        )
        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())["data"]

        result = {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "is_tor": 1 if data.get("isTor", False) else 0,
            "last_reported": data.get("lastReportedAt", ""),
        }

        # Cache result
        conn = get_db()
        conn.execute("""
            INSERT OR REPLACE INTO ip_reputation
            (ip, abuse_score, total_reports, country_code, isp, domain, is_tor, last_reported, checked_at)
            VALUES (?,?,?,?,?,?,?,?,datetime('now','localtime'))
        """, (result["ip"], result["abuse_score"], result["total_reports"],
              result["country_code"], result["isp"], result["domain"],
              result["is_tor"], result["last_reported"]))
        conn.commit()
        conn.close()
        return result

    except (URLError, Exception) as e:
        return {"ip": ip, "abuse_score": -1, "error": str(e)}


def lookup_batch_reputation(ips, max_ips=20):
    """Look up reputation for multiple IPs. Returns dict of ip -> result."""
    results = {}
    checked = 0
    for ip in ips:
        if checked >= max_ips:
            break
        results[ip] = lookup_reputation(ip)
        if results[ip].get("abuse_score", -1) >= 0:
            checked += 1
    return results


def get_cached_reputation(ip):
    """Get cached reputation only (no API call)."""
    conn = get_db()
    row = conn.execute("SELECT * FROM ip_reputation WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    return dict(row) if row else None


_BENIGN_DOMAINS = frozenset([
    "microsoft.com", "google.com", "googleapis.com", "gstatic.com",
    "apple.com", "icloud.com", "akamai.com", "akamaiedge.net",
    "cloudflare.com", "cloudfront.net", "amazonaws.com", "amazon.com", "azure.com",
    "office.com", "live.com", "outlook.com", "skype.com", "msedge.net",
    "windows.com", "windowsupdate.com", "microsoft.net", "msn.com",
    "github.com", "github.io", "githubusercontent.com",
    "facebook.com", "fbcdn.net", "whatsapp.com", "whatsapp.net",
    "youtube.com", "googlevideo.com", "ytimg.com",
    "linkedin.com", "licdn.com", "twitter.com", "x.com",
    "ubuntu.com", "canonical.com", "debian.org",
    "docker.com", "docker.io", "fastly.net", "telegram.org",
    "newrelic.com", "automattic.com", "wordpress.com",
    "archive.org", "bit.ly",
])


def get_all_cached():
    """Get all cached reputation data, filtering out known benign providers."""
    conn = get_db()
    rows = conn.execute(
        "SELECT ip, abuse_score, total_reports, country_code, isp, domain, "
        "is_tor, last_reported, checked_at, vt_score, vt_malicious, "
        "vt_suspicious, vt_total_engines, classification "
        "FROM ip_reputation WHERE abuse_score > 0 ORDER BY abuse_score DESC"
    ).fetchall()
    geo_rows = conn.execute("SELECT ip, isp, org FROM geo_cache").fetchall()
    conn.close()

    geo_map = {r["ip"]: (r["isp"] or r["org"] or "").lower() for r in geo_rows}
    benign_isps = ["microsoft", "google", "amazon", "apple", "cloudflare",
                   "akamai", "fastly", "canonical", "github", "facebook",
                   "meta platforms", "telegram", "linkedin"]

    results = []
    for r in rows:
        d = dict(r)
        domain = d.get("domain", "") or ""
        if domain and any(domain.endswith(b) for b in _BENIGN_DOMAINS):
            continue
        isp = geo_map.get(d["ip"], "")
        if isp and any(b in isp for b in benign_isps):
            continue
        results.append(d)
    return results
