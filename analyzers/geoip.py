"""
GeoIP resolution with SQLite caching.

Resolution order:
  1. SQLite geo_cache (fast, persistent)
  2. GeoLite2 offline DBs in geolite2/ (microseconds, no rate limit)
  3. ip-api.com HTTP batch fallback (slow, rate-limited; only if 1+2 miss)

The offline DBs are populated by dropping the MaxMind GeoLite2 mmdb files
into `geolite2/` — see geolite2/README.md for download instructions.
"""

import json
import urllib.request
import urllib.error
from db import get_db
from eve_reader import is_internal
from analyzers import geoip_offline


def lookup_batch(ip_list):
    """
    Resolve GeoIP for a list of external IPs.
    Checks cache first; for misses, tries the offline GeoLite2 DBs;
    only falls back to ip-api.com HTTP for IPs the offline DBs can't resolve.
    Returns dict: {ip: {country, country_code, city, isp, org}}
    """
    if not ip_list:
        return {}

    external = [ip for ip in set(ip_list) if not is_internal(ip)]
    if not external:
        return {}

    conn = get_db()
    results = {}
    misses = []

    # Layer 1 — SQLite cache
    for ip in external:
        row = conn.execute("SELECT country, country_code, city, isp, org FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
        if row:
            results[ip] = dict(row)
        else:
            misses.append(ip)
    conn.close()

    if not misses:
        return results

    # Layer 2 — offline GeoLite2 (preferred for cache misses)
    if geoip_offline.is_available():
        offline_resolved = {}
        for ip in misses:
            geo = geoip_offline.lookup(ip)
            if geo:
                offline_resolved[ip] = geo
        if offline_resolved:
            results.update(offline_resolved)
            conn = get_db()
            for ip, geo in offline_resolved.items():
                conn.execute(
                    "INSERT OR REPLACE INTO geo_cache (ip, country, country_code, city, isp, org) VALUES (?,?,?,?,?,?)",
                    (ip, geo.get("country", ""), geo.get("country_code", ""),
                     geo.get("city", ""), geo.get("isp", ""), geo.get("org", "")),
                )
            conn.commit()
            conn.close()
            misses = [ip for ip in misses if ip not in offline_resolved]

    # Layer 3 — ip-api.com HTTP fallback (still works if offline DBs aren't loaded)
    if misses:
        for i in range(0, len(misses), 100):
            batch = misses[i:i + 100]
            resolved = _batch_api_call(batch)
            if resolved:
                conn = get_db()
                for ip, geo in resolved.items():
                    results[ip] = geo
                    conn.execute(
                        "INSERT OR REPLACE INTO geo_cache (ip, country, country_code, city, isp, org) VALUES (?,?,?,?,?,?)",
                        (ip, geo.get("country", ""), geo.get("country_code", ""),
                         geo.get("city", ""), geo.get("isp", ""), geo.get("org", "")),
                    )
                conn.commit()
                conn.close()

    return results


def get_cached(ip):
    """SQLite-only lookup, no HTTP. Returns dict or None."""
    conn = get_db()
    row = conn.execute("SELECT country, country_code, city, isp, org FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    return dict(row) if row else None


def lookup_single(ip):
    """Lookup a single IP, with cache → offline → HTTP fallback."""
    cached = get_cached(ip)
    if cached:
        return cached
    if geoip_offline.is_available():
        geo = geoip_offline.lookup(ip)
        if geo:
            conn = get_db()
            conn.execute(
                "INSERT OR REPLACE INTO geo_cache (ip, country, country_code, city, isp, org) VALUES (?,?,?,?,?,?)",
                (ip, geo.get("country", ""), geo.get("country_code", ""),
                 geo.get("city", ""), geo.get("isp", ""), geo.get("org", "")),
            )
            conn.commit()
            conn.close()
            return geo
    result = _batch_api_call([ip])
    return result.get(ip, {"country": "Unknown", "country_code": "??", "city": "", "isp": "", "org": ""})


def _batch_api_call(ip_list):
    """Call ip-api.com batch endpoint. Returns {ip: geo_dict}."""
    results = {}
    try:
        payload = json.dumps(ip_list).encode("utf-8")
        req = urllib.request.Request(
            "http://ip-api.com/batch?fields=query,status,country,countryCode,city,isp,org",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for entry in data:
                if entry.get("status") == "success":
                    ip = entry["query"]
                    results[ip] = {
                        "country": entry.get("country", ""),
                        "country_code": entry.get("countryCode", ""),
                        "city": entry.get("city", ""),
                        "isp": entry.get("isp", ""),
                        "org": entry.get("org", ""),
                    }
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        # Network error — return empty, caller handles gracefully
        pass
    return results
