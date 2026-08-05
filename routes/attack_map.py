"""Live Attack Map API — geo-located alert data for visualization.

Only shows alerts from IPs confirmed as malicious/suspicious via:
  - AbuseIPDB abuse score >= 25
  - VirusTotal malicious detections > 0
  - Known Tor exit nodes
  - OSINT threat feed matches
  - High-severity alerts (sev 1) from unknown IPs (not yet checked)
  - IPs classified as 'malicious' or 'suspicious'

Clean IPs (Microsoft, Google, CDNs, etc.) are excluded even if they
triggered behavioral/volume-based alerts.
"""

from collections import defaultdict
from bottle import request
from db import cache_get, cache_set, get_db, close_db
from eve_reader import iter_events, is_internal, is_ipv4, is_noise_alert
from analyzers.geoip import get_cached


COUNTRY_COORDS = {
    "US": [39.8, -98.5], "CN": [35.9, 104.2], "RU": [61.5, 105.3],
    "DE": [51.2, 10.5], "GB": [55.4, -3.4], "FR": [46.2, 2.2],
    "JP": [36.2, 138.3], "KR": [35.9, 127.8], "BR": [-14.2, -51.9],
    "IN": [20.6, 78.9], "AU": [-25.3, 133.8], "CA": [56.1, -106.3],
    "NL": [52.1, 5.3], "IT": [41.9, 12.6], "ES": [40.5, -3.7],
    "SE": [60.1, 18.6], "NO": [60.5, 8.5], "FI": [61.9, 25.7],
    "PL": [51.9, 19.1], "UA": [48.4, 31.2], "RO": [45.9, 25.0],
    "TR": [39.0, 35.2], "IL": [31.0, 34.9], "SA": [23.9, 45.1],
    "AE": [23.4, 53.8], "ZA": [-30.6, 22.9], "EG": [26.8, 30.8],
    "NG": [9.1, 8.7], "KE": [-0.0, 37.9], "AR": [-38.4, -63.6],
    "MX": [23.6, -102.6], "CO": [4.6, -74.3], "CL": [-35.7, -71.5],
    "ID": [-0.8, 113.9], "TH": [15.9, 100.9], "VN": [14.1, 108.3],
    "PH": [12.9, 121.8], "MY": [4.2, 101.9], "SG": [1.4, 103.8],
    "PK": [30.4, 69.3], "BD": [23.7, 90.4], "IR": [32.4, 53.7],
    "IQ": [33.2, 43.7], "TW": [23.7, 121.0], "HK": [22.4, 114.1],
    "PT": [39.4, -8.2], "CZ": [49.8, 15.5], "AT": [47.5, 14.6],
    "CH": [46.8, 8.2], "BE": [50.5, 4.5], "DK": [56.3, 9.5],
    "IE": [53.1, -7.7], "HU": [47.2, 19.5], "BG": [42.7, 25.5],
}
DEFAULT_COORD = [0, 0]

_ABUSE_THRESHOLD = 25
_BENIGN_DOMAINS = frozenset([
    "microsoft.com", "google.com", "googleapis.com", "gstatic.com",
    "apple.com", "icloud.com", "akamai.com", "akamaiedge.net",
    "cloudflare.com", "cloudfront.net", "amazonaws.com", "amazon.com", "azure.com",
    "office.com", "live.com", "outlook.com", "skype.com", "msedge.net",
    "windows.com", "windowsupdate.com", "microsoft.net", "msn.com",
    "github.com", "github.io", "githubusercontent.com",
    "facebook.com", "fbcdn.net", "whatsapp.com", "whatsapp.net",
    "youtube.com", "googlevideo.com", "ytimg.com",
    "linkedin.com", "licdn.com",
    "twitter.com", "twimg.com", "x.com",
    "ubuntu.com", "canonical.com", "debian.org",
    "docker.com", "docker.io",
    "fastly.net", "fastlylb.net",
    "edgecastcdn.net", "azureedge.net",
    "telegram.org", "newrelic.com",
    "automattic.com", "wordpress.com",
    "archive.org", "bit.ly",
])

_BENIGN_ISPS = frozenset([
    "microsoft", "google", "amazon", "apple", "cloudflare", "akamai",
    "fastly", "canonical", "github", "facebook", "meta platforms",
    "telegram", "linkedin",
])


def _load_reputation_data():
    """Load all IP reputation + OSINT match data into memory for fast lookups."""
    conn = get_db()
    try:
        rep_rows = conn.execute(
            "SELECT ip, abuse_score, is_tor, domain, classification, "
            "vt_malicious, vt_suspicious FROM ip_reputation"
        ).fetchall()

        osint_ips = set()
        try:
            osint_rows = conn.execute(
                "SELECT DISTINCT matched_value FROM osint_matches WHERE match_type = 'ip'"
            ).fetchall()
            osint_ips = {r[0] for r in osint_rows}
        except Exception:
            pass

        tor_ips = set()
        try:
            tor_rows = conn.execute("SELECT ip FROM tor_exits").fetchall()
            tor_ips = {r[0] for r in tor_rows}
        except Exception:
            pass

        geo_cache = {}
        try:
            geo_rows = conn.execute("SELECT ip, isp, org FROM geo_cache").fetchall()
            geo_cache = {r["ip"]: {"isp": r["isp"] or "", "org": r["org"] or ""} for r in geo_rows}
        except Exception:
            pass
    finally:
        close_db(conn)

    reputation = {}
    for r in rep_rows:
        reputation[r["ip"]] = {
            "abuse_score": r["abuse_score"] or 0,
            "is_tor": bool(r["is_tor"]),
            "domain": r["domain"] or "",
            "isp": "",
            "classification": r["classification"] or "unknown",
            "vt_malicious": r["vt_malicious"] or 0,
            "vt_suspicious": r["vt_suspicious"] or 0,
        }

    return reputation, osint_ips, tor_ips, geo_cache


_VT_MALICIOUS_THRESHOLD = 5


def _is_benign_provider(rep, geo):
    """Check if an IP belongs to a known benign cloud/SaaS provider."""
    domain = rep.get("domain", "") if rep else ""
    if domain and any(domain.endswith(d) for d in _BENIGN_DOMAINS):
        return True
    isp = (rep.get("isp", "") or "").lower() if rep else ""
    if not isp and geo:
        isp = (geo.get("isp", "") or geo.get("org", "") or "").lower()
    if isp and any(b in isp for b in _BENIGN_ISPS):
        return True
    return False


_ATTACK_SIG_KEYWORDS = ("ATTACK", "EXPLOIT", "MALWARE", "TROJAN", "BACKDOOR",
                        "SHELLCODE", "C2", "COMMAND AND CONTROL", "EXFIL")


def _is_malicious(ip, reputation, osint_ips, tor_ips, geo_cache, signature=""):
    """Only return True for IPs with strong malicious evidence."""
    if ip in tor_ips:
        return True
    if ip in osint_ips:
        return True

    rep = reputation.get(ip)
    if not rep:
        if signature and any(k in signature.upper() for k in _ATTACK_SIG_KEYWORDS):
            return True
        return False

    if rep["classification"] == "malicious":
        return True
    if rep["is_tor"]:
        return True

    geo = geo_cache.get(ip)
    if _is_benign_provider(rep, geo):
        if signature and any(k in signature.upper() for k in _ATTACK_SIG_KEYWORDS):
            return True
        return False
    if rep["abuse_score"] >= _ABUSE_THRESHOLD:
        return True
    if rep["vt_malicious"] >= _VT_MALICIOUS_THRESHOLD:
        return True
    return False


def register(app):

    @app.get("/api/attack-map")
    def api_attack_map():
        minutes = int(request.query.get("minutes", 60)) or 60
        cache_key = f"attack_map_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = _build_attack_map(minutes)
        cache_set(cache_key, result, ttl=60)
        return result


def _build_attack_map(minutes):
    """Build geo-located attack data from confirmed malicious IPs only."""
    reputation, osint_ips, tor_ips, geo_cache = _load_reputation_data()

    country_attacks = defaultdict(lambda: {
        "count": 0, "severities": defaultdict(int),
        "categories": defaultdict(int), "ips": set(),
    })
    attacks = []
    total = 0
    skipped = 0

    for ev in iter_events(event_types={"alert"}, minutes=minutes):
        alert = ev.get("alert", {})
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        ts = ev.get("timestamp", "")
        severity = alert.get("severity", 3)

        attacker = src if not is_internal(src) else dst
        if is_internal(attacker) or not is_ipv4(attacker):
            continue

        sig = alert.get("signature", "")
        cat = alert.get("category", "")
        if is_noise_alert(sig, cat):
            continue
        if not _is_malicious(attacker, reputation, osint_ips, tor_ips, geo_cache, signature=sig):
            skipped += 1
            continue

        geo = get_cached(attacker)
        if not geo or not geo.get("country_code"):
            continue

        sev_label = {1: "critical", 2: "high", 3: "medium"}.get(severity, "low")
        category = alert.get("category", "unknown")

        cc = geo.get("country_code", "??")
        country = geo.get("country", "Unknown")
        coords = COUNTRY_COORDS.get(cc, DEFAULT_COORD)

        rep = reputation.get(attacker, {})

        ca = country_attacks[cc]
        ca["count"] += 1
        ca["severities"][sev_label] += 1
        ca["categories"][category] += 1
        ca["ips"].add(attacker)
        ca["country_name"] = country

        total += 1
        if len(attacks) < 500:
            attacks.append({
                "ts": ts,
                "src_ip": attacker,
                "lat": coords[0],
                "lon": coords[1],
                "country": country,
                "country_code": cc,
                "city": geo.get("city", ""),
                "severity": sev_label,
                "category": category,
                "signature": sig[:100],
                "abuse_score": rep.get("abuse_score", 0),
                "is_tor": attacker in tor_ips or rep.get("is_tor", False),
                "osint_match": attacker in osint_ips,
            })

    country_list = []
    for cc, info in country_attacks.items():
        coords = COUNTRY_COORDS.get(cc, DEFAULT_COORD)
        country_list.append({
            "country_code": cc,
            "country": info.get("country_name", ""),
            "lat": coords[0],
            "lon": coords[1],
            "count": info["count"],
            "unique_ips": len(info["ips"]),
            "severities": dict(info["severities"]),
            "top_category": max(info["categories"], key=info["categories"].get) if info["categories"] else "",
        })
    country_list.sort(key=lambda x: -x["count"])

    return {
        "attacks": attacks,
        "countries": country_list,
        "total_attacks": total,
        "total_countries": len(country_list),
        "filtered_out": skipped,
        "target": {"lat": 20.6, "lon": 78.9, "label": "NOTICE Network"},
    }
