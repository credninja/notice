"""
IP Enrichment Engine — hostname resolution, service identification,
geo-location, and owner attribution for all IP addresses.

Combines: reverse DNS, TLS SNI, DNS query logs, HTTP host headers,
known service IP ranges, and GeoIP data into a unified enrichment layer.
"""

from collections import defaultdict
from eve_reader import iter_events, is_internal, is_ipv4
from db import get_db
from analyzers.geoip import lookup_batch, get_cached

# Known service IP range prefixes and SNI/domain -> service mapping
SERVICE_DOMAINS = {
    "google": {"google.com", "googleapis.com", "gstatic.com", "youtube.com", "ytimg.com",
               "googlevideo.com", "googleusercontent.com", "ggpht.com", "doubleclick.net",
               "google-analytics.com", "googleadservices.com", "gvt1.com", "gvt2.com"},
    "Meta (Facebook)": {"facebook.com", "fbcdn.net", "fb.com", "instagram.com",
                        "whatsapp.net", "whatsapp.com", "facebook.net", "fbsbx.com"},
    "Microsoft": {"microsoft.com", "msedge.net", "windows.net", "office.com", "live.com",
                  "outlook.com", "skype.com", "microsoftonline.com", "azure.com", "bing.com",
                  "teams.microsoft.com", "sharepoint.com", "onedrive.com", "visualstudio.com",
                  "vscode-cdn.net", "windows.com", "msftconnecttest.com"},
    "Apple": {"apple.com", "icloud.com", "aaplimg.com", "apple-dns.net", "cdn-apple.com",
              "mzstatic.com", "itunes.apple.com"},
    "Amazon (AWS)": {"amazonaws.com", "amazon.com", "aws.amazon.com", "cloudfront.net",
                     "a2z.com", "awsstatic.com", "elasticloadbalancing.com", "awswaf.com"},
    "Cloudflare": {"cloudflare.com", "cloudflare-dns.com", "cloudflareinsights.com",
                   "cdnjs.cloudflare.com", "workers.dev"},
    "Akamai": {"akamai.net", "akamaiedge.net", "akadns.net", "akamaized.net"},
    "Fastly": {"fastly.net", "fastlylb.net", "fastly.com"},
    "Discord": {"discord.com", "discord.gg", "discordapp.com", "discord.media"},
    "Spotify": {"spotify.com", "scdn.co", "spotifycdn.com"},
    "Mozilla": {"mozilla.org", "mozilla.com", "firefox.com", "mozgcp.net"},
    "Ubuntu/Canonical": {"ubuntu.com", "canonical.com", "launchpad.net", "snapcraft.io"},
    "Fortinet": {"fortinet.com", "fortiguard.com", "fortigate.com"},
    "Elastic": {"elastic.co", "elasticsearch.com"},
    "ChatGPT (OpenAI)": {"openai.com", "chatgpt.com", "oaiusercontent.com"},
    "Telegram": {"telegram.org", "t.me", "telegram.me"},
    "GitHub": {"github.com", "github.io", "githubusercontent.com", "githubassets.com"},
    "Overleaf": {"overleaf.com"},
}

# Flatten for fast lookup
_DOMAIN_TO_SERVICE = {}
for svc, domains in SERVICE_DOMAINS.items():
    for d in domains:
        _DOMAIN_TO_SERVICE[d] = svc


def identify_service(hostname_or_sni):
    """Map a hostname/SNI/domain to a known service name."""
    if not hostname_or_sni:
        return ""
    h = hostname_or_sni.lower().rstrip(".")
    # Direct match
    if h in _DOMAIN_TO_SERVICE:
        return _DOMAIN_TO_SERVICE[h]
    # Try parent domains
    parts = h.split(".")
    for i in range(len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in _DOMAIN_TO_SERVICE:
            return _DOMAIN_TO_SERVICE[parent]
    return ""


def get_asset_map():
    """Load internal asset map for owner attribution."""
    try:
        conn = get_db()
        rows = conn.execute(
            "SELECT ip, owner, hostname, asset_type, department FROM assets WHERE scope='internal'"
        ).fetchall()
        conn.close()
        return {r["ip"]: {
            "owner": r["owner"] or "",
            "hostname": r["hostname"] or "",
            "type": r["asset_type"] or "",
            "department": r["department"] or "",
        } for r in rows}
    except Exception:
        return {}


def enrich_ip(ip, asset_map=None, hostname_map=None, geo_map=None):
    """
    Fully enrich a single IP address.
    Returns dict with owner, hostname, service, geo, is_india, etc.
    """
    result = {
        "ip": ip,
        "internal": is_internal(ip),
        "owner": "",
        "department": "",
        "asset_type": "",
        "hostname": "",
        "service": "",
        "country": "",
        "country_code": "",
        "city": "",
        "isp": "",
        "org": "",
        "is_india": None,
        "geo_tag": "",
    }

    # Owner attribution (internal IPs)
    if asset_map and ip in asset_map:
        a = asset_map[ip]
        result["owner"] = a.get("owner", "")
        result["department"] = a.get("department", "")
        result["asset_type"] = a.get("type", "")
        result["hostname"] = a.get("hostname", "")

    # Hostname/service mapping (external IPs)
    if hostname_map and ip in hostname_map:
        hn = hostname_map[ip]
        result["hostname"] = hn.get("hostname", "")
        result["service"] = hn.get("service", "")

    # GeoIP
    if geo_map and ip in geo_map:
        g = geo_map[ip]
        result["country"] = g.get("country", "")
        result["country_code"] = g.get("country_code", "")
        result["city"] = g.get("city", "")
        result["isp"] = g.get("isp", "")
        result["org"] = g.get("org", "")
        result["is_india"] = g.get("country_code", "") == "IN"
        result["geo_tag"] = "India" if result["is_india"] else ("International" if result["country"] else "")

    return result


def format_label(ip, asset_map=None, hostname_map=None):
    """Build a display label like 'Analyst-1 (10.0.0.10)' or 'example.com (93.184.x.x)'."""
    if asset_map and ip in asset_map:
        owner = asset_map[ip].get("owner", "")
        if owner:
            return f"{owner} ({ip})"
    if hostname_map and ip in hostname_map:
        hn = hostname_map[ip].get("hostname", "")
        svc = hostname_map[ip].get("service", "")
        if hn:
            label = hn
            if svc:
                label = f"{hn} [{svc}]"
            return f"{label}"
    return ip


_hostname_cache = {"data": None, "minutes": None, "ts": 0}

def build_hostname_map(minutes=None):
    """
    Build IP -> hostname/service map from DNS queries, TLS SNI, and HTTP hosts.
    Scans eve.json to correlate IPs with their hostnames.
    Results are cached for 120s to avoid redundant eve.json scans.
    """
    import time as _t
    now = _t.time()
    if (_hostname_cache["data"] is not None
            and _hostname_cache["minutes"] == minutes
            and now - _hostname_cache["ts"] < 120):
        return _hostname_cache["data"]
    ip_to_host = defaultdict(lambda: {"hostnames": defaultdict(int), "snis": defaultdict(int)})

    for ev in iter_events(event_types={"dns", "tls", "http"}, minutes=minutes):
        etype = ev.get("event_type")
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")

        if etype == "dns":
            dns = ev.get("dns", {})
            # DNS answers map queried domain to resolved IP
            if dns.get("type") == "response":
                answers = dns.get("answers", [])
                for ans in answers:
                    rdata = ans.get("rdata", "")
                    rrname = ans.get("rrname", "")
                    if rdata and rrname and is_ipv4(rdata) and not is_internal(rdata):
                        ip_to_host[rdata]["hostnames"][rrname.rstrip(".")] += 1

        elif etype == "tls":
            tls = ev.get("tls", {})
            sni = tls.get("sni", "")
            if sni and dst and not is_internal(dst):
                ip_to_host[dst]["snis"][sni] += 1

        elif etype == "http":
            http = ev.get("http", {})
            host = http.get("hostname", "")
            if host and dst and not is_internal(dst):
                ip_to_host[dst]["hostnames"][host] += 1

    # Build final map: pick the most-seen hostname for each IP
    result = {}
    for ip, data in ip_to_host.items():
        best_host = ""
        best_count = 0
        # Prefer SNI over DNS/HTTP for accuracy
        for sni, cnt in data["snis"].items():
            if cnt > best_count:
                best_host = sni
                best_count = cnt
        if not best_host:
            for hn, cnt in data["hostnames"].items():
                if cnt > best_count:
                    best_host = hn
                    best_count = cnt
        if best_host:
            service = identify_service(best_host)
            result[ip] = {"hostname": best_host, "service": service}

    _hostname_cache["data"] = result
    _hostname_cache["minutes"] = minutes
    _hostname_cache["ts"] = _t.time()
    return result


def build_enrichment_context(minutes=None, external_ips=None):
    """
    Build complete enrichment context: asset map, hostname map, geo map.
    Call once, pass to enrich_ip() for each IP.
    Returns (asset_map, hostname_map, geo_map).
    """
    asset_map = get_asset_map()
    hostname_map = build_hostname_map(minutes=minutes)

    # Collect all external IPs for geo lookup
    all_ext = set(hostname_map.keys())
    if external_ips:
        all_ext.update(external_ips)
    all_ext = [ip for ip in all_ext if not is_internal(ip)]

    geo_map = {}
    if all_ext:
        geo_map = lookup_batch(all_ext[:200])  # limit batch size

    return asset_map, hostname_map, geo_map
