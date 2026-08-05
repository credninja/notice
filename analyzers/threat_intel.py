"""
Threat intelligence integration.
- JA4+ fingerprint matching against known malware signatures
"""

import json
from collections import defaultdict
from db import get_db
from eve_reader import iter_events, is_internal, is_ipv4

# Known malicious JA4 fingerprints (curated from public threat intel)
# Format: ja4 hash -> {name, description, category}
# Sources: ja4db.com, trisul, FoxIO
KNOWN_JA4 = {
    "t13d1517h2_8daaf6152771_b1ff8ab2d16f": {"name": "Cobalt Strike", "category": "c2", "severity": "critical"},
    "t13d1516h2_8daaf6152771_b1ff8ab2d16f": {"name": "Cobalt Strike (variant)", "category": "c2", "severity": "critical"},
    "t13d1517h2_8daaf6152771_e5627efa2ab1": {"name": "Cobalt Strike Beacon", "category": "c2", "severity": "critical"},
    "t13i1517h2_8daaf6152771_b1ff8ab2d16f": {"name": "Cobalt Strike (JARM)", "category": "c2", "severity": "critical"},
    "t13d1516h2_8daaf6152771_02713d6af862": {"name": "Metasploit Meterpreter", "category": "c2", "severity": "critical"},
    "t13d190900_9dc949149365_97f8aa674fd9": {"name": "Sliver C2", "category": "c2", "severity": "critical"},
    "t13d1517h2_2bab15409345_d42e22b1e924": {"name": "Havoc C2", "category": "c2", "severity": "critical"},
    "t10i060600_4f0108287fc8_6172060a5f94": {"name": "Suspicious TLS 1.0 Client", "category": "suspicious", "severity": "high"},
    "t13d1517h2_8daaf6152771_3b5074ec1b0a": {"name": "Brute Ratel", "category": "c2", "severity": "critical"},
    "t13d1517h2_8daaf6152771_bb5074ec1b0a": {"name": "Mythic C2", "category": "c2", "severity": "critical"},
}


def scan_ja4_fingerprints(minutes=None):
    """Scan TLS events for known malicious JA4 fingerprints."""
    matches = defaultdict(lambda: {
        "count": 0, "sources": set(), "dests": set(), "snis": set(), "timestamps": []
    })
    all_ja4s = defaultdict(lambda: {
        "count": 0, "sources": set(), "dests": set(), "snis": set()
    })

    for ev in iter_events(event_types={"tls"}, minutes=minutes):
        tls = ev.get("tls", {})
        ja4 = tls.get("ja4", "")
        if not ja4:
            continue

        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        sni = tls.get("sni", "")

        # Track all JA4s for frequency analysis
        info = all_ja4s[ja4]
        info["count"] += 1
        info["sources"].add(src)
        info["dests"].add(dst)
        if sni:
            info["snis"].add(sni)

        # Check against known malicious
        if ja4 in KNOWN_JA4:
            m = matches[ja4]
            m["count"] += 1
            m["sources"].add(src)
            m["dests"].add(dst)
            if sni:
                m["snis"].add(sni)
            if len(m["timestamps"]) < 10:
                m["timestamps"].append(ev.get("timestamp", ""))

    malicious = []
    for ja4, info in matches.items():
        known = KNOWN_JA4[ja4]
        malicious.append({
            "ja4": ja4,
            "name": known["name"],
            "category": known["category"],
            "severity": known["severity"],
            "count": info["count"],
            "sources": list(info["sources"])[:20],
            "dests": list(info["dests"])[:20],
            "snis": list(info["snis"])[:10],
            "timestamps": info["timestamps"][:5],
        })
    malicious.sort(key=lambda x: x["count"], reverse=True)

    # Top JA4 fingerprints by frequency (for analysis)
    top_ja4 = []
    for ja4, info in sorted(all_ja4s.items(), key=lambda x: -x[1]["count"])[:30]:
        is_known = ja4 in KNOWN_JA4
        top_ja4.append({
            "ja4": ja4,
            "count": info["count"],
            "unique_sources": len(info["sources"]),
            "unique_dests": len(info["dests"]),
            "sample_snis": list(info["snis"])[:5],
            "known_malicious": is_known,
            "name": KNOWN_JA4[ja4]["name"] if is_known else "",
        })

    return {
        "malicious_matches": malicious,
        "top_fingerprints": top_ja4,
        "total_ja4_seen": len(all_ja4s),
        "malicious_count": len(malicious),
    }


def get_external_ip_intel(minutes=None):
    """
    Collect external IPs communicating with internal hosts,
    enrich with geo from cache.
    """
    external = defaultdict(lambda: {
        "bytes": 0, "flows": 0, "internal_peers": set(),
        "app_protos": set(), "has_alerts": False,
    })

    for ev in iter_events(event_types={"flow", "alert"}, minutes=minutes):
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        if not is_ipv4(src) or not is_ipv4(dst):
            continue
        src_int = is_internal(src)
        dst_int = is_internal(dst)
        if not src_int and not dst_int:
            continue

        etype = ev["event_type"]
        ext_ip = dst if src_int else src
        int_ip = src if src_int else dst

        if is_internal(ext_ip):
            continue

        info = external[ext_ip]
        if etype == "alert":
            info["has_alerts"] = True
        elif etype == "flow":
            flow = ev.get("flow", {})
            info["bytes"] += flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
            info["flows"] += 1
            info["internal_peers"].add(int_ip)
            ap = ev.get("app_proto", "")
            if ap and ap != "failed":
                info["app_protos"].add(ap)

    # Top external IPs by traffic volume
    sorted_ext = sorted(external.items(), key=lambda x: -x[1]["bytes"])[:50]

    conn = get_db()
    results = []
    for ip, info in sorted_ext:
        entry = {
            "ip": ip,
            "bytes": info["bytes"],
            "flows": info["flows"],
            "internal_peers": list(info["internal_peers"])[:10],
            "internal_peer_count": len(info["internal_peers"]),
            "app_protos": list(info["app_protos"]),
            "has_alerts": info["has_alerts"],
            "geo": None,
        }
        # Pull geo from existing cache
        geo = conn.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
        if geo:
            entry["geo"] = {"country": geo["country"], "country_code": geo["country_code"],
                            "city": geo["city"], "isp": geo["isp"], "org": geo["org"]}
        results.append(entry)
    conn.close()

    return results
