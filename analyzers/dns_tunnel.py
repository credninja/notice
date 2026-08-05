"""
DNS tunneling detection.
Uses entropy analysis, subdomain length, query frequency, and TXT record abuse
to identify potential DNS-based data exfiltration or C2 channels.
"""

import math
from collections import defaultdict
from eve_reader import iter_events, is_internal

# Thresholds
ENTROPY_THRESHOLD = 3.5  # Shannon entropy of subdomain (random chars ~4.0+)
SUBDOMAIN_LEN_THRESHOLD = 30  # Unusually long subdomains
TXT_QUERY_THRESHOLD = 10  # TXT queries to same domain
QUERY_RATE_THRESHOLD = 100  # Queries per host to same domain in window
LABEL_COUNT_THRESHOLD = 5  # Too many subdomain labels


def shannon_entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def extract_subdomain(fqdn):
    """Extract the subdomain portion (everything before the registered domain)."""
    parts = fqdn.rstrip(".").split(".")
    if len(parts) <= 2:
        return ""
    # Heuristic: last 2 parts are domain + TLD (or last 3 for .co.uk etc)
    if len(parts) >= 3 and len(parts[-2]) <= 3:
        return ".".join(parts[:-3])
    return ".".join(parts[:-2])


def get_base_domain(fqdn):
    """Extract base domain from FQDN."""
    parts = fqdn.rstrip(".").split(".")
    if len(parts) <= 2:
        return fqdn.rstrip(".")
    if len(parts) >= 3 and len(parts[-2]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def detect_dns_tunneling(minutes=None):
    """
    Analyze DNS traffic for tunneling indicators.
    Returns suspicious hosts and domains with scoring.
    """
    # Per-host, per-domain aggregation
    host_domain = defaultdict(lambda: {
        "query_count": 0, "txt_count": 0, "null_count": 0,
        "unique_subdomains": set(), "subdomains": [],
        "high_entropy_count": 0, "long_subdomain_count": 0,
        "total_subdomain_len": 0, "max_subdomain_len": 0,
        "nxdomain_count": 0, "timestamps": [],
        "rrtypes": defaultdict(int),
    })

    # Also track per-host totals
    host_totals = defaultdict(lambda: {
        "total_queries": 0, "unique_domains": set(),
        "txt_total": 0, "null_total": 0,
    })

    for ev in iter_events(event_types={"dns"}, minutes=minutes):
        dns = ev.get("dns", {})
        src = ev.get("src_ip", "")
        if not src or not is_internal(src):
            continue

        queries = dns.get("queries", [])
        dns_type = dns.get("type", "")
        rcode = dns.get("rcode", "")

        for q in queries:
            rrname = q.get("rrname", "")
            rrtype = q.get("rrtype", "")
            if not rrname:
                continue

            # Skip common/known-safe domains
            if _is_known_safe(rrname):
                continue

            base = get_base_domain(rrname)
            subdomain = extract_subdomain(rrname)
            key = (src, base)

            info = host_domain[key]
            info["query_count"] += 1
            info["rrtypes"][rrtype] += 1

            if rrtype == "TXT":
                info["txt_count"] += 1
            elif rrtype == "NULL":
                info["null_count"] += 1

            if subdomain:
                info["unique_subdomains"].add(subdomain)
                if len(info["subdomains"]) < 50:
                    info["subdomains"].append(subdomain)
                sub_len = len(subdomain)
                info["total_subdomain_len"] += sub_len
                if sub_len > info["max_subdomain_len"]:
                    info["max_subdomain_len"] = sub_len
                if sub_len > SUBDOMAIN_LEN_THRESHOLD:
                    info["long_subdomain_count"] += 1
                entropy = shannon_entropy(subdomain.replace(".", ""))
                if entropy > ENTROPY_THRESHOLD:
                    info["high_entropy_count"] += 1

            if rcode == "NXDOMAIN":
                info["nxdomain_count"] += 1

            if len(info["timestamps"]) < 20:
                info["timestamps"].append(ev.get("timestamp", ""))

            ht = host_totals[src]
            ht["total_queries"] += 1
            ht["unique_domains"].add(base)
            if rrtype == "TXT":
                ht["txt_total"] += 1
            elif rrtype == "NULL":
                ht["null_total"] += 1

    # Score each host-domain pair
    suspicious = []
    for (host, domain), info in host_domain.items():
        score, reasons = _compute_tunnel_score(info, domain)
        if score < 30:
            continue  # Not suspicious enough
        avg_sub_len = (info["total_subdomain_len"] / len(info["unique_subdomains"])
                       if info["unique_subdomains"] else 0)
        suspicious.append({
            "host": host,
            "domain": domain,
            "score": score,
            "reasons": reasons,
            "query_count": info["query_count"],
            "unique_subdomains": len(info["unique_subdomains"]),
            "txt_queries": info["txt_count"],
            "null_queries": info["null_count"],
            "high_entropy_count": info["high_entropy_count"],
            "long_subdomain_count": info["long_subdomain_count"],
            "avg_subdomain_len": round(avg_sub_len, 1),
            "max_subdomain_len": info["max_subdomain_len"],
            "nxdomain_count": info["nxdomain_count"],
            "rrtypes": dict(info["rrtypes"]),
            "sample_subdomains": info["subdomains"][:10],
            "first_seen": info["timestamps"][0] if info["timestamps"] else None,
            "last_seen": info["timestamps"][-1] if info["timestamps"] else None,
        })

    suspicious.sort(key=lambda x: -x["score"])

    # Summary per host
    host_summary = []
    suspicious_hosts = set(s["host"] for s in suspicious)
    for host in suspicious_hosts:
        ht = host_totals[host]
        host_entries = [s for s in suspicious if s["host"] == host]
        host_summary.append({
            "host": host,
            "total_queries": ht["total_queries"],
            "unique_domains": len(ht["unique_domains"]),
            "suspicious_domains": len(host_entries),
            "max_score": max(s["score"] for s in host_entries),
            "txt_total": ht["txt_total"],
            "null_total": ht["null_total"],
        })
    host_summary.sort(key=lambda x: -x["max_score"])

    return {
        "suspicious_pairs": suspicious[:100],
        "host_summary": host_summary,
        "total_suspicious_pairs": len(suspicious),
        "total_suspicious_hosts": len(suspicious_hosts),
    }


def _compute_tunnel_score(info, domain):
    """Score 0-100 for DNS tunneling likelihood."""
    score = 0
    reasons = []

    # High query volume to single domain
    if info["query_count"] > QUERY_RATE_THRESHOLD:
        score += 20
        reasons.append(f"High query volume ({info['query_count']})")

    # Many unique subdomains = data encoded in DNS
    unique_count = len(info["unique_subdomains"])
    if unique_count > 20:
        score += 25
        reasons.append(f"Many unique subdomains ({unique_count})")
    elif unique_count > 5:
        score += 10
        reasons.append(f"Multiple unique subdomains ({unique_count})")

    # High entropy subdomains (random/encoded data)
    if info["high_entropy_count"] > 5:
        score += 25
        reasons.append(f"High-entropy subdomains ({info['high_entropy_count']})")
    elif info["high_entropy_count"] > 0:
        score += 10

    # Long subdomains
    if info["long_subdomain_count"] > 3:
        score += 15
        reasons.append(f"Long subdomains ({info['long_subdomain_count']})")
    elif info["max_subdomain_len"] > SUBDOMAIN_LEN_THRESHOLD:
        score += 5

    # TXT record abuse (commonly used for tunneling)
    if info["txt_count"] > TXT_QUERY_THRESHOLD:
        score += 20
        reasons.append(f"Excessive TXT queries ({info['txt_count']})")

    # NULL record queries (iodine DNS tunnel)
    if info["null_count"] > 0:
        score += 15
        reasons.append(f"NULL record queries ({info['null_count']})")

    return min(score, 100), reasons


def _is_known_safe(fqdn):
    """Filter out known-safe domains that would create false positives."""
    safe = {
        "local", "arpa", "googleapis.com", "google.com", "gstatic.com",
        "microsoft.com", "windows.net", "apple.com", "icloud.com",
        "mozilla.org", "mozilla.com", "firefox.com", "ubuntu.com",
        "cloudflare.com", "amazonaws.com", "akamai.net", "akamaiedge.net",
        "fbcdn.net", "facebook.com", "whatsapp.net",
    }
    parts = fqdn.rstrip(".").split(".")
    if len(parts) >= 2:
        base = ".".join(parts[-2:])
        if base in safe:
            return True
    if fqdn.endswith(".local") or fqdn.endswith(".arpa"):
        return True
    return False
