"""
DNS Analytics — query statistics, DGA detection, top domains,
unusual query volume detection, and per-host DNS profiling.
"""

import math
from collections import defaultdict
from eve_reader import iter_events, is_internal
from analyzers.dns_tunnel import shannon_entropy, get_base_domain


# DGA detection thresholds
DGA_ENTROPY_THRESHOLD = 3.8
DGA_LENGTH_THRESHOLD = 12
DGA_CONSONANT_RATIO = 0.7
DGA_DIGIT_RATIO = 0.3

VOWELS = set("aeiou")


def _is_dga_candidate(domain):
    """Heuristic DGA detection based on entropy, length, and character distribution."""
    parts = domain.rstrip(".").split(".")
    if len(parts) < 2:
        return False, 0, []
    sld = parts[-2] if len(parts) >= 2 else parts[0]
    if len(sld) < DGA_LENGTH_THRESHOLD:
        return False, 0, []
    reasons = []
    score = 0
    entropy = shannon_entropy(sld)
    if entropy > DGA_ENTROPY_THRESHOLD:
        score += 40
        reasons.append(f"High entropy ({entropy:.2f})")
    alpha = [c for c in sld if c.isalpha()]
    if alpha:
        consonant_ratio = sum(1 for c in alpha if c.lower() not in VOWELS) / len(alpha)
        if consonant_ratio > DGA_CONSONANT_RATIO:
            score += 25
            reasons.append(f"High consonant ratio ({consonant_ratio:.2f})")
    digits = sum(1 for c in sld if c.isdigit())
    if len(sld) > 0 and digits / len(sld) > DGA_DIGIT_RATIO:
        score += 20
        reasons.append(f"High digit ratio ({digits}/{len(sld)})")
    if len(sld) > 20:
        score += 15
        reasons.append(f"Very long SLD ({len(sld)} chars)")
    has_pattern = any(sld[i] == sld[i+1] == sld[i+2] for i in range(len(sld)-2) if sld[i].isdigit())
    if not has_pattern and score >= 40:
        pass
    return score >= 40, score, reasons


def analyze_dns(minutes=None):
    """Full DNS analytics: stats, top domains, DGA detection, per-host profiles."""
    host_queries = defaultdict(lambda: {
        "total": 0, "domains": defaultdict(int), "rrtypes": defaultdict(int),
        "nxdomain": 0, "responses": 0,
    })
    domain_stats = defaultdict(lambda: {
        "query_count": 0, "queried_by": set(), "rrtypes": defaultdict(int),
        "nxdomain_count": 0,
    })
    rrtype_totals = defaultdict(int)
    total_queries = 0
    total_responses = 0
    total_nxdomain = 0
    hourly_queries = defaultdict(int)

    for ev in iter_events(event_types={"dns"}, minutes=minutes):
        dns = ev.get("dns", {})
        src = ev.get("src_ip", "")
        ts = ev.get("timestamp", "")

        if not src or not is_internal(src):
            continue

        dns_type = dns.get("type", "")
        rrname = dns.get("rrname", "")
        rrtype = dns.get("rrtype", "")
        rcode = dns.get("rcode", "")

        if not rrname:
            queries = dns.get("queries", [])
            if queries:
                rrname = queries[0].get("rrname", "")
                rrtype = queries[0].get("rrtype", "")

        if not rrname:
            continue

        base = get_base_domain(rrname)
        total_queries += 1

        if rrtype:
            rrtype_totals[rrtype] += 1

        hq = host_queries[src]
        hq["total"] += 1
        hq["domains"][base] += 1
        if rrtype:
            hq["rrtypes"][rrtype] += 1

        ds = domain_stats[base]
        ds["query_count"] += 1
        ds["queried_by"].add(src)
        if rrtype:
            ds["rrtypes"][rrtype] += 1

        if rcode == "NXDOMAIN":
            total_nxdomain += 1
            hq["nxdomain"] += 1
            ds["nxdomain_count"] += 1

        if dns_type == "answer" or dns_type == "response":
            total_responses += 1
            hq["responses"] += 1

        if ts:
            try:
                hour = ts[11:13]
                if hour:
                    hourly_queries[int(hour)] += 1
            except (ValueError, IndexError):
                pass

    # Top queried domains
    top_domains = sorted(domain_stats.items(), key=lambda x: -x[1]["query_count"])[:50]
    top_domains_list = [{
        "domain": d,
        "query_count": info["query_count"],
        "unique_hosts": len(info["queried_by"]),
        "nxdomain_count": info["nxdomain_count"],
        "rrtypes": dict(info["rrtypes"]),
    } for d, info in top_domains]

    # DGA detection
    dga_suspects = []
    for domain, info in domain_stats.items():
        is_dga, score, reasons = _is_dga_candidate(domain)
        if is_dga:
            dga_suspects.append({
                "domain": domain,
                "score": score,
                "reasons": reasons,
                "query_count": info["query_count"],
                "unique_hosts": len(info["queried_by"]),
                "hosts": sorted(info["queried_by"])[:10],
            })
    dga_suspects.sort(key=lambda x: -x["score"])

    # Per-host DNS profiles (top talkers)
    host_profiles = []
    for host, info in host_queries.items():
        top_host_domains = sorted(info["domains"].items(), key=lambda x: -x[1])[:10]
        nxdomain_ratio = info["nxdomain"] / info["total"] if info["total"] > 0 else 0
        host_profiles.append({
            "host": host,
            "total_queries": info["total"],
            "unique_domains": len(info["domains"]),
            "nxdomain_count": info["nxdomain"],
            "nxdomain_ratio": round(nxdomain_ratio, 3),
            "rrtypes": dict(info["rrtypes"]),
            "top_domains": [{"domain": d, "count": c} for d, c in top_host_domains],
        })
    host_profiles.sort(key=lambda x: -x["total_queries"])

    # Unusual query volume detection
    if host_profiles:
        counts = [h["total_queries"] for h in host_profiles]
        mean_q = sum(counts) / len(counts)
        if len(counts) > 1:
            var = sum((c - mean_q) ** 2 for c in counts) / len(counts)
            stddev = math.sqrt(var)
        else:
            stddev = 0
        threshold = mean_q + 2 * stddev
        anomalous_hosts = [h for h in host_profiles if h["total_queries"] > threshold and h["total_queries"] > 50]
    else:
        anomalous_hosts = []

    # Hourly distribution
    hourly = [{"hour": h, "queries": hourly_queries.get(h, 0)} for h in range(24)]

    return {
        "summary": {
            "total_queries": total_queries,
            "total_responses": total_responses,
            "total_nxdomain": total_nxdomain,
            "unique_domains": len(domain_stats),
            "unique_hosts": len(host_queries),
            "dga_suspects": len(dga_suspects),
            "anomalous_hosts": len(anomalous_hosts),
        },
        "top_domains": top_domains_list[:30],
        "dga_suspects": dga_suspects[:50],
        "host_profiles": host_profiles[:50],
        "anomalous_hosts": anomalous_hosts[:20],
        "rrtype_distribution": dict(rrtype_totals),
        "hourly_distribution": hourly,
    }
