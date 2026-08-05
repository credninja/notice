"""
Unified threat-intelligence scorer.

Combines signals from every TI source NOTICE has into one classification
({malicious, suspicious, benign, unknown, internal}) and a 0-100 score so
the rest of the system (alert log chips, auto-promote engine, knowledge
graph, incident impact) doesn't have to know which underlying API the
verdict came from.

Sources (in priority order):
  1. VirusTotal           — definitive when ≥1 engine flags malicious
  2. AbuseIPDB            — high abuse_score = malicious; medium = suspicious
  3. Tor exit list        — automatic suspicious (not malicious by itself)
  4. Internal/local       — never flagged; tagged 'internal'
"""

from analyzers.virustotal import lookup_ip as vt_lookup_ip, lookup_domain as vt_lookup_domain, lookup_url as vt_lookup_url
from analyzers.reputation import lookup_reputation as abuse_lookup
from analyzers.tor_list import is_tor_exit
from eve_reader import is_internal


def score_ip(ip):
    """Unified IP score combining VT + AbuseIPDB + Tor.

    Returns:
        {
          ip, classification, score, sources,
          vt: {...}, abuse: {...}, is_tor: bool, is_internal: bool,
        }
    """
    if is_internal(ip):
        return {
            "ip": ip, "classification": "internal", "score": 0,
            "sources": ["internal"], "is_internal": True, "is_tor": False,
            "vt": {}, "abuse": {},
        }

    vt = vt_lookup_ip(ip) or {}
    abuse = abuse_lookup(ip) or {}
    tor = bool(is_tor_exit(ip))

    sources = []
    cls = "unknown"
    score = 0

    vt_mal = int(vt.get("vt_malicious") or 0)
    vt_sus = int(vt.get("vt_suspicious") or 0)
    vt_score = int(vt.get("vt_score") or 0)
    vt_total = int(vt.get("vt_total_engines") or 0)
    if vt_total:
        sources.append("virustotal")
        if vt_mal >= 5:
            cls = "malicious"
            score = max(score, 80 + min(vt_score, 20))
        elif vt_mal >= 1 or vt_sus >= 3:
            cls = "suspicious"
            score = max(score, 50 + min(vt_score, 30))
        else:
            score = max(score, vt_score)

    abuse_score = int(abuse.get("abuse_score") or 0)
    if abuse_score >= 0:
        sources.append("abuseipdb")
        if abuse_score >= 75 and cls != "malicious":
            cls = "malicious"
            score = max(score, abuse_score)
        elif abuse_score >= 25 and cls != "malicious":
            cls = "suspicious"
            score = max(score, abuse_score)
        elif cls == "unknown":
            score = max(score, abuse_score)

    if tor:
        sources.append("tor_exit")
        if cls in ("unknown", "benign"):
            cls = "suspicious"
            score = max(score, 60)

    if cls == "unknown" and (vt_total or abuse_score >= 0):
        cls = "benign"

    return {
        "ip": ip,
        "classification": cls,
        "score": int(score),
        "sources": sources,
        "is_internal": False,
        "is_tor": tor,
        "vt": {
            "malicious": vt_mal,
            "suspicious": vt_sus,
            "total_engines": vt_total,
            "score": vt_score,
            "categories": vt.get("vt_categories") or "",
            "error": vt.get("error"),
        },
        "abuse": {
            "score": abuse_score,
            "total_reports": abuse.get("total_reports") or 0,
            "country": abuse.get("country_code") or "",
            "isp": abuse.get("isp") or "",
            "domain": abuse.get("domain") or "",
            "error": abuse.get("error"),
        },
    }


def score_domain(domain):
    """Domain reputation — VT only."""
    vt = vt_lookup_domain(domain) or {}
    cls = vt.get("classification") or "unknown"
    score = int(vt.get("vt_score") or 0)
    return {
        "domain": domain,
        "classification": cls,
        "score": score,
        "sources": ["virustotal"] if vt.get("vt_total_engines") else [],
        "vt": vt,
    }


def score_url(url):
    vt = vt_lookup_url(url) or {}
    cls = vt.get("classification") or "unknown"
    score = int(vt.get("vt_score") or 0)
    return {
        "url": url,
        "classification": cls,
        "score": score,
        "sources": ["virustotal"] if vt.get("vt_total_engines") else [],
        "vt": vt,
    }


def quick_chip_for_ip(ip):
    """Lightweight version for inline chips: returns just classification + score
    using ONLY cached data (no API call). For row decoration in the alert log."""
    if is_internal(ip):
        return {"classification": "internal", "score": 0}
    from db import get_db
    conn = get_db()
    row = conn.execute(
        "SELECT abuse_score, vt_score, vt_malicious, vt_suspicious, vt_total_engines, "
        "       classification, is_tor "
        "FROM ip_reputation WHERE ip = ?",
        (ip,),
    ).fetchone()
    conn.close()
    if not row:
        return {"classification": "unknown", "score": 0}
    cls = row["classification"] or "unknown"
    if cls == "unknown":
        # Derive from raw fields if classification wasn't computed
        ab = int(row["abuse_score"] or 0)
        vm = int(row["vt_malicious"] or 0)
        vs = int(row["vt_suspicious"] or 0)
        if vm >= 5 or ab >= 75:
            cls = "malicious"
        elif vm >= 1 or vs >= 3 or ab >= 25:
            cls = "suspicious"
        elif (row["vt_total_engines"] or 0) > 0 or ab >= 0:
            cls = "benign"
    score = max(int(row["abuse_score"] or 0), int(row["vt_score"] or 0))
    return {"classification": cls, "score": score, "is_tor": bool(row["is_tor"])}
