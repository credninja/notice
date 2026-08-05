"""
Plaintext communication detection.
Identifies unencrypted protocols: HTTP, FTP, SMTP, weak SNMP, deprecated TLS.
"""

from collections import defaultdict
from eve_reader import iter_events, is_internal

WEAK_SNMP_COMMUNITIES = {"public", "private", "iiit123", "community", "default"}
DEPRECATED_TLS_VERSIONS = {"TLSv1", "TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"}


def detect_plaintext(minutes=None):
    """Scan for plaintext communication across all relevant event types."""
    http_connections = defaultdict(lambda: {
        "count": 0, "methods": set(), "urls": [], "user_agents": set()
    })
    ftp_events = []
    smtp_events = []
    snmp_weak = defaultdict(lambda: {"count": 0, "communities": set(), "pdu_types": set()})
    tls_deprecated = defaultdict(lambda: {"count": 0, "versions": set(), "snis": set()})

    event_types = {"http", "ftp", "smtp", "snmp", "tls"}

    for ev in iter_events(event_types=event_types, minutes=minutes):
        etype = ev["event_type"]
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")

        if etype == "http":
            http = ev.get("http", {})
            port = ev.get("dest_port", 0)
            if port == 443:
                continue  # HTTPS, not plaintext
            key = (src, dst, http.get("hostname", ""))
            c = http_connections[key]
            c["count"] += 1
            c["methods"].add(http.get("http_method", ""))
            if len(c["urls"]) < 5:
                c["urls"].append(http.get("url", "/"))
            ua = http.get("http_user_agent", "")
            if ua:
                c["user_agents"].add(ua[:80])

        elif etype == "ftp":
            ftp = ev.get("ftp", {})
            ftp_events.append({
                "timestamp": ev.get("timestamp", ""),
                "src_ip": src, "dest_ip": dst,
                "src_port": ev.get("src_port"),
                "dest_port": ev.get("dest_port"),
                "command": ftp.get("command", ""),
                "command_data": ftp.get("command_data", ""),
                "reply": ftp.get("reply", []),
                "src_internal": is_internal(src),
            })

        elif etype == "smtp":
            smtp = ev.get("smtp", {})
            smtp_events.append({
                "timestamp": ev.get("timestamp", ""),
                "src_ip": src, "dest_ip": dst,
                "helo": smtp.get("helo", ""),
                "mail_from": smtp.get("mail_from", ""),
                "rcpt_to": smtp.get("rcpt_to", []),
                "src_internal": is_internal(src),
            })

        elif etype == "snmp":
            snmp = ev.get("snmp", {})
            community = snmp.get("community", "")
            if community.lower() in WEAK_SNMP_COMMUNITIES:
                key = (src, dst)
                s = snmp_weak[key]
                s["count"] += 1
                s["communities"].add(community)
                s["pdu_types"].add(snmp.get("pdu_type", ""))

        elif etype == "tls":
            tls = ev.get("tls", {})
            version = tls.get("version", "")
            if version in DEPRECATED_TLS_VERSIONS:
                key = (src, dst)
                t = tls_deprecated[key]
                t["count"] += 1
                t["versions"].add(version)
                sni = tls.get("sni", "")
                if sni:
                    t["snis"].add(sni)

    # Build response
    http_list = []
    for (src, dst, hostname), info in http_connections.items():
        http_list.append({
            "src_ip": src, "dest_ip": dst,
            "hostname": hostname,
            "count": info["count"],
            "methods": list(info["methods"]),
            "sample_urls": info["urls"][:5],
            "user_agents": list(info["user_agents"])[:3],
            "src_internal": is_internal(src),
        })
    http_list.sort(key=lambda x: x["count"], reverse=True)

    snmp_list = []
    for (src, dst), info in snmp_weak.items():
        snmp_list.append({
            "src_ip": src, "dest_ip": dst,
            "count": info["count"],
            "communities": list(info["communities"]),
            "pdu_types": list(info["pdu_types"]),
            "src_internal": is_internal(src),
        })
    snmp_list.sort(key=lambda x: x["count"], reverse=True)

    tls_list = []
    for (src, dst), info in tls_deprecated.items():
        tls_list.append({
            "src_ip": src, "dest_ip": dst,
            "count": info["count"],
            "versions": list(info["versions"]),
            "snis": list(info["snis"])[:5],
            "src_internal": is_internal(src),
        })
    tls_list.sort(key=lambda x: x["count"], reverse=True)

    return {
        "http": http_list,
        "ftp": ftp_events,
        "smtp": smtp_events,
        "snmp_weak": snmp_list,
        "tls_deprecated": tls_list,
        "summary": {
            "http_connections": len(http_list),
            "http_requests": sum(h["count"] for h in http_list),
            "ftp_events": len(ftp_events),
            "smtp_events": len(smtp_events),
            "snmp_weak_connections": len(snmp_list),
            "tls_deprecated_connections": len(tls_list),
        },
    }
