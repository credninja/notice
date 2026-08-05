"""
Anomaly detection engine — enhanced with classification, confidence scoring,
and forensic reasoning for each detection.
Identifies: Nmap scanning, high-volume flows, DNS exfiltration indicators,
deprecated TLS, unusual ports, and application-layer anomalies.
"""

from collections import defaultdict
from eve_reader import iter_events, is_internal
from db import get_db

# Thresholds
HIGH_VOLUME_BYTES = 50 * 1024 * 1024  # 50MB
DNS_LONG_DOMAIN_LEN = 60
DNS_HIGH_QUERY_THRESHOLD = 200  # queries from single host
KNOWN_PORTS = {
    "http": {80, 8080, 8000, 8443},
    "tls": {443, 8443, 993, 995, 465},
    "dns": {53},
    "ssh": {22},
    "ftp": {21},
    "smtp": {25, 587, 465},
    "snmp": {161, 162},
    "sip": {5060, 5061},
    "dhcp": {67, 68},
    "ntp": {123},
}

# Anomaly type classification constants
ANOM_PORT_SCAN = "Port Scan"
ANOM_BEACON = "Beaconing / C2"
ANOM_DNS_TUNNEL = "DNS Tunneling"
ANOM_LATERAL = "Lateral Movement"
ANOM_UNUSUAL_PORT = "Unusual Port Usage"
ANOM_PROTOCOL_VIOLATION = "Protocol Violation"
ANOM_HIGH_VOLUME = "Data Exfiltration Indicator"
ANOM_DEPRECATED_CRYPTO = "Deprecated Cryptography"
ANOM_DNS_ABUSE = "DNS Abuse"
ANOM_RECON = "Reconnaissance"


def _get_asset_map():
    """Load asset map for enrichment."""
    try:
        conn = get_db()
        rows = conn.execute("SELECT ip, owner, hostname, asset_type FROM assets WHERE scope='internal'").fetchall()
        conn.close()
        return {r["ip"]: {"owner": r["owner"] or "", "hostname": r["hostname"] or "", "type": r["asset_type"] or ""} for r in rows}
    except Exception:
        return {}


def _asset_label(ip, asset_map):
    """Return owner/hostname label for an IP."""
    a = asset_map.get(ip)
    if not a:
        return ""
    return a["owner"] or a["hostname"] or ""


def detect_anomalies(minutes=None):
    """Detect anomalous patterns across event types with classification and reasoning."""
    asset_map = _get_asset_map()

    nmap_scanning = defaultdict(lambda: {
        "targets": set(), "software": set(), "timestamps": []
    })
    high_volume = []
    dns_by_host = defaultdict(lambda: {
        "query_count": 0, "domains": [], "long_domains": [], "nxdomain_count": 0
    })
    deprecated_tls = defaultdict(lambda: {"count": 0, "versions": set(), "snis": set()})
    unusual_ports = []
    applayer_anomalies = defaultdict(lambda: {"count": 0, "sources": set(), "dests": set(), "timestamps": []})

    event_types = {"ssh", "flow", "dns", "tls", "anomaly"}

    for ev in iter_events(event_types=event_types, minutes=minutes):
        etype = ev["event_type"]
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        ts = ev.get("timestamp", "")

        if etype == "ssh":
            ssh = ev.get("ssh", {})
            client_sw = ssh.get("client", {}).get("software_version", "")
            if "nmap" in client_sw.lower() or "NmapNSE" in client_sw:
                info = nmap_scanning[src]
                info["targets"].add(dst)
                info["software"].add(client_sw)
                if len(info["timestamps"]) < 10:
                    info["timestamps"].append(ts)

        elif etype == "flow":
            flow = ev.get("flow", {})
            total_bytes = flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
            if total_bytes > HIGH_VOLUME_BYTES:
                b_out = flow.get("bytes_toserver", 0)
                b_in = flow.get("bytes_toclient", 0)
                # Determine direction bias for exfil assessment
                direction = "outbound" if b_out > b_in else "inbound"
                ratio = max(b_out, b_in) / max(min(b_out, b_in), 1)
                high_volume.append({
                    "src_ip": src, "dest_ip": dst,
                    "bytes": total_bytes,
                    "bytes_out": b_out, "bytes_in": b_in,
                    "packets": flow.get("pkts_toserver", 0) + flow.get("pkts_toclient", 0),
                    "app_proto": ev.get("app_proto", "unknown"),
                    "proto": ev.get("proto", ""),
                    "dest_port": ev.get("dest_port", 0),
                    "duration": flow.get("age", 0),
                    "timestamp": ts,
                    "src_internal": is_internal(src),
                    "dest_internal": is_internal(dst),
                    "src_asset": _asset_label(src, asset_map),
                    "dest_asset": _asset_label(dst, asset_map),
                    # Classification
                    "anomaly_type": ANOM_HIGH_VOLUME,
                    "confidence": "Real" if (is_internal(src) and not is_internal(dst) and direction == "outbound" and ratio > 5) else "Suspected",
                    "severity": "high" if (is_internal(src) and not is_internal(dst) and b_out > HIGH_VOLUME_BYTES) else "medium",
                    "direction": direction,
                    "detection_type": "threshold",
                    "reasoning": _high_volume_reasoning(src, dst, b_out, b_in, total_bytes, is_internal(src), is_internal(dst)),
                })

            # Check unusual ports
            app_proto = ev.get("app_proto", "")
            dest_port = ev.get("dest_port", 0)
            if app_proto and app_proto in KNOWN_PORTS and dest_port not in KNOWN_PORTS[app_proto]:
                unusual_ports.append({
                    "src_ip": src, "dest_ip": dst,
                    "port": dest_port, "proto": ev.get("proto", ""),
                    "app_proto": app_proto,
                    "timestamp": ts,
                    "src_internal": is_internal(src),
                    "dest_internal": is_internal(dst),
                    "src_asset": _asset_label(src, asset_map),
                    "dest_asset": _asset_label(dst, asset_map),
                    # Classification
                    "anomaly_type": ANOM_UNUSUAL_PORT if dest_port != 1900 else ANOM_PROTOCOL_VIOLATION,
                    "confidence": "Suspected" if dest_port != 1900 else "False Positive",
                    "severity": "medium" if dest_port != 1900 else "low",
                    "detection_type": "rule-based",
                    "reasoning": f"Application protocol '{app_proto}' detected on port {dest_port}, which is not a standard port for this protocol. "
                                 f"Expected ports: {sorted(KNOWN_PORTS.get(app_proto, set()))}. "
                                 + ("This is SSDP/UPnP multicast (port 1900) misidentified as SIP — likely a false positive." if dest_port == 1900 else
                                    "Non-standard port usage may indicate evasion, tunneling, or misconfiguration."),
                })

        elif etype == "dns":
            dns = ev.get("dns", {})
            if dns.get("type") == "request":
                info = dns_by_host[src]
                info["query_count"] += 1
                queries = dns.get("queries", [])
                for q in queries:
                    rrname = q.get("rrname", "")
                    if len(rrname) > DNS_LONG_DOMAIN_LEN:
                        info["long_domains"].append(rrname)
                    if len(info["domains"]) < 20:
                        info["domains"].append(rrname)
            elif dns.get("type") == "response":
                rcode = dns.get("rcode", "")
                if rcode == "NXDOMAIN":
                    dns_by_host[src]["nxdomain_count"] += 1

        elif etype == "tls":
            tls = ev.get("tls", {})
            version = tls.get("version", "")
            if version in {"TLSv1", "TLS 1.0", "TLS 1.1", "SSLv3"}:
                key = (src, dst)
                d = deprecated_tls[key]
                d["count"] += 1
                d["versions"].add(version)
                sni = tls.get("sni", "")
                if sni:
                    d["snis"].add(sni)

        elif etype == "anomaly":
            anom = ev.get("anomaly", {})
            event_name = anom.get("event", "unknown")
            info = applayer_anomalies[event_name]
            info["count"] += 1
            info["sources"].add(src)
            info["dests"].add(dst)
            if len(info["timestamps"]) < 10:
                info["timestamps"].append(ts)

    # Build results with enriched classification
    nmap_list = []
    for src_ip, info in nmap_scanning.items():
        nmap_list.append({
            "src_ip": src_ip,
            "target_count": len(info["targets"]),
            "targets": list(info["targets"])[:20],
            "software": list(info["software"]),
            "timestamps": info["timestamps"][:5],
            "src_internal": is_internal(src_ip),
            "src_asset": _asset_label(src_ip, asset_map),
            # Classification
            "anomaly_type": ANOM_PORT_SCAN,
            "confidence": "Real",
            "severity": "critical" if is_internal(src_ip) else "high",
            "detection_type": "signature",
            "reasoning": f"Nmap scanning tool detected via SSH client fingerprint ({', '.join(info['software'])}). "
                         f"Host scanned {len(info['targets'])} target(s). "
                         f"{'Internal scanner — possible lateral movement or unauthorized pentesting.' if is_internal(src_ip) else 'External scanner — active reconnaissance against network.'}",
        })

    high_volume.sort(key=lambda x: x["bytes"], reverse=True)
    high_volume = high_volume[:50]

    dns_suspicious = []
    for host, info in dns_by_host.items():
        suspicious = False
        reasons = []
        if info["query_count"] > DNS_HIGH_QUERY_THRESHOLD:
            suspicious = True
            reasons.append(f"high query volume ({info['query_count']})")
        if info["long_domains"]:
            suspicious = True
            reasons.append(f"long domain names ({len(info['long_domains'])})")
        if info["nxdomain_count"] > 50:
            suspicious = True
            reasons.append(f"high NXDOMAIN ({info['nxdomain_count']})")
        if suspicious:
            # Determine anomaly sub-type
            if info["nxdomain_count"] > 50:
                anom_type = ANOM_DNS_ABUSE
                confidence = "Real" if info["nxdomain_count"] > 200 else "Suspected"
                severity = "high" if info["nxdomain_count"] > 200 else "medium"
                reason_detail = (f"Host generated {info['nxdomain_count']} NXDOMAIN responses, which is {info['nxdomain_count']//50}x the baseline threshold of 50. "
                                 "High NXDOMAIN rates indicate Domain Generation Algorithm (DGA) malware or misconfigured DNS clients.")
            elif info["long_domains"]:
                anom_type = ANOM_DNS_TUNNEL
                confidence = "Suspected"
                severity = "medium"
                reason_detail = (f"Host sent {len(info['long_domains'])} DNS queries with domain names exceeding {DNS_LONG_DOMAIN_LEN} characters. "
                                 "Long subdomains can encode data for DNS tunneling exfiltration (e.g., iodine, dnscat2). "
                                 f"Sample: {info['long_domains'][0][:80]}...")
            else:
                anom_type = ANOM_DNS_ABUSE
                confidence = "Suspected"
                severity = "low"
                reason_detail = (f"Host generated {info['query_count']} DNS queries in the monitoring window, "
                                 f"which is {info['query_count']//DNS_HIGH_QUERY_THRESHOLD}x the baseline of {DNS_HIGH_QUERY_THRESHOLD}. "
                                 "High query volumes may indicate beaconing, tunneling, or simply heavy browsing.")

            dns_suspicious.append({
                "src_ip": host,
                "query_count": info["query_count"],
                "long_domain_count": len(info["long_domains"]),
                "nxdomain_count": info["nxdomain_count"],
                "sample_domains": info["domains"][:10],
                "sample_long_domains": info["long_domains"][:5],
                "reasons": reasons,
                "src_internal": is_internal(host),
                "src_asset": _asset_label(host, asset_map),
                # Classification
                "anomaly_type": anom_type,
                "confidence": confidence,
                "severity": severity,
                "detection_type": "statistical",
                "reasoning": reason_detail,
            })
    dns_suspicious.sort(key=lambda x: x["query_count"], reverse=True)

    tls_list = []
    for (src, dst), info in deprecated_tls.items():
        tls_list.append({
            "src_ip": src, "dest_ip": dst,
            "count": info["count"],
            "versions": list(info["versions"]),
            "snis": list(info["snis"])[:5],
            "src_internal": is_internal(src),
            "dest_internal": is_internal(dst),
            "src_asset": _asset_label(src, asset_map),
            "dest_asset": _asset_label(dst, asset_map),
            # Classification
            "anomaly_type": ANOM_DEPRECATED_CRYPTO,
            "confidence": "Real",
            "severity": "high" if info["count"] > 50 else "medium",
            "detection_type": "rule-based",
            "reasoning": f"{'TLS' if 'TLS' in str(info['versions']) else 'SSL'} version {', '.join(info['versions'])} is deprecated per IETF RFC 8996. "
                         f"Observed {info['count']} connections using this insecure protocol. "
                         f"Vulnerable to BEAST, POODLE, and CRIME attacks. "
                         + (f"No SNI present — indicates old/embedded software or deliberate evasion." if not info["snis"]
                            else f"SNI: {', '.join(list(info['snis'])[:3])}"),
        })
    tls_list.sort(key=lambda x: x["count"], reverse=True)

    unusual_ports = unusual_ports[:50]

    applayer_list = []
    for event_name, info in applayer_anomalies.items():
        applayer_list.append({
            "event": event_name,
            "count": info["count"],
            "unique_sources": len(info["sources"]),
            "unique_dests": len(info["dests"]),
            "sample_sources": list(info["sources"])[:10],
            "timestamps": info["timestamps"][:5],
            # Classification
            "anomaly_type": ANOM_PROTOCOL_VIOLATION,
            "confidence": "Suspected",
            "severity": "medium" if info["count"] > 10 else "low",
            "detection_type": "protocol-based",
            "reasoning": f"Application-layer protocol decoder detected '{event_name}' anomaly "
                         f"{info['count']} times from {len(info['sources'])} unique source(s). "
                         "This indicates malformed protocol data, parser evasion, or implementation bugs.",
        })
    applayer_list.sort(key=lambda x: x["count"], reverse=True)

    # Build unified "real anomalies" list — everything above confidence threshold
    real_anomalies = []
    for item in nmap_list:
        if item["confidence"] in ("Real", "Suspected"):
            real_anomalies.append(_build_unified_entry(item, "nmap"))
    for item in high_volume:
        if item["confidence"] in ("Real", "Suspected"):
            real_anomalies.append(_build_unified_entry(item, "high_volume"))
    for item in dns_suspicious:
        if item["confidence"] in ("Real", "Suspected"):
            real_anomalies.append(_build_unified_entry(item, "dns"))
    for item in tls_list:
        if item["confidence"] in ("Real", "Suspected"):
            real_anomalies.append(_build_unified_entry(item, "tls"))
    for item in unusual_ports[:20]:
        if item["confidence"] in ("Real", "Suspected"):
            real_anomalies.append(_build_unified_entry(item, "unusual_port"))

    # Sort by severity priority
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    real_anomalies.sort(key=lambda x: sev_order.get(x["severity"], 4))

    total = (len(nmap_list) + len(high_volume) + len(dns_suspicious)
             + len(tls_list) + len(unusual_ports) + len(applayer_list))

    return {
        "nmap_scanning": nmap_list,
        "high_volume_flows": high_volume,
        "dns_suspicious": dns_suspicious,
        "deprecated_tls": tls_list,
        "unusual_ports": unusual_ports,
        "applayer_anomalies": applayer_list,
        "real_anomalies": real_anomalies,
        "summary": {
            "total_anomalies": total,
            "real_anomaly_count": len([a for a in real_anomalies if a["confidence"] == "Real"]),
            "suspected_count": len([a for a in real_anomalies if a["confidence"] == "Suspected"]),
            "nmap_scanners": len(nmap_list),
            "high_volume_count": len(high_volume),
            "dns_suspicious_hosts": len(dns_suspicious),
            "deprecated_tls_pairs": len(tls_list),
            "unusual_port_count": len(unusual_ports),
            "applayer_anomaly_types": len(applayer_list),
        },
    }


def _build_unified_entry(item, category):
    """Build a unified anomaly entry for the real anomalies list."""
    entry = {
        "category": category,
        "anomaly_type": item.get("anomaly_type", "Unknown"),
        "confidence": item.get("confidence", "Suspected"),
        "severity": item.get("severity", "medium"),
        "detection_type": item.get("detection_type", "unknown"),
        "reasoning": item.get("reasoning", ""),
        "src_ip": item.get("src_ip", ""),
        "dest_ip": item.get("dest_ip", ""),
        "src_asset": item.get("src_asset", ""),
        "dest_asset": item.get("dest_asset", ""),
        "src_internal": item.get("src_internal", False),
        "timestamp": "",
    }
    # Category-specific fields
    if category == "nmap":
        entry["dest_ip"] = f"{item['target_count']} targets"
        entry["port"] = "22 (SSH)"
        entry["protocol"] = "SSH"
        entry["occurrences"] = item["target_count"]
        entry["first_seen"] = item["timestamps"][0] if item["timestamps"] else ""
        entry["last_seen"] = item["timestamps"][-1] if item["timestamps"] else ""
        entry["timestamp"] = entry["first_seen"]
    elif category == "high_volume":
        entry["port"] = str(item.get("dest_port", ""))
        entry["protocol"] = item.get("app_proto", "")
        entry["occurrences"] = 1
        entry["bytes"] = item.get("bytes", 0)
        entry["first_seen"] = item.get("timestamp", "")
        entry["last_seen"] = item.get("timestamp", "")
        entry["timestamp"] = entry["first_seen"]
    elif category == "dns":
        entry["dest_ip"] = "DNS"
        entry["port"] = "53"
        entry["protocol"] = "DNS"
        entry["occurrences"] = item.get("query_count", 0)
        entry["first_seen"] = ""
        entry["last_seen"] = ""
    elif category == "tls":
        entry["port"] = "443"
        entry["protocol"] = ", ".join(item.get("versions", []))
        entry["occurrences"] = item.get("count", 0)
        entry["first_seen"] = ""
        entry["last_seen"] = ""
    elif category == "unusual_port":
        entry["port"] = str(item.get("port", ""))
        entry["protocol"] = item.get("app_proto", "")
        entry["occurrences"] = 1
        entry["first_seen"] = item.get("timestamp", "")
        entry["last_seen"] = item.get("timestamp", "")
        entry["timestamp"] = entry["first_seen"]
    return entry


def _high_volume_reasoning(src, dst, b_out, b_in, total, src_int, dst_int):
    """Generate forensic reasoning for high-volume flow."""
    direction = "outbound" if b_out > b_in else "inbound"
    ratio = max(b_out, b_in) / max(min(b_out, b_in), 1)
    mb = total / (1024 * 1024)

    parts = [f"Flow transferred {mb:.1f} MB total, exceeding the {HIGH_VOLUME_BYTES//(1024*1024)} MB threshold."]

    if src_int and not dst_int:
        if direction == "outbound" and ratio > 5:
            parts.append(f"Internal host sent {b_out/(1024*1024):.1f} MB to external destination (ratio {ratio:.1f}:1 out:in). "
                         "Strongly asymmetric outbound transfer is a data exfiltration indicator.")
        elif direction == "inbound":
            parts.append(f"Internal host received {b_in/(1024*1024):.1f} MB from external source. "
                         "Large inbound transfer could be legitimate download or malware staging.")
    elif src_int and dst_int:
        parts.append("Internal-to-internal high volume transfer. Could indicate lateral data movement or large file share access.")

    return " ".join(parts)
