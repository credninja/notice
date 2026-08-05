"""
IP investigation API.
Provides comprehensive activity timeline for a given IP address.
"""

from collections import defaultdict
from bottle import request
from eve_reader import iter_events, is_internal, is_ipv4
from analyzers.enrich import get_asset_map, build_hostname_map, enrich_ip
from analyzers.geoip import lookup_batch


def register(app):

    @app.get("/api/investigate/<ip>")
    def api_investigate(ip):
        if not is_ipv4(ip):
            return {"error": "Invalid IPv4 address"}

        minutes = int(request.query.get("minutes", 1440)) or 1440

        timeline = []
        connections = defaultdict(lambda: {
            "bytes_in": 0, "bytes_out": 0, "flow_count": 0, "protocols": set(), "app_protos": set()
        })
        dns_queries = defaultdict(lambda: {"count": 0, "rrtypes": set()})
        alerts = []
        anomalies = []
        tls_sessions = defaultdict(lambda: {"count": 0, "versions": set(), "ja4s": set()})
        http_requests = []
        ssh_events = []
        file_transfers = []
        risk_indicators = []
        first_seen = None
        last_seen = None

        for ev in iter_events(ip_filter=ip, minutes=minutes):
            etype = ev["event_type"]
            src = ev.get("src_ip", "")
            dst = ev.get("dest_ip", "")
            ts = ev.get("timestamp", "")

            if not first_seen or ts < first_seen:
                first_seen = ts
            if not last_seen or ts > last_seen:
                last_seen = ts

            peer = dst if src == ip else src
            direction = "outbound" if src == ip else "inbound"

            # Timeline entry (limit to 500 for performance)
            if len(timeline) < 500:
                summary = _event_summary(ev, etype, direction)
                timeline.append({
                    "timestamp": ts,
                    "event_type": etype,
                    "direction": direction,
                    "peer": peer,
                    "summary": summary,
                })

            if etype == "flow":
                flow = ev.get("flow", {})
                c = connections[peer]
                if src == ip:
                    c["bytes_out"] += flow.get("bytes_toserver", 0)
                    c["bytes_in"] += flow.get("bytes_toclient", 0)
                else:
                    c["bytes_in"] += flow.get("bytes_toserver", 0)
                    c["bytes_out"] += flow.get("bytes_toclient", 0)
                c["flow_count"] += 1
                proto = ev.get("proto", "")
                if proto:
                    c["protocols"].add(proto)
                app_proto = ev.get("app_proto", "")
                if app_proto and app_proto != "failed":
                    c["app_protos"].add(app_proto)

            elif etype == "alert":
                alert = ev.get("alert", {})
                alerts.append({
                    "timestamp": ts,
                    "peer": peer,
                    "direction": direction,
                    "signature": alert.get("signature", ""),
                    "signature_id": alert.get("signature_id"),
                    "severity": alert.get("severity", 3),
                    "category": alert.get("category", ""),
                })

            elif etype == "dns":
                dns = ev.get("dns", {})
                if dns.get("type") == "request":
                    for q in dns.get("queries", []):
                        rrname = q.get("rrname", "")
                        d = dns_queries[rrname]
                        d["count"] += 1
                        d["rrtypes"].add(q.get("rrtype", ""))

            elif etype == "tls":
                tls = ev.get("tls", {})
                sni = tls.get("sni", peer)
                t = tls_sessions[sni]
                t["count"] += 1
                version = tls.get("version", "")
                if version:
                    t["versions"].add(version)
                ja4 = tls.get("ja4", "")
                if ja4:
                    t["ja4s"].add(ja4)

            elif etype == "http":
                http = ev.get("http", {})
                if len(http_requests) < 100:
                    http_requests.append({
                        "timestamp": ts,
                        "direction": direction,
                        "hostname": http.get("hostname", ""),
                        "url": http.get("url", ""),
                        "method": http.get("http_method", ""),
                        "status": http.get("status"),
                        "user_agent": http.get("http_user_agent", "")[:100],
                    })

            elif etype == "ssh":
                ssh = ev.get("ssh", {})
                if len(ssh_events) < 50:
                    ssh_events.append({
                        "timestamp": ts,
                        "peer": peer,
                        "direction": direction,
                        "client_software": ssh.get("client", {}).get("software_version", ""),
                        "server_software": ssh.get("server", {}).get("software_version", ""),
                    })

            elif etype == "fileinfo":
                fi = ev.get("fileinfo", {})
                if len(file_transfers) < 50:
                    file_transfers.append({
                        "timestamp": ts,
                        "direction": direction,
                        "peer": peer,
                        "filename": fi.get("filename", ""),
                        "size": fi.get("size", 0),
                        "sha256": fi.get("sha256", ""),
                    })

            elif etype == "anomaly":
                anom = ev.get("anomaly", {})
                if len(anomalies) < 50:
                    anomalies.append({
                        "timestamp": ts,
                        "peer": peer,
                        "event": anom.get("event", ""),
                        "type": anom.get("type", ""),
                        "layer": anom.get("layer", ""),
                    })

        # Compute risk indicators
        if alerts:
            risk_indicators.append({
                "type": "alert",
                "severity": "high",
                "message": f"{len(alerts)} security alert(s) triggered",
            })
        if http_requests:
            risk_indicators.append({
                "type": "plaintext",
                "severity": "medium",
                "message": f"Uses plaintext HTTP ({len(http_requests)} requests)",
            })
        for se in ssh_events:
            if "nmap" in se.get("client_software", "").lower():
                risk_indicators.append({
                    "type": "scanning",
                    "severity": "high",
                    "message": f"Nmap scanning detected (client: {se['client_software']})",
                })
                break
        deprecated_tls_found = False
        for sni, info in tls_sessions.items():
            for v in info["versions"]:
                if v in {"TLSv1", "TLS 1.0", "TLS 1.1", "SSLv3"}:
                    deprecated_tls_found = True
                    break
        if deprecated_tls_found:
            risk_indicators.append({
                "type": "deprecated_tls",
                "severity": "medium",
                "message": "Uses deprecated TLS version",
            })
        if anomalies:
            risk_indicators.append({
                "type": "anomaly",
                "severity": "low",
                "message": f"{len(anomalies)} protocol anomalies detected",
            })

        # Enrich connections with hostname, service, geo, owner
        asset_map = get_asset_map()
        hostname_map = build_hostname_map(minutes=minutes)
        ext_ips = [p for p in connections.keys() if not is_internal(p)]
        geo_map = lookup_batch(ext_ips[:100]) if ext_ips else {}

        # Also enrich the investigated IP itself
        ip_enriched = enrich_ip(ip, asset_map=asset_map, hostname_map=hostname_map, geo_map=geo_map)

        conn_list = []
        for peer_ip, info in connections.items():
            e = enrich_ip(peer_ip, asset_map=asset_map, hostname_map=hostname_map, geo_map=geo_map)
            conn_list.append({
                "ip": peer_ip,
                "internal": is_internal(peer_ip),
                "bytes_in": info["bytes_in"],
                "bytes_out": info["bytes_out"],
                "flow_count": info["flow_count"],
                "protocols": list(info["protocols"]),
                "app_protos": list(info["app_protos"]),
                "owner": e["owner"], "hostname": e["hostname"],
                "service": e["service"], "country": e["country"],
                "country_code": e["country_code"], "geo_tag": e["geo_tag"],
                "isp": e["isp"],
            })
        conn_list.sort(key=lambda x: x["bytes_in"] + x["bytes_out"], reverse=True)

        # DNS queries list
        dns_list = []
        for rrname, info in dns_queries.items():
            dns_list.append({
                "rrname": rrname,
                "count": info["count"],
                "rrtypes": list(info["rrtypes"]),
            })
        dns_list.sort(key=lambda x: x["count"], reverse=True)

        # TLS sessions list
        tls_list = []
        for sni, info in tls_sessions.items():
            tls_list.append({
                "sni": sni,
                "count": info["count"],
                "versions": list(info["versions"]),
                "ja4s": list(info["ja4s"])[:5],
            })
        tls_list.sort(key=lambda x: x["count"], reverse=True)

        # Unique services
        services = set()
        for c in conn_list:
            services.update(c["app_protos"])

        # Sort timeline newest-first
        timeline.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        return {
            "ip": ip,
            "internal": is_internal(ip),
            "owner": ip_enriched["owner"],
            "hostname": ip_enriched["hostname"],
            "service": ip_enriched["service"],
            "country": ip_enriched["country"],
            "country_code": ip_enriched["country_code"],
            "geo_tag": ip_enriched["geo_tag"],
            "isp": ip_enriched["isp"],
            "first_seen": first_seen,
            "last_seen": last_seen,
            "risk_indicators": risk_indicators,
            "timeline": timeline[:500],
            "connections": conn_list[:100],
            "total_connections": len(conn_list),
            "dns_queries": dns_list[:50],
            "alerts": alerts,
            "anomalies": anomalies[:50],
            "tls_sessions": tls_list[:50],
            "http_requests": http_requests[:100],
            "ssh_events": ssh_events[:50],
            "file_transfers": file_transfers[:50],
            "services": list(services),
        }


def _event_summary(ev, etype, direction):
    if etype == "flow":
        flow = ev.get("flow", {})
        total = flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
        return f"{ev.get('app_proto', ev.get('proto', ''))} flow ({total} bytes)"
    elif etype == "alert":
        return ev.get("alert", {}).get("signature", "Alert")
    elif etype == "dns":
        dns = ev.get("dns", {})
        queries = dns.get("queries", [{}])
        return f"DNS {dns.get('type', '')} {queries[0].get('rrname', '')}"
    elif etype == "http":
        http = ev.get("http", {})
        return f"{http.get('http_method', 'GET')} {http.get('hostname', '')}{http.get('url', '/')}"
    elif etype == "tls":
        tls = ev.get("tls", {})
        return f"TLS {tls.get('version', '')} -> {tls.get('sni', '')}"
    elif etype == "ssh":
        ssh = ev.get("ssh", {})
        return f"SSH client={ssh.get('client', {}).get('software_version', '')}"
    elif etype == "anomaly":
        return ev.get("anomaly", {}).get("event", "anomaly")
    elif etype == "fileinfo":
        fi = ev.get("fileinfo", {})
        return f"File: {fi.get('filename', '')} ({fi.get('size', 0)} bytes)"
    return etype
