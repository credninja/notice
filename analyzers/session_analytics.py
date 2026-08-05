"""
Session Analytics — Arkime-inspired network session analysis.

Provides: connection graph, protocol analytics, session timeline,
top talkers, file transfer tracking, and extended protocol decoding.

All data sourced from Suricata's eve.json — no extra capture needed.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from eve_reader import iter_events, is_internal, is_ipv4

IST = timezone(timedelta(hours=5, minutes=30))

ALL_EVENT_TYPES = {
    "flow", "alert", "dns", "http", "tls", "fileinfo",
    "ssh", "snmp", "dhcp", "quic", "sip", "ike", "anomaly", "mdns",
}

PROTO_LABELS = {
    "flow": "Network Flows",
    "alert": "Alerts",
    "dns": "DNS",
    "http": "HTTP",
    "tls": "TLS/SSL",
    "fileinfo": "File Transfers",
    "ssh": "SSH",
    "snmp": "SNMP",
    "dhcp": "DHCP",
    "quic": "QUIC",
    "sip": "SIP/VoIP",
    "ike": "IKE/VPN",
    "anomaly": "Anomalies",
    "mdns": "mDNS",
}


def get_connection_graph(minutes=60, max_edges=300):
    """Build a force-directed graph of network connections.

    Returns nodes (IPs) and edges (connections) with metadata for D3.js.
    """
    edge_map = defaultdict(lambda: {
        "bytes": 0, "packets": 0, "flows": 0,
        "protocols": set(), "alerts": 0,
    })
    node_map = defaultdict(lambda: {
        "bytes_out": 0, "bytes_in": 0, "flows": 0,
        "protocols": set(), "alerts": 0, "is_internal": False,
    })

    for ev in iter_events(event_types={"flow", "alert"}, minutes=minutes):
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        if not src or not dst or not is_ipv4(src) or not is_ipv4(dst):
            continue

        etype = ev.get("event_type", "")
        proto = ev.get("proto", "").upper()
        app_proto = ev.get("app_proto", "")

        if src > dst:
            key = (dst, src)
        else:
            key = (src, dst)

        if etype == "flow":
            fl = ev.get("flow", {})
            b_ts = fl.get("bytes_toserver", 0)
            b_tc = fl.get("bytes_toclient", 0)
            p_ts = fl.get("pkts_toserver", 0)
            p_tc = fl.get("pkts_toclient", 0)
            edge_map[key]["bytes"] += b_ts + b_tc
            edge_map[key]["packets"] += p_ts + p_tc
            edge_map[key]["flows"] += 1
            if app_proto and app_proto != "failed":
                edge_map[key]["protocols"].add(app_proto)
            elif proto:
                edge_map[key]["protocols"].add(proto)

            node_map[src]["bytes_out"] += b_ts
            node_map[src]["bytes_in"] += b_tc
            node_map[src]["flows"] += 1
            node_map[dst]["bytes_in"] += b_ts
            node_map[dst]["bytes_out"] += b_tc
            node_map[dst]["flows"] += 1
            node_map[src]["is_internal"] = is_internal(src)
            node_map[dst]["is_internal"] = is_internal(dst)

        elif etype == "alert":
            edge_map[key]["alerts"] += 1
            node_map[src]["alerts"] += 1
            node_map[dst]["alerts"] += 1
            node_map[src]["is_internal"] = is_internal(src)
            node_map[dst]["is_internal"] = is_internal(dst)

    sorted_edges = sorted(edge_map.items(), key=lambda x: x[1]["bytes"], reverse=True)
    top_edges = sorted_edges[:max_edges]
    used_ips = set()
    for (s, d), _ in top_edges:
        used_ips.add(s)
        used_ips.add(d)

    nodes = []
    for ip in used_ips:
        n = node_map[ip]
        nodes.append({
            "id": ip,
            "internal": n["is_internal"],
            "bytes": n["bytes_out"] + n["bytes_in"],
            "flows": n["flows"],
            "alerts": n["alerts"],
        })

    edges = []
    for (s, d), e in top_edges:
        edges.append({
            "source": s,
            "target": d,
            "bytes": e["bytes"],
            "packets": e["packets"],
            "flows": e["flows"],
            "protocols": list(e["protocols"])[:5],
            "alerts": e["alerts"],
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "total_flows": sum(e["flows"] for e in edge_map.values()),
        "total_bytes": sum(e["bytes"] for e in edge_map.values()),
        "total_edges": len(edge_map),
        "unique_ips": len(node_map),
    }


def get_protocol_analytics(minutes=60):
    """Protocol breakdown with traffic volume, session counts, and metadata."""
    proto_stats = defaultdict(lambda: {
        "count": 0, "bytes": 0, "src_ips": set(), "dst_ips": set(),
    })
    app_proto_stats = defaultdict(lambda: {"count": 0, "bytes": 0})
    transport_stats = defaultdict(int)

    for ev in iter_events(event_types=ALL_EVENT_TYPES, minutes=minutes):
        etype = ev.get("event_type", "")
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        proto = ev.get("proto", "").upper()

        if proto:
            transport_stats[proto] += 1

        proto_stats[etype]["count"] += 1
        if src:
            proto_stats[etype]["src_ips"].add(src)
        if dst:
            proto_stats[etype]["dst_ips"].add(dst)

        if etype == "flow":
            fl = ev.get("flow", {})
            b = fl.get("bytes_toserver", 0) + fl.get("bytes_toclient", 0)
            proto_stats[etype]["bytes"] += b
            app = ev.get("app_proto", "")
            if app and app != "failed":
                app_proto_stats[app]["count"] += 1
                app_proto_stats[app]["bytes"] += b

    protocols = []
    for et in sorted(proto_stats, key=lambda x: proto_stats[x]["count"], reverse=True):
        ps = proto_stats[et]
        protocols.append({
            "event_type": et,
            "label": PROTO_LABELS.get(et, et),
            "count": ps["count"],
            "bytes": ps["bytes"],
            "unique_sources": len(ps["src_ips"]),
            "unique_destinations": len(ps["dst_ips"]),
        })

    app_protos = []
    for ap in sorted(app_proto_stats, key=lambda x: app_proto_stats[x]["count"], reverse=True):
        app_protos.append({
            "protocol": ap,
            "sessions": app_proto_stats[ap]["count"],
            "bytes": app_proto_stats[ap]["bytes"],
        })

    transport = [{"protocol": k, "count": v} for k, v in
                 sorted(transport_stats.items(), key=lambda x: x[1], reverse=True)]

    return {
        "event_types": protocols,
        "app_protocols": app_protos,
        "transport": transport,
        "total_events": sum(p["count"] for p in protocols),
    }


def get_session_timeline(minutes=60, buckets=60):
    """Session count histogram bucketed over time."""
    now = datetime.now(IST)
    bucket_size = max(1, minutes // buckets)
    timeline = defaultdict(lambda: defaultdict(int))

    for ev in iter_events(event_types=ALL_EVENT_TYPES, minutes=minutes):
        ts_str = ev.get("timestamp", "")
        etype = ev.get("event_type", "")
        try:
            ts = datetime.fromisoformat(ts_str)
            age_min = (now - ts).total_seconds() / 60
            bucket_idx = int(age_min // bucket_size)
            bucket_time = now - timedelta(minutes=bucket_idx * bucket_size)
            key = bucket_time.strftime("%H:%M")
            timeline[key][etype] += 1
        except (ValueError, TypeError):
            continue

    result = []
    for i in range(buckets):
        t = now - timedelta(minutes=i * bucket_size)
        key = t.strftime("%H:%M")
        entry = {"time": key, "total": 0}
        for et in timeline.get(key, {}):
            entry[et] = timeline[key][et]
            entry["total"] += timeline[key][et]
        result.append(entry)

    result.reverse()
    return {"timeline": result, "bucket_minutes": bucket_size}


def get_top_talkers(minutes=60, limit=25):
    """Top bandwidth consumers and most active hosts."""
    host_stats = defaultdict(lambda: {
        "bytes_out": 0, "bytes_in": 0, "flows": 0,
        "alerts": 0, "internal": False, "protocols": set(),
        "peers": set(),
    })

    for ev in iter_events(event_types={"flow", "alert"}, minutes=minutes):
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        if not src or not dst:
            continue

        etype = ev.get("event_type", "")
        if etype == "flow":
            fl = ev.get("flow", {})
            b_ts = fl.get("bytes_toserver", 0)
            b_tc = fl.get("bytes_toclient", 0)
            app = ev.get("app_proto", "")

            host_stats[src]["bytes_out"] += b_ts
            host_stats[src]["bytes_in"] += b_tc
            host_stats[src]["flows"] += 1
            host_stats[src]["internal"] = is_internal(src)
            host_stats[src]["peers"].add(dst)
            if app and app != "failed":
                host_stats[src]["protocols"].add(app)

            host_stats[dst]["bytes_in"] += b_ts
            host_stats[dst]["bytes_out"] += b_tc
            host_stats[dst]["flows"] += 1
            host_stats[dst]["internal"] = is_internal(dst)
            host_stats[dst]["peers"].add(src)
            if app and app != "failed":
                host_stats[dst]["protocols"].add(app)

        elif etype == "alert":
            host_stats[src]["alerts"] += 1
            host_stats[dst]["alerts"] += 1

    by_bytes = sorted(host_stats.items(),
                      key=lambda x: x[1]["bytes_out"] + x[1]["bytes_in"], reverse=True)[:limit]

    result = []
    for ip, s in by_bytes:
        result.append({
            "ip": ip,
            "internal": s["internal"],
            "bytes_total": s["bytes_out"] + s["bytes_in"],
            "bytes_out": s["bytes_out"],
            "bytes_in": s["bytes_in"],
            "flows": s["flows"],
            "alerts": s["alerts"],
            "protocols": list(s["protocols"])[:8],
            "peers": len(s["peers"]),
        })

    return {"talkers": result, "total_hosts": len(host_stats)}


def get_file_transfers(minutes=60, limit=200):
    """Track files seen on the wire from Suricata's fileinfo events."""
    files = []

    for ev in iter_events(event_types={"fileinfo"}, minutes=minutes):
        fi = ev.get("fileinfo", {})
        http = ev.get("http", {})
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        ts = ev.get("timestamp", "")

        files.append({
            "timestamp": ts[:19].replace("T", " ") if ts else "",
            "filename": fi.get("filename", ""),
            "size": fi.get("size", 0),
            "magic": fi.get("magic", ""),
            "md5": fi.get("md5", ""),
            "sha256": fi.get("sha256", ""),
            "sha1": fi.get("sha1", ""),
            "stored": fi.get("stored", False),
            "hostname": http.get("hostname", ""),
            "url": http.get("url", "")[:200],
            "http_method": http.get("http_method", ""),
            "content_type": http.get("http_content_type", ""),
            "src_ip": src,
            "dest_ip": dst,
            "src_internal": is_internal(src) if src else False,
        })
        if len(files) >= limit:
            break

    by_type = defaultdict(int)
    total_size = 0
    for f in files:
        ct = f.get("content_type", "") or f.get("magic", "") or "unknown"
        by_type[ct.split(";")[0].strip()] += 1
        total_size += f.get("size", 0)

    return {
        "files": files,
        "total": len(files),
        "total_size": total_size,
        "by_type": dict(sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:15]),
    }


def get_extended_protocols(minutes=60):
    """Decode and summarize extended protocol metadata (SSH, SNMP, DHCP, QUIC, SIP, IKE)."""
    ssh_sessions = []
    snmp_queries = defaultdict(int)
    dhcp_leases = []
    quic_connections = []
    sip_calls = []
    ike_sessions = []

    for ev in iter_events(event_types={"ssh", "snmp", "dhcp", "quic", "sip", "ike"}, minutes=minutes):
        etype = ev.get("event_type", "")
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        ts = ev.get("timestamp", "")[:19].replace("T", " ")

        if etype == "ssh":
            ssh = ev.get("ssh", {})
            client = ssh.get("client", {})
            server = ssh.get("server", {})
            ssh_sessions.append({
                "timestamp": ts, "src_ip": src, "dest_ip": dst,
                "client_version": client.get("software_version", ""),
                "server_version": server.get("software_version", ""),
                "client_proto": client.get("proto_version", ""),
            })

        elif etype == "snmp":
            snmp = ev.get("snmp", {})
            community = snmp.get("community", "")
            pdu = snmp.get("pdu_type", "")
            snmp_queries[f"{community}|{pdu}"] += 1

        elif etype == "dhcp":
            dhcp = ev.get("dhcp", {})
            if dhcp.get("dhcp_type") in ("ack", "offer", "request"):
                dhcp_leases.append({
                    "timestamp": ts,
                    "type": dhcp.get("dhcp_type", ""),
                    "client_mac": dhcp.get("client_mac", ""),
                    "assigned_ip": dhcp.get("assigned_ip", ""),
                    "hostname": dhcp.get("hostname", ""),
                    "src_ip": src, "dest_ip": dst,
                })

        elif etype == "quic":
            q = ev.get("quic", {})
            quic_connections.append({
                "timestamp": ts, "src_ip": src, "dest_ip": dst,
                "sni": q.get("sni", ""),
                "version": q.get("version", ""),
                "ja4": q.get("ja4", ""),
            })

        elif etype == "sip":
            s = ev.get("sip", {})
            sip_calls.append({
                "timestamp": ts, "src_ip": src, "dest_ip": dst,
                "method": s.get("method", ""),
                "uri": s.get("uri", ""),
                "version": s.get("version", ""),
            })

        elif etype == "ike":
            ik = ev.get("ike", {})
            ike_sessions.append({
                "timestamp": ts, "src_ip": src, "dest_ip": dst,
                "version": f"{ik.get('version_major','')}.{ik.get('version_minor','')}",
                "role": ik.get("role", ""),
                "exchange_type": ik.get("exchange_type", 0),
                "init_spi": ik.get("init_spi", "")[:16],
            })

    snmp_list = [{"community": k.split("|")[0], "pdu_type": k.split("|")[1], "count": v}
                 for k, v in sorted(snmp_queries.items(), key=lambda x: x[1], reverse=True)[:30]]

    return {
        "ssh": {"sessions": ssh_sessions[:100], "total": len(ssh_sessions)},
        "snmp": {"queries": snmp_list, "total": sum(snmp_queries.values())},
        "dhcp": {"leases": dhcp_leases[:100], "total": len(dhcp_leases)},
        "quic": {"connections": quic_connections[:100], "total": len(quic_connections)},
        "sip": {"calls": sip_calls[:100], "total": len(sip_calls)},
        "ike": {"sessions": ike_sessions[:50], "total": len(ike_sessions)},
    }
