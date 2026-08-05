"""
Network graph and summary API endpoints.
Ported from the original app.py.
"""

from collections import defaultdict
from bottle import request
from eve_reader import iter_events, is_internal, is_ipv4, SUBNET
from db import cache_get, cache_set


def register(app):

    @app.get("/api/graph")
    def api_graph():
        minutes = int(request.query.get("minutes", 60)) or 60
        cache_key = f"graph_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached

        data = _build_graph(minutes)
        cache_set(cache_key, data, ttl=300)
        return data

    @app.get("/api/summary")
    def api_summary():
        cached = cache_get("summary")
        if cached:
            return cached

        data = _build_summary()
        cache_set("summary", data, ttl=300)
        return data


def _build_graph(minutes=None):
    edges = defaultdict(lambda: {
        "bytes": 0, "packets": 0, "protocols": set(), "app_protos": set(), "count": 0
    })
    alerts_by_pair = defaultdict(list)
    node_info = {}

    for ev in iter_events(event_types={"flow", "alert"}, minutes=minutes):
        etype = ev["event_type"]
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")

        if not src or not dst or not is_ipv4(src) or not is_ipv4(dst):
            continue

        is_multicast = dst.startswith("224.") or dst.startswith("255.") or dst == "0.0.0.0"

        if etype == "alert":
            if not is_multicast:
                alert = ev.get("alert", {})
                pair_key = tuple(sorted([src, dst]))
                alerts_by_pair[pair_key].append({
                    "signature": alert.get("signature", ""),
                    "severity": alert.get("severity", 3),
                    "category": alert.get("category", ""),
                    "src": src, "dst": dst,
                })
            continue

        # flow events
        src_int = is_internal(src)
        dst_int = is_internal(dst)

        # Track source node even for multicast traffic
        if is_multicast:
            if src_int or dst_int:
                if src not in node_info:
                    node_info[src] = {"internal": is_internal(src), "connections": 0}
                node_info[src]["connections"] += 1
            continue

        if not src_int and not dst_int:
            continue

        proto = ev.get("proto", "")
        app_proto = ev.get("app_proto", "")
        flow = ev.get("flow", {})

        key = tuple(sorted([src, dst]))
        e = edges[key]
        e["bytes"] += flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
        e["packets"] += flow.get("pkts_toserver", 0) + flow.get("pkts_toclient", 0)
        e["count"] += 1
        if proto:
            e["protocols"].add(proto)
        if app_proto and app_proto != "failed":
            e["app_protos"].add(app_proto)

        for ip in (src, dst):
            if ip not in node_info:
                node_info[ip] = {"internal": is_internal(ip), "connections": 0}
            node_info[ip]["connections"] += 1

    # Limit to top 200 nodes by connection count to keep UI responsive
    MAX_NODES = 200
    top_ips = sorted(node_info.keys(), key=lambda ip: node_info[ip]["connections"], reverse=True)[:MAX_NODES]
    top_set = set(top_ips)

    nodes = []
    for ip in top_ips:
        info = node_info[ip]
        has_alerts = any(ip in pk for pk in alerts_by_pair)
        nodes.append({
            "id": ip,
            "internal": info["internal"],
            "connections": info["connections"],
            "has_alerts": has_alerts,
        })

    links = []
    for (src, dst), info in edges.items():
        if src not in top_set or dst not in top_set:
            continue
        pair_key = tuple(sorted([src, dst]))
        link_alerts = alerts_by_pair.get(pair_key, [])
        links.append({
            "source": src, "target": dst,
            "bytes": info["bytes"], "packets": info["packets"], "count": info["count"],
            "protocols": list(info["protocols"]),
            "app_protos": list(info["app_protos"]),
            "has_alerts": len(link_alerts) > 0,
            "alerts": link_alerts[:5],
        })

    return {"nodes": nodes, "links": links}


def _build_summary():
    internal_ips = set()
    external_ips = set()
    proto_counts = defaultdict(int)
    event_counts = defaultdict(int)
    alert_list = []
    total_bytes = 0

    for ev in iter_events():
        etype = ev.get("event_type")
        event_counts[etype] += 1
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")

        if not is_ipv4(src) or not is_ipv4(dst):
            continue

        if is_internal(src):
            internal_ips.add(src)
        if is_internal(dst):
            internal_ips.add(dst)
        if not is_internal(src):
            external_ips.add(src)
        if not is_internal(dst):
            external_ips.add(dst)

        if etype == "flow":
            flow = ev.get("flow", {})
            total_bytes += flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
            app_proto = ev.get("app_proto", "")
            if app_proto and app_proto != "failed":
                proto_counts[app_proto] += 1

        if etype == "alert":
            alert = ev.get("alert", {})
            alert_list.append({
                "timestamp": ev.get("timestamp", ""),
                "src": src, "dst": dst,
                "signature": alert.get("signature", ""),
                "severity": alert.get("severity", 3),
                "category": alert.get("category", ""),
            })

    return {
        "internal_hosts": len(internal_ips),
        "external_hosts": len(external_ips),
        "total_bytes": total_bytes,
        "protocol_breakdown": dict(proto_counts),
        "event_type_counts": dict(event_counts),
        "recent_alerts": alert_list[-20:],
        "monitored_subnet": str(SUBNET),
    }
