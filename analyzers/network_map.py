"""
Deep network communication map builder.
Classifies east-west vs north-south traffic, detects hubs,
frequent pairs, unusual paths, and enriches nodes with asset data.
"""

import math
from collections import defaultdict
from eve_reader import iter_events, is_internal, is_ipv4
from db import get_db

MAX_NODES = 200


def build_network_map(minutes=None):
    """Build an enriched network communication map from flow/alert events."""

    edges = defaultdict(lambda: {
        "bytes": 0, "packets": 0, "count": 0,
        "protocols": set(), "app_protos": set(),
    })
    node_info = defaultdict(lambda: {
        "connections": 0, "bytes": 0,
        "internal_peers": set(), "external_peers": set(),
        "app_protos": set(), "has_alerts": False,
    })
    alerts_by_pair = defaultdict(list)

    for ev in iter_events(event_types={"flow", "alert"}, minutes=minutes):
        etype = ev["event_type"]
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")

        if not src or not dst or not is_ipv4(src) or not is_ipv4(dst):
            continue

        is_multicast = dst.startswith("224.") or dst.startswith("255.") or dst == "0.0.0.0"

        src_int = is_internal(src)
        dst_int = is_internal(dst)

        if etype == "alert":
            if not is_multicast:
                alert = ev.get("alert", {})
                pair_key = tuple(sorted([src, dst]))
                alerts_by_pair[pair_key].append({
                    "signature": alert.get("signature", ""),
                    "severity": alert.get("severity", 3),
                })
                if src_int:
                    node_info[src]["has_alerts"] = True
                if dst_int:
                    node_info[dst]["has_alerts"] = True
            continue

        # For multicast, track source node only (no edge)
        if is_multicast:
            if src_int or dst_int:
                n = node_info[src]
                n["connections"] += 1
                flow = ev.get("flow", {})
                n["bytes"] += flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
                app_proto = ev.get("app_proto", "")
                if app_proto and app_proto != "failed":
                    n["app_protos"].add(app_proto)
            continue

        # Flow events — require at least one internal endpoint
        if not src_int and not dst_int:
            continue

        flow = ev.get("flow", {})
        total_bytes = flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
        total_pkts = flow.get("pkts_toserver", 0) + flow.get("pkts_toclient", 0)
        proto = ev.get("proto", "")
        app_proto = ev.get("app_proto", "")

        key = tuple(sorted([src, dst]))
        e = edges[key]
        e["bytes"] += total_bytes
        e["packets"] += total_pkts
        e["count"] += 1
        if proto:
            e["protocols"].add(proto)
        if app_proto and app_proto != "failed":
            e["app_protos"].add(app_proto)

        for ip in (src, dst):
            n = node_info[ip]
            n["connections"] += 1
            n["bytes"] += total_bytes
            peer = dst if ip == src else src
            if is_internal(peer):
                n["internal_peers"].add(peer)
            else:
                n["external_peers"].add(peer)
            if app_proto and app_proto != "failed":
                n["app_protos"].add(app_proto)

    # --- Asset enrichment ---
    conn = get_db()
    rows = conn.execute("SELECT ip, owner, hostname, asset_type, department FROM assets").fetchall()
    conn.close()
    asset_map = {r["ip"]: dict(r) for r in rows}

    # --- Node cap: top MAX_NODES by connections ---
    top_ips = sorted(node_info.keys(), key=lambda ip: node_info[ip]["connections"], reverse=True)[:MAX_NODES]
    top_set = set(top_ips)

    # --- Hub detection ---
    internal_conns = [node_info[ip]["connections"] for ip in top_ips if is_internal(ip)]
    if internal_conns:
        median_conn = sorted(internal_conns)[len(internal_conns) // 2]
        mean_conn = sum(internal_conns) / len(internal_conns)
        stdev_conn = math.sqrt(sum((c - mean_conn) ** 2 for c in internal_conns) / max(len(internal_conns), 1))
        hub_threshold = median_conn + 2 * stdev_conn
    else:
        hub_threshold = float("inf")

    # Top 3 by bytes (always considered hubs)
    top_by_bytes = set(
        sorted([ip for ip in top_ips if is_internal(ip)],
               key=lambda ip: node_info[ip]["bytes"], reverse=True)[:3]
    )

    max_conn = max((node_info[ip]["connections"] for ip in top_ips), default=1)

    # --- Build nodes ---
    nodes = []
    for ip in top_ips:
        info = node_info[ip]
        internal = is_internal(ip)
        is_hub = internal and (info["connections"] > hub_threshold or ip in top_by_bytes)
        hub_score = min(1.0, info["connections"] / max_conn) if is_hub else 0.0

        asset = asset_map.get(ip, {})
        owner = asset.get("owner", "")
        hostname = asset.get("hostname", "")
        if owner:
            label = f"{owner} ({ip})"
        elif hostname:
            label = f"{hostname} ({ip})"
        else:
            label = ip

        nodes.append({
            "id": ip,
            "internal": internal,
            "connections": info["connections"],
            "bytes": info["bytes"],
            "internal_peers": len(info["internal_peers"]),
            "external_peers": len(info["external_peers"]),
            "app_protos": list(info["app_protos"]),
            "has_alerts": info["has_alerts"],
            "is_hub": is_hub,
            "hub_score": round(hub_score, 2),
            "owner": owner,
            "hostname": hostname,
            "asset_type": asset.get("asset_type", ""),
            "department": asset.get("department", ""),
            "label": label,
        })

    # --- Build links with classification ---
    all_counts = [e["count"] for e in edges.values()]
    median_count = sorted(all_counts)[len(all_counts) // 2] if all_counts else 1
    frequent_threshold = max(median_count * 3, 5)

    # Track top frequent pairs
    frequent_candidates = []

    internal_links = []
    external_links = []
    unusual_paths = []
    ew_flows = 0
    ns_flows = 0
    ew_bytes = 0
    ns_bytes = 0

    for (ip_a, ip_b), info in edges.items():
        if ip_a not in top_set or ip_b not in top_set:
            continue

        a_int = is_internal(ip_a)
        b_int = is_internal(ip_b)
        edge_type = "internal" if (a_int and b_int) else "external"

        pair_key = tuple(sorted([ip_a, ip_b]))
        link_alerts = alerts_by_pair.get(pair_key, [])
        has_alerts = len(link_alerts) > 0
        is_frequent = info["count"] >= frequent_threshold

        # Unusual path detection (internal only)
        is_unusual = False
        unusual_reason = None
        if edge_type == "internal":
            if not info["app_protos"]:
                is_unusual = True
                unusual_reason = "no_protocol"
            elif info["count"] == 1:
                is_unusual = True
                unusual_reason = "single_occurrence"
            elif has_alerts:
                is_unusual = True
                unusual_reason = "has_alerts"

        link_data = {
            "source": ip_a, "target": ip_b,
            "bytes": info["bytes"], "packets": info["packets"], "count": info["count"],
            "protocols": list(info["protocols"]),
            "app_protos": list(info["app_protos"]),
            "has_alerts": has_alerts,
            "is_frequent": is_frequent,
            "is_unusual": is_unusual,
            "unusual_reason": unusual_reason,
            "edge_type": edge_type,
        }

        if edge_type == "internal":
            internal_links.append(link_data)
            ew_flows += info["count"]
            ew_bytes += info["bytes"]
        else:
            external_links.append(link_data)
            ns_flows += info["count"]
            ns_bytes += info["bytes"]

        if is_unusual:
            # Enrich with labels
            a_asset = asset_map.get(ip_a, {})
            b_asset = asset_map.get(ip_b, {})
            unusual_paths.append({
                "source": ip_a, "target": ip_b,
                "source_label": a_asset.get("owner") or ip_a,
                "target_label": b_asset.get("owner") or ip_b,
                "count": info["count"], "bytes": info["bytes"],
                "app_protos": list(info["app_protos"]),
                "reason": unusual_reason,
            })

        if is_frequent:
            frequent_candidates.append({
                "source": ip_a, "target": ip_b,
                "source_label": asset_map.get(ip_a, {}).get("owner") or ip_a,
                "target_label": asset_map.get(ip_b, {}).get("owner") or ip_b,
                "count": info["count"], "bytes": info["bytes"],
                "app_protos": list(info["app_protos"]),
                "edge_type": edge_type,
            })

    frequent_candidates.sort(key=lambda x: x["count"], reverse=True)
    frequent_pairs = frequent_candidates[:10]

    hubs = [
        {"ip": n["id"], "label": n["label"], "connections": n["connections"],
         "bytes": n["bytes"], "hub_score": n["hub_score"],
         "internal_peers": n["internal_peers"], "external_peers": n["external_peers"]}
        for n in nodes if n["is_hub"]
    ]
    hubs.sort(key=lambda x: x["connections"], reverse=True)

    int_nodes = sum(1 for n in nodes if n["internal"])
    ext_nodes = sum(1 for n in nodes if not n["internal"])

    return {
        "nodes": nodes,
        "internal_links": internal_links,
        "external_links": external_links,
        "hubs": hubs,
        "frequent_pairs": frequent_pairs,
        "unusual_paths": unusual_paths,
        "summary": {
            "east_west_flows": ew_flows,
            "north_south_flows": ns_flows,
            "east_west_bytes": ew_bytes,
            "north_south_bytes": ns_bytes,
            "hub_count": len(hubs),
            "frequent_pair_count": len(frequent_pairs),
            "unusual_path_count": len(unusual_paths),
            "total_internal_nodes": int_nodes,
            "total_external_nodes": ext_nodes,
        },
    }
