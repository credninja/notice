"""
Network communication map API.
"""

from collections import defaultdict
from bottle import request
from analyzers.network_map import build_network_map
from db import cache_get, cache_set, get_db
from eve_reader import iter_events, is_internal, is_ipv4


PURDUE_LEVELS = [
    {"id": "5", "name": "Enterprise Network", "desc": "Corporate WAN, cloud, ERP, email"},
    {"id": "4", "name": "Business Planning & Logistics", "desc": "Office IT, file shares, business apps"},
    {"id": "3.5", "name": "Industrial DMZ", "desc": "Patch servers, jump hosts, AV/proxy between IT and OT"},
    {"id": "3", "name": "Site Operations", "desc": "Historian, MES, engineering workstations"},
    {"id": "2", "name": "Area Supervisory Control", "desc": "HMI, SCADA, alarm servers"},
    {"id": "1", "name": "Basic Control", "desc": "PLCs, RTUs, IEDs, controllers"},
    {"id": "0", "name": "Process", "desc": "Sensors, actuators, motors, valves"},
]
LEVEL_ORDER = {lvl["id"]: i for i, lvl in enumerate(PURDUE_LEVELS)}
UNCLASSIFIED = "?"


def _level_rank(level):
    """Numeric rank used to detect cross-level direction (higher rank = higher PERA level)."""
    if not level or level == UNCLASSIFIED:
        return None
    try:
        return float(level)
    except (TypeError, ValueError):
        return None


def register(app):

    @app.get("/api/network/map")
    def api_network_map():
        minutes = int(request.query.get("minutes", 60)) or 60
        cache_key = f"network_map_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached

        data = build_network_map(minutes=minutes)
        cache_set(cache_key, data, ttl=300)
        return data

    @app.get("/api/network/purdue")
    def api_network_purdue():
        """Purdue Model (PERA) view — groups assets by purdue_level and reports cross-level traffic."""
        minutes = int(request.query.get("minutes", 0)) or None
        cache_key = f"network_purdue_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached

        conn = get_db()
        rows = conn.execute("SELECT * FROM assets").fetchall()
        conn.close()

        asset_by_ip = {}
        for r in rows:
            d = dict(r)
            level = (d.get("purdue_level") or "").strip() or UNCLASSIFIED
            d["purdue_level"] = level
            asset_by_ip[d["ip"]] = d

        # Aggregate flow stats per IP and per (src_ip, dst_ip) pair
        ip_stats = defaultdict(lambda: {"bytes": 0, "flows": 0, "has_alerts": False})
        pair_stats = defaultdict(lambda: {"bytes": 0, "flows": 0, "has_alerts": False, "app_protos": set()})

        for ev in iter_events(event_types={"flow", "alert"}, minutes=minutes):
            src = ev.get("src_ip", "")
            dst = ev.get("dest_ip", "")
            if not is_ipv4(src) or not is_ipv4(dst):
                continue
            if dst.startswith("224.") or dst.startswith("255.") or dst == "0.0.0.0":
                continue

            etype = ev["event_type"]
            if etype == "alert":
                ip_stats[src]["has_alerts"] = True
                ip_stats[dst]["has_alerts"] = True
                key = tuple(sorted([src, dst]))
                pair_stats[key]["has_alerts"] = True
                continue

            flow = ev.get("flow", {})
            total_bytes = flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
            ip_stats[src]["bytes"] += total_bytes
            ip_stats[src]["flows"] += 1
            ip_stats[dst]["bytes"] += total_bytes
            ip_stats[dst]["flows"] += 1

            key = tuple(sorted([src, dst]))
            p = pair_stats[key]
            p["bytes"] += total_bytes
            p["flows"] += 1
            ap = ev.get("app_proto", "")
            if ap and ap != "failed":
                p["app_protos"].add(ap)

        # Build per-level node lists (only registered assets show up — that's the point of tagging)
        levels_out = []
        for lvl in PURDUE_LEVELS:
            levels_out.append({
                "id": lvl["id"], "name": lvl["name"], "desc": lvl["desc"],
                "nodes": [],
            })
        unclassified_bucket = {"id": UNCLASSIFIED, "name": "Unclassified", "desc": "Registered assets with no Purdue level set", "nodes": []}

        level_index = {lvl["id"]: i for i, lvl in enumerate(levels_out)}

        for ip, asset in asset_by_ip.items():
            stats = ip_stats.get(ip, {"bytes": 0, "flows": 0, "has_alerts": False})
            node = {
                "ip": ip,
                "hostname": asset.get("hostname", ""),
                "owner": asset.get("owner", ""),
                "department": asset.get("department", ""),
                "asset_type": asset.get("asset_type", ""),
                "scope": asset.get("scope", "internal"),
                "business_critical": asset.get("business_critical", 0),
                "purdue_level": asset["purdue_level"],
                "bytes": stats["bytes"],
                "flows": stats["flows"],
                "has_alerts": stats["has_alerts"],
                "label": asset.get("owner") or asset.get("hostname") or ip,
            }
            if asset["purdue_level"] in level_index:
                levels_out[level_index[asset["purdue_level"]]]["nodes"].append(node)
            else:
                unclassified_bucket["nodes"].append(node)

        if unclassified_bucket["nodes"]:
            levels_out.append(unclassified_bucket)

        # Sort nodes within a level: critical first, then by bytes desc
        for lvl in levels_out:
            lvl["nodes"].sort(key=lambda n: (-int(n["business_critical"] or 0), -n["bytes"], n["ip"]))

        # Build edges only between registered assets (the diagram is about known segmentation)
        edges = []
        registered = set(asset_by_ip.keys())
        for (a, b), p in pair_stats.items():
            if a not in registered or b not in registered:
                continue
            la = asset_by_ip[a]["purdue_level"]
            lb = asset_by_ip[b]["purdue_level"]
            ra = _level_rank(la)
            rb = _level_rank(lb)
            same = la == lb
            cross_zone = False
            zone_jump = 0
            if ra is not None and rb is not None and not same:
                zone_jump = abs(ra - rb)
                # Skipping the IT/OT boundary (3.5) is a classic violation; flag jumps of >1 level too.
                if zone_jump > 1:
                    cross_zone = True
                # Direct Enterprise <-> OT (L4/L5 to L0/L1/L2) without DMZ
                if (ra >= 4 and rb <= 2) or (rb >= 4 and ra <= 2):
                    cross_zone = True
            edges.append({
                "source": a, "target": b,
                "source_level": la, "target_level": lb,
                "bytes": p["bytes"], "flows": p["flows"],
                "has_alerts": p["has_alerts"],
                "app_protos": sorted(p["app_protos"]),
                "same_level": same,
                "cross_zone": cross_zone,
                "zone_jump": zone_jump,
            })
        edges.sort(key=lambda e: (-int(e["cross_zone"]), -int(e["has_alerts"]), -e["flows"]))

        summary = {
            "total_assets": len(asset_by_ip),
            "tagged_assets": sum(1 for a in asset_by_ip.values() if a["purdue_level"] != UNCLASSIFIED),
            "untagged_assets": sum(1 for a in asset_by_ip.values() if a["purdue_level"] == UNCLASSIFIED),
            "level_counts": {lvl["id"]: len(lvl["nodes"]) for lvl in levels_out},
            "cross_zone_pairs": sum(1 for e in edges if e["cross_zone"]),
            "alerting_pairs": sum(1 for e in edges if e["has_alerts"]),
            "total_pairs": len(edges),
        }

        result = {"levels": levels_out, "edges": edges, "summary": summary}
        cache_set(cache_key, result, ttl=300)
        return result
