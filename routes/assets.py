"""
Asset management API.
Tracks identified vs unidentified assets for both internal and external networks.
"""

from collections import defaultdict
from bottle import request, response
from db import get_db, safe_update, cache_get, cache_set
from eve_reader import iter_events, is_internal, is_ipv4, SUBNET


def _invalidate_asset_caches():
    """Drop ALL cached views that depend on asset metadata."""
    conn = get_db()
    conn.execute("""DELETE FROM cache WHERE
        key LIKE 'network_purdue_%' OR key LIKE 'asset_discovery_%' OR key LIKE 'network_map_%'
        OR key LIKE 'alerts_%' OR key LIKE 'correlate_%' OR key LIKE 'priority_assets_%'
        OR key LIKE 'monitoring_combined_%' OR key LIKE 'asset_detail_%'
        OR key LIKE 'rule_coverage_full' OR key LIKE 'rule_stats'
        OR key LIKE 'rule_analytics_%' OR key LIKE 'dashboard_%'
        OR key LIKE 'asset_inventory_%'""")
    conn.commit()
    conn.close()
    try:
        from analyzers.rule_coverage import _clear_cache
        _clear_cache()
    except Exception:
        pass


def register(app):

    @app.get("/api/assets")
    def list_assets():
        scope = request.query.get("scope", "")
        conn = get_db()
        if scope:
            rows = conn.execute("SELECT * FROM assets WHERE scope = ? ORDER BY ip", (scope,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM assets ORDER BY scope, ip").fetchall()
        conn.close()
        return {"assets": [dict(r) for r in rows]}

    @app.post("/api/assets")
    def create_asset():
        data = request.json or {}
        ip = data.get("ip", "").strip()
        if not ip:
            response.status = 400
            return {"error": "IP is required"}
        conn = get_db()
        existing = conn.execute("SELECT id FROM assets WHERE ip = ?", (ip,)).fetchone()
        if existing:
            response.status = 409
            return {"error": "Asset already exists"}
        scope = data.get("scope", "internal" if is_internal(ip) else "external")
        conn.execute(
            "INSERT INTO assets (ip, hostname, owner, department, asset_type, scope, os, notes, purdue_level) VALUES (?,?,?,?,?,?,?,?,?)",
            (ip, data.get("hostname", ""), data.get("owner", ""), data.get("department", ""),
             data.get("asset_type", "workstation"), scope, data.get("os", ""), data.get("notes", ""),
             data.get("purdue_level", "")),
        )
        conn.commit()
        result = dict(conn.execute("SELECT * FROM assets WHERE ip = ?", (ip,)).fetchone())
        conn.close()
        _invalidate_asset_caches()
        response.status = 201
        return result

    @app.put("/api/assets/<asset_id:int>")
    def update_asset(asset_id):
        data = request.json or {}
        conn = get_db()
        row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
        if not row:
            conn.close()
            response.status = 404
            return {"error": "Asset not found"}
        _ASSET_FIELDS = frozenset({"ip", "hostname", "owner", "department", "asset_type", "scope", "os", "notes", "business_critical", "purdue_level"})
        safe_update("assets", _ASSET_FIELDS, data, "WHERE id = ?", [asset_id],
                     extra_sets=["updated_at = datetime('now','localtime')"])
        result = dict(conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone())
        conn.close()
        _invalidate_asset_caches()
        return result

    @app.put("/api/assets/bulk_purdue")
    def bulk_purdue():
        data = request.json or {}
        ids = data.get("ids", [])
        level = (data.get("purdue_level") or "").strip()
        if not isinstance(ids, list) or not ids:
            response.status = 400
            return {"error": "ids list is required"}
        ids = [int(i) for i in ids if str(i).isdigit()]
        if not ids:
            return {"updated": 0}
        valid_levels = {"", "0", "1", "2", "3", "3.5", "4", "5"}
        if level not in valid_levels:
            response.status = 400
            return {"error": f"invalid purdue_level: {level}"}
        conn = get_db()
        placeholders = ",".join("?" for _ in ids)
        conn.execute(
            f"UPDATE assets SET purdue_level = ?, updated_at = datetime('now','localtime') WHERE id IN ({placeholders})",
            [level] + ids,
        )
        conn.commit()
        conn.close()
        _invalidate_asset_caches()
        return {"updated": len(ids), "purdue_level": level}

    @app.delete("/api/assets/<asset_id:int>")
    def delete_asset(asset_id):
        conn = get_db()
        conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        conn.commit()
        conn.close()
        _invalidate_asset_caches()
        return {"ok": True}

    @app.get("/api/assets/discovery")
    def asset_discovery():
        """Discover all active IPs (internal + external), cross-reference with known assets."""
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"asset_discovery_v2_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached

        # Get known assets from DB, split by scope
        conn = get_db()
        rows = conn.execute("SELECT * FROM assets").fetchall()
        conn.close()
        known_internal = {}
        known_external = {}
        for r in rows:
            d = dict(r)
            scope = d.get("scope", "internal")
            if scope == "external":
                known_external[d["ip"]] = d
            else:
                known_internal[d["ip"]] = d

        # Discover active IPs from traffic
        internal_ips = defaultdict(lambda: _new_host_info())
        external_ips = defaultdict(lambda: _new_host_info())

        for ev in iter_events(event_types={"flow", "alert"}, minutes=minutes):
            src = ev.get("src_ip", "")
            dst = ev.get("dest_ip", "")
            if not is_ipv4(src) or not is_ipv4(dst):
                continue

            is_multicast = dst.startswith("224.") or dst.startswith("255.") or dst == "0.0.0.0"

            etype = ev["event_type"]
            ts = ev.get("timestamp", "")
            src_int = is_internal(src)
            dst_int = is_internal(dst)

            # We only care about traffic where at least one side is internal
            if not src_int and not dst_int:
                continue

            flow = ev.get("flow", {}) if etype == "flow" else {}
            total_bytes = flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
            proto = ev.get("proto", "")
            app_proto = ev.get("app_proto", "")

            # For multicast, only track the source IP (don't add multicast dst as a host)
            if is_multicast:
                if src_int:
                    bucket = internal_ips
                else:
                    bucket = external_ips
                info = bucket[src]
                if not info["first_seen"] or ts < info["first_seen"]:
                    info["first_seen"] = ts
                if not info["last_seen"] or ts > info["last_seen"]:
                    info["last_seen"] = ts
                if etype == "alert":
                    info["has_alerts"] = True
                if etype == "flow":
                    info["bytes"] += total_bytes
                    info["flows"] += 1
                    if proto:
                        info["protocols"].add(proto)
                    if app_proto and app_proto != "failed":
                        info["app_protos"].add(app_proto)
                continue

            # Process each IP for unicast traffic
            for ip, peer, ip_is_internal in [(src, dst, src_int), (dst, src, dst_int)]:
                bucket = internal_ips if ip_is_internal else external_ips
                info = bucket[ip]

                if not info["first_seen"] or ts < info["first_seen"]:
                    info["first_seen"] = ts
                if not info["last_seen"] or ts > info["last_seen"]:
                    info["last_seen"] = ts

                if etype == "alert":
                    info["has_alerts"] = True

                if etype == "flow":
                    info["bytes"] += total_bytes
                    info["flows"] += 1
                    if proto:
                        info["protocols"].add(proto)
                    if app_proto and app_proto != "failed":
                        info["app_protos"].add(app_proto)
                    if peer and is_ipv4(peer):
                        if is_internal(peer):
                            info["internal_peers"].add(peer)
                        else:
                            info["external_peers"].add(peer)

        # Build the 2x2 structure
        int_identified, int_unidentified = _classify(internal_ips, known_internal)
        ext_identified, ext_unidentified = _classify(external_ips, known_external)

        result = {
            "internal": {
                "identified": int_identified,
                "unidentified": int_unidentified,
            },
            "external": {
                "identified": ext_identified,
                "unidentified": ext_unidentified,
            },
            "summary": {
                "internal_active": len(internal_ips),
                "internal_identified": len(int_identified),
                "internal_unidentified": len(int_unidentified),
                "external_active": len(external_ips),
                "external_identified": len(ext_identified),
                "external_unidentified": len(ext_unidentified),
                "total_known_assets": len(known_internal) + len(known_external),
            },
        }
        cache_set(cache_key, result, ttl=120)
        return result


def _new_host_info():
    return {
        "bytes": 0, "flows": 0, "protocols": set(), "app_protos": set(),
        "first_seen": None, "last_seen": None,
        "internal_peers": set(), "external_peers": set(),
        "has_alerts": False,
    }


def _classify(active_ips, known_assets):
    """Split active IPs into identified (in known_assets) and unidentified."""
    identified = []
    unidentified = []

    for ip, info in sorted(active_ips.items()):
        entry = {
            "ip": ip,
            "bytes": info["bytes"],
            "flows": info["flows"],
            "protocols": list(info["protocols"]),
            "app_protos": list(info["app_protos"]),
            "first_seen": info["first_seen"],
            "last_seen": info["last_seen"],
            "internal_peer_count": len(info["internal_peers"]),
            "external_peer_count": len(info["external_peers"]),
            "has_alerts": info["has_alerts"],
        }
        if ip in known_assets:
            asset = known_assets[ip]
            entry["asset_id"] = asset["id"]
            entry["owner"] = asset.get("owner", "")
            entry["hostname"] = asset.get("hostname", "")
            entry["department"] = asset.get("department", "")
            entry["asset_type"] = asset.get("asset_type", "")
            entry["os"] = asset.get("os", "")
            entry["notes"] = asset.get("notes", "")
            identified.append(entry)
        else:
            unidentified.append(entry)

    # Include known assets not seen in traffic (inactive)
    for ip, asset in known_assets.items():
        if ip not in active_ips:
            identified.append({
                "ip": ip,
                "bytes": 0, "flows": 0, "protocols": [], "app_protos": [],
                "first_seen": None, "last_seen": None,
                "internal_peer_count": 0, "external_peer_count": 0,
                "has_alerts": False, "inactive": True,
                "asset_id": asset["id"],
                "owner": asset.get("owner", ""),
                "hostname": asset.get("hostname", ""),
                "department": asset.get("department", ""),
                "asset_type": asset.get("asset_type", ""),
                "os": asset.get("os", ""),
                "notes": asset.get("notes", ""),
            })

    unidentified.sort(key=lambda x: x["bytes"], reverse=True)
    return identified, unidentified
