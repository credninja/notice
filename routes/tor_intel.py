"""
Tor traffic intelligence — surfaces flows and alerts that touch known
Tor exit nodes, plus list-management endpoints.

GET  /api/intel/tor-status         summary of the loaded exit list
POST /api/intel/tor-refresh        force a list refresh from check.torproject.org
GET  /api/intel/tor-traffic        counts + per-host breakdown for a time window
"""

from collections import defaultdict
from bottle import request, response
from eve_reader import iter_events, is_internal, is_ipv4
from db import cache_get, cache_set, get_db
from analyzers.tor_list import (
    is_tor_exit, refresh_tor_exits, get_count, get_last_refresh, needs_refresh,
)


def register(app):

    @app.get("/api/geoip/status")
    def geoip_status():
        """Reports whether GeoLite2 offline DBs are loaded and which mode we're in."""
        from analyzers import geoip_offline
        return geoip_offline.status()

    @app.get("/api/intel/tor-status")
    def tor_status():
        return {
            "total_exits": get_count(),
            "last_refresh": get_last_refresh(),
            "needs_refresh": needs_refresh(),
        }

    @app.post("/api/intel/tor-refresh")
    def tor_refresh():
        result = refresh_tor_exits()
        if result.get("error"):
            response.status = 502
        return result

    @app.get("/api/intel/tor-traffic")
    def tor_traffic():
        """For the given window, count flows and alerts that touch Tor exits.
        Returns: total_flows, total_bytes, total_alerts, internal hosts using
        Tor (with their byte counts), and the top Tor exit nodes seen."""
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"tor_traffic_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached

        # Pre-fetch asset map for owner enrichment
        try:
            conn = get_db()
            asset_rows = conn.execute("SELECT ip, owner, hostname FROM assets WHERE scope='internal'").fetchall()
            conn.close()
            owner_map = {r["ip"]: {"owner": r["owner"], "hostname": r["hostname"]} for r in asset_rows}
        except Exception:
            owner_map = {}

        total_flows = 0
        total_bytes = 0
        total_alerts = 0
        # Per-internal-host breakdown of Tor usage
        host_usage = defaultdict(lambda: {"flows": 0, "bytes": 0, "alerts": 0, "exits": set()})
        # Most-contacted exit nodes
        exit_usage = defaultdict(lambda: {"flows": 0, "bytes": 0, "alerts": 0, "internal_peers": set()})

        for ev in iter_events(event_types={"flow", "alert"}, minutes=minutes):
            src = ev.get("src_ip", "")
            dst = ev.get("dest_ip", "")
            if not is_ipv4(src) or not is_ipv4(dst):
                continue

            # Identify which side (if any) is a Tor exit
            src_tor = (not is_internal(src)) and is_tor_exit(src)
            dst_tor = (not is_internal(dst)) and is_tor_exit(dst)
            if not (src_tor or dst_tor):
                continue

            internal_ip = src if is_internal(src) else (dst if is_internal(dst) else "")
            tor_ip = src if src_tor else dst

            etype = ev["event_type"]
            if etype == "flow":
                flow = ev.get("flow", {}) or {}
                bytes_total = (flow.get("bytes_toserver", 0) or 0) + (flow.get("bytes_toclient", 0) or 0)
                total_flows += 1
                total_bytes += bytes_total
                if internal_ip:
                    h = host_usage[internal_ip]
                    h["flows"] += 1
                    h["bytes"] += bytes_total
                    h["exits"].add(tor_ip)
                e = exit_usage[tor_ip]
                e["flows"] += 1
                e["bytes"] += bytes_total
                if internal_ip:
                    e["internal_peers"].add(internal_ip)
            elif etype == "alert":
                total_alerts += 1
                if internal_ip:
                    host_usage[internal_ip]["alerts"] += 1
                exit_usage[tor_ip]["alerts"] += 1

        # Build per-host list with owner enrichment
        hosts = []
        for ip, h in host_usage.items():
            meta = owner_map.get(ip, {})
            hosts.append({
                "ip": ip,
                "owner": meta.get("owner", ""),
                "hostname": meta.get("hostname", ""),
                "flows": h["flows"],
                "bytes": h["bytes"],
                "alerts": h["alerts"],
                "distinct_exits": len(h["exits"]),
            })
        hosts.sort(key=lambda x: (-x["bytes"], -x["flows"]))

        exits = []
        for ip, e in exit_usage.items():
            exits.append({
                "ip": ip,
                "flows": e["flows"],
                "bytes": e["bytes"],
                "alerts": e["alerts"],
                "internal_peers": len(e["internal_peers"]),
            })
        exits.sort(key=lambda x: (-x["flows"], -x["bytes"]))

        result = {
            "summary": {
                "total_flows": total_flows,
                "total_bytes": total_bytes,
                "total_alerts": total_alerts,
                "internal_hosts_using_tor": len(host_usage),
                "distinct_exits_contacted": len(exit_usage),
                "loaded_exits": get_count(),
                "last_refresh": get_last_refresh(),
            },
            "internal_hosts": hosts[:20],
            "top_exits": exits[:20],
        }
        cache_set(cache_key, result, ttl=120)
        return result
