"""
Threat Intelligence & Advanced Detection API.
Bundles: JA4 fingerprints, DNS tunneling, beaconing, MAC tracking.
"""

from collections import defaultdict
from bottle import request, response
from db import cache_get, cache_set, get_db
from eve_reader import iter_events, is_internal, is_ipv4
from analyzers.threat_intel import scan_ja4_fingerprints, get_external_ip_intel
from analyzers.dns_tunnel import detect_dns_tunneling
from analyzers.beacon import detect_beaconing


def register(app):

    # ── JA4 Fingerprints ───────────────────────────────────────

    @app.get("/api/intel/ja4")
    def api_ja4():
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"ja4_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = scan_ja4_fingerprints(minutes=minutes)
        cache_set(cache_key, result, ttl=300)
        return result

    @app.get("/api/intel/external")
    def api_external_intel():
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"ext_intel_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return {"ips": cached}
        result = get_external_ip_intel(minutes=minutes)
        cache_set(cache_key, result, ttl=300)
        return {"ips": result}

    # ── DNS Tunneling ───────────────────────────────────────────

    @app.get("/api/intel/dns-tunnel")
    def api_dns_tunnel():
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"dns_tunnel_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = detect_dns_tunneling(minutes=minutes)
        cache_set(cache_key, result, ttl=300)
        return result

    # ── Beaconing ───────────────────────────────────────────────

    @app.get("/api/intel/beacons")
    def api_beacons():
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"beacons_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = detect_beaconing(minutes=minutes)
        cache_set(cache_key, result, ttl=300)
        return result

    # ── MAC Address Tracking (DHCP) ─────────────────────────────

    @app.get("/api/intel/mac-tracking")
    def api_mac_tracking():
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"mac_track_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = _track_mac_addresses(minutes=minutes)
        cache_set(cache_key, result, ttl=300)
        return result


def _track_mac_addresses(minutes=None):
    """
    Extract MAC-to-IP mappings from DHCP events.
    Detects: IP changes, MAC conflicts, rogue devices.
    """
    mac_history = defaultdict(lambda: {
        "ips": set(), "hostnames": set(), "events": [],
        "first_seen": None, "last_seen": None, "dhcp_types": defaultdict(int),
    })
    ip_to_mac = defaultdict(set)

    for ev in iter_events(event_types={"dhcp"}, minutes=minutes):
        dhcp = ev.get("dhcp", {})
        mac = dhcp.get("client_mac", "")
        assigned_ip = dhcp.get("assigned_ip", "")
        hostname = dhcp.get("hostname", "")
        dhcp_type = dhcp.get("dhcp_type", dhcp.get("type", ""))
        ts = ev.get("timestamp", "")

        if not mac:
            continue

        info = mac_history[mac]
        if assigned_ip:
            info["ips"].add(assigned_ip)
            ip_to_mac[assigned_ip].add(mac)
        if hostname:
            info["hostnames"].add(hostname)

        if not info["first_seen"] or ts < info["first_seen"]:
            info["first_seen"] = ts
        if not info["last_seen"] or ts > info["last_seen"]:
            info["last_seen"] = ts

        info["dhcp_types"][dhcp_type] += 1

        if len(info["events"]) < 20:
            info["events"].append({
                "timestamp": ts,
                "dhcp_type": dhcp_type,
                "assigned_ip": assigned_ip,
                "hostname": hostname,
                "src_ip": ev.get("src_ip", ""),
                "dest_ip": ev.get("dest_ip", ""),
            })

    # Cross-reference with known assets
    conn = get_db()
    known_assets = {}
    for row in conn.execute("SELECT ip, owner, hostname FROM assets"):
        known_assets[row["ip"]] = {"owner": row["owner"], "hostname": row["hostname"]}
    conn.close()

    # Build device list
    devices = []
    anomalies = []
    for mac, info in mac_history.items():
        ips = sorted(info["ips"])
        owners = set()
        for ip in ips:
            if ip in known_assets and known_assets[ip]["owner"]:
                owners.add(known_assets[ip]["owner"])

        device = {
            "mac": mac,
            "ips": ips,
            "ip_count": len(ips),
            "hostnames": list(info["hostnames"]),
            "owners": list(owners),
            "first_seen": info["first_seen"],
            "last_seen": info["last_seen"],
            "dhcp_types": dict(info["dhcp_types"]),
            "event_count": sum(info["dhcp_types"].values()),
            "recent_events": info["events"][-5:],
            "known": any(ip in known_assets for ip in ips),
        }
        devices.append(device)

        # Flag anomalies
        if len(ips) > 2:
            anomalies.append({
                "type": "ip_change",
                "severity": "medium",
                "mac": mac,
                "message": f"MAC {mac} used {len(ips)} different IPs: {', '.join(ips[:5])}",
                "ips": ips,
            })

    # Check for MAC conflicts (same IP, different MACs)
    for ip, macs in ip_to_mac.items():
        if len(macs) > 1:
            anomalies.append({
                "type": "mac_conflict",
                "severity": "high",
                "ip": ip,
                "message": f"IP {ip} seen with {len(macs)} different MACs: {', '.join(sorted(macs))}",
                "macs": sorted(macs),
            })

    # Detect unknown devices (MAC not mapped to any known asset)
    unknown_devices = [d for d in devices if not d["known"]]

    devices.sort(key=lambda x: x["event_count"], reverse=True)

    return {
        "devices": devices,
        "unknown_devices": unknown_devices,
        "anomalies": anomalies,
        "summary": {
            "total_macs": len(devices),
            "known_devices": len(devices) - len(unknown_devices),
            "unknown_devices": len(unknown_devices),
            "ip_changes": sum(1 for a in anomalies if a["type"] == "ip_change"),
            "mac_conflicts": sum(1 for a in anomalies if a["type"] == "mac_conflict"),
            "total_dhcp_events": sum(d["event_count"] for d in devices),
        },
    }
