"""
Asset behavioral baseline builder.

Scans eve.json over a long window (default 7 days) to learn each asset's
normal behavior, which the rule generator then uses to produce
asset-specific anomaly/threshold/pinning rules.
"""

from collections import defaultdict, Counter
from datetime import datetime
from eve_reader import iter_events, is_internal, is_ipv4
from db import get_db


def build_asset_baselines(minutes=10080):
    """
    Scan eve.json and return per-asset behavioral baseline dict.
    Returns: {ip: {listening_ports, dest_countries, ja3_hashes, ja4_hashes,
                   mac, active_hours, peak_flow_rate, top_dest_ports,
                   typical_user_agents, total_flows}}
    """
    # First, get GeoIP cache for country lookups
    conn = get_db()
    geo_map = {}
    for r in conn.execute("SELECT ip, country_code FROM geo_cache WHERE country_code != ''").fetchall():
        geo_map[r["ip"]] = r["country_code"]
    # Asset DB to filter
    assets = {r["ip"]: dict(r) for r in conn.execute("SELECT * FROM assets WHERE scope='internal'").fetchall()}
    conn.close()

    baselines = defaultdict(lambda: {
        "listening_ports": Counter(),       # port -> connection count
        "dest_countries": Counter(),         # country code -> count
        "ja3_hashes": Counter(),             # JA3 hash -> count
        "ja4_hashes": Counter(),             # JA4 hash -> count
        "mac_addresses": Counter(),          # MAC -> count
        "active_hours": set(),               # 0-23
        "minute_flow_count": defaultdict(int),  # minute -> flow count
        "top_dest_ports": Counter(),         # port -> count
        "user_agents": Counter(),            # UA -> count
        "tls_snis": Counter(),               # SNI -> count
        "total_flows": 0,
        "first_seen": None,
        "last_seen": None,
    })

    for ev in iter_events(minutes=minutes):
        etype = ev.get("event_type", "")
        ts = ev.get("timestamp", "")
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        sport = ev.get("src_port", 0)
        dport = ev.get("dest_port", 0)

        # Determine which asset this event relates to
        asset_ips = []
        if is_ipv4(src) and src in assets:
            asset_ips.append(("src", src))
        if is_ipv4(dst) and dst in assets:
            asset_ips.append(("dst", dst))

        if not asset_ips:
            continue

        # Hour of activity
        try:
            hour = int(ts[11:13])
        except (ValueError, IndexError):
            hour = -1

        for role, ip in asset_ips:
            b = baselines[ip]
            if not b["first_seen"] or ts < b["first_seen"]:
                b["first_seen"] = ts
            if not b["last_seen"] or ts > b["last_seen"]:
                b["last_seen"] = ts
            if 0 <= hour <= 23:
                b["active_hours"].add(hour)

            if etype == "flow":
                b["total_flows"] += 1
                # Listening port = port the asset is receiving on
                if role == "dst" and dport > 0:
                    b["listening_ports"][dport] += 1
                # Destination port the asset connects to
                if role == "src" and dport > 0:
                    b["top_dest_ports"][dport] += 1
                # Bucket flow rate by minute
                minute_key = ts[:16]  # YYYY-MM-DDTHH:MM
                b["minute_flow_count"][minute_key] += 1
                # Geographic: track country of the EXTERNAL peer
                peer_ip = dst if role == "src" else src
                if is_ipv4(peer_ip) and not is_internal(peer_ip):
                    cc = geo_map.get(peer_ip, "")
                    if cc:
                        b["dest_countries"][cc] += 1

            elif etype == "tls":
                tls = ev.get("tls", {})
                ja3 = tls.get("ja3", {})
                if isinstance(ja3, dict) and ja3.get("hash"):
                    b["ja3_hashes"][ja3["hash"]] += 1
                ja4 = tls.get("ja4")
                if ja4:
                    if isinstance(ja4, str):
                        b["ja4_hashes"][ja4] += 1
                    elif isinstance(ja4, dict) and ja4.get("hash"):
                        b["ja4_hashes"][ja4["hash"]] += 1
                sni = tls.get("sni", "")
                if sni:
                    b["tls_snis"][sni] += 1

            elif etype == "http":
                ua = ev.get("http", {}).get("http_user_agent", "")
                if ua:
                    b["user_agents"][ua[:200]] += 1

            elif etype == "dhcp":
                dhcp = ev.get("dhcp", {})
                # If this DHCP event assigned the IP to a MAC, record the mapping
                assigned = dhcp.get("assigned_ip", "") or dhcp.get("client_ip", "")
                client_mac = dhcp.get("client_mac", "")
                if assigned == ip and client_mac:
                    b["mac_addresses"][client_mac.lower()] += 1

    # Post-process: compute peak flow rate
    out = {}
    for ip, b in baselines.items():
        flow_rates = list(b["minute_flow_count"].values())
        peak = max(flow_rates) if flow_rates else 0
        avg = sum(flow_rates) / len(flow_rates) if flow_rates else 0

        # Determine the most likely MAC
        mac = None
        if b["mac_addresses"]:
            mac = b["mac_addresses"].most_common(1)[0][0]

        # Top JA3/JA4 (limit to top 8 to avoid rule bloat)
        top_ja3 = [h for h, _ in b["ja3_hashes"].most_common(8)]
        top_ja4 = [h for h, _ in b["ja4_hashes"].most_common(8)]

        # Top countries (limit 10)
        top_countries = [cc for cc, _ in b["dest_countries"].most_common(10)]

        # Listening ports observed >5 times
        listening = [p for p, c in b["listening_ports"].most_common(20) if c >= 5]
        # Top dest ports (>10 connections)
        top_dest = [p for p, c in b["top_dest_ports"].most_common(15) if c >= 10]

        # Off-hours = hours NOT in active_hours that have at least some general activity
        # Practically: active_hours determines business hours
        active_hours = sorted(b["active_hours"])

        out[ip] = {
            "listening_ports": listening,
            "top_dest_ports": top_dest,
            "dest_countries": top_countries,
            "ja3_hashes": top_ja3,
            "ja4_hashes": top_ja4,
            "mac_address": mac,
            "all_macs_observed": list(b["mac_addresses"].keys()),
            "active_hours": active_hours,
            "total_flows": b["total_flows"],
            "peak_flows_per_min": peak,
            "avg_flows_per_min": round(avg, 2),
            "first_seen": b["first_seen"],
            "last_seen": b["last_seen"],
            "baseline_minutes": minutes,
            "computed_at": datetime.now().isoformat(),
        }

    return out


def save_baselines(baselines):
    """Persist baselines to SQLite for later retrieval."""
    import json
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS asset_baselines (
            ip TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            updated_at TEXT DEFAULT (datetime('now','localtime'))
        )
    """)
    for ip, b in baselines.items():
        conn.execute(
            "INSERT OR REPLACE INTO asset_baselines (ip, data, updated_at) VALUES (?, ?, datetime('now','localtime'))",
            (ip, json.dumps(b))
        )
    conn.commit()
    conn.close()


def load_baselines():
    """Load all stored baselines."""
    import json
    conn = get_db()
    try:
        rows = conn.execute("SELECT ip, data, updated_at FROM asset_baselines").fetchall()
    except Exception:
        conn.close()
        return {}
    conn.close()
    out = {}
    for r in rows:
        try:
            d = json.loads(r["data"])
            d["_updated_at"] = r["updated_at"]
            out[r["ip"]] = d
        except Exception:
            continue
    return out


def refresh_and_save(minutes=10080):
    """Compute baselines and persist them. Returns summary stats."""
    baselines = build_asset_baselines(minutes=minutes)
    save_baselines(baselines)
    return {
        "asset_count": len(baselines),
        "minutes_scanned": minutes,
        "summary": {
            ip: {
                "listening_ports": len(b["listening_ports"]),
                "countries_seen": len(b["dest_countries"]),
                "ja3_fingerprints": len(b["ja3_hashes"]),
                "mac_known": b["mac_address"] is not None,
                "total_flows": b["total_flows"],
            } for ip, b in baselines.items()
        }
    }
