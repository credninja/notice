"""
Dashboard API — top source IPs, top destination IPs, bandwidth stats,
Priority Assets submenu, with full IP enrichment (hostname, service, geo, owner).
"""

from collections import defaultdict, Counter
from bottle import request
from eve_reader import iter_events, is_internal, is_ipv4, is_noise_alert, is_monitored
from db import get_db, cache_get, cache_set
from analyzers.enrich import (
    get_asset_map, build_hostname_map, enrich_ip, identify_service, format_label
)
from analyzers.geoip import lookup_batch
from analyzers.suricata_rules import get_rule_stats


def register(app):

    @app.get("/api/dashboard")
    def api_dashboard():
        minutes = int(request.query.get("minutes", 60)) or 60
        cache_key = f"dashboard_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        data = _build_dashboard(minutes)
        cache_set(cache_key, data, ttl=120)
        return data

    @app.get("/api/dashboard/trends")
    def api_trends():
        """Compare current period vs previous period."""
        minutes = int(request.query.get("minutes", 60)) or 60
        cache_key = f"trends_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        from analyzers.trends import compute_trends
        data = compute_trends(minutes=minutes)
        cache_set(cache_key, data, ttl=120)
        return data

    @app.get("/api/dashboard/engine-stats")
    def api_engine_stats():
        """Live detection engine statistics — EPS, verdict rates, rule metrics."""
        minutes = int(request.query.get("minutes", 60)) or 60
        cache_key = f"engine_stats_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        data = _build_engine_stats(minutes)
        cache_set(cache_key, data, ttl=30)
        return data

    @app.get("/api/dashboard/priority-assets")
    def api_priority_assets():
        minutes = int(request.query.get("minutes", 60)) or 60
        cache_key = f"priority_assets_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        data = _build_priority_assets(minutes)
        cache_set(cache_key, data, ttl=60)
        return data


def _build_dashboard(minutes):
    src_stats = defaultdict(lambda: {"bytes_out": 0, "bytes_in": 0, "flows": 0, "peers": set(), "protos": set()})
    dst_stats = defaultdict(lambda: {"bytes_in": 0, "bytes_out": 0, "flows": 0, "peers": set(), "protos": set()})
    pair_stats = defaultdict(lambda: {"bytes": 0, "flows": 0, "protos": set()})
    proto_bytes = defaultdict(int)
    total_bytes = 0
    total_flows = 0
    alert_count = 0

    asset_map = get_asset_map()

    for ev in iter_events(event_types={"flow", "alert"}, minutes=minutes):
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        if not is_ipv4(src) or not is_ipv4(dst):
            continue

        is_multicast = dst.startswith("224.") or dst.startswith("255.") or dst == "0.0.0.0"
        etype = ev["event_type"]

        if etype == "alert":
            if not is_multicast:
                sig = ev.get("alert", {}).get("signature", "")
                cat = ev.get("alert", {}).get("category", "")
                if is_noise_alert(sig, cat):
                    continue
                if is_internal(src) and is_internal(dst) and "Port Scan" in sig:
                    if not is_monitored(src) and not is_monitored(dst):
                        continue
                alert_count += 1
            continue

        flow = ev.get("flow", {})
        b_out = flow.get("bytes_toserver", 0)
        b_in = flow.get("bytes_toclient", 0)
        b_total = b_out + b_in
        app_proto = ev.get("app_proto", "")

        s = src_stats[src]
        s["bytes_out"] += b_out
        s["bytes_in"] += b_in
        s["flows"] += 1
        if app_proto and app_proto != "failed":
            s["protos"].add(app_proto)

        if is_multicast:
            s["peers"].add(dst)
            continue

        total_bytes += b_total
        total_flows += 1

        if app_proto and app_proto != "failed":
            proto_bytes[app_proto] += b_total

        s["peers"].add(dst)

        d = dst_stats[dst]
        d["bytes_in"] += b_out
        d["bytes_out"] += b_in
        d["flows"] += 1
        d["peers"].add(src)
        if app_proto and app_proto != "failed":
            d["protos"].add(app_proto)

        pair_key = tuple(sorted([src, dst]))
        p = pair_stats[pair_key]
        p["bytes"] += b_total
        p["flows"] += 1
        if app_proto and app_proto != "failed":
            p["protos"].add(app_proto)

    # Build enrichment: hostname map + geo for all external IPs
    hostname_map = build_hostname_map(minutes=minutes)
    all_ext_ips = [ip for ip in (set(src_stats.keys()) | set(dst_stats.keys())) if not is_internal(ip)]
    geo_map = lookup_batch(all_ext_ips[:200]) if all_ext_ips else {}

    def _enrich(ip):
        return enrich_ip(ip, asset_map=asset_map, hostname_map=hostname_map, geo_map=geo_map)

    def _label(ip):
        return format_label(ip, asset_map=asset_map, hostname_map=hostname_map)

    # Top sources
    top_sources = sorted(src_stats.items(), key=lambda x: x[1]["bytes_out"], reverse=True)[:20]
    top_src_list = []
    for ip, info in top_sources:
        e = _enrich(ip)
        top_src_list.append({
            "ip": ip, "label": _label(ip), "internal": is_internal(ip),
            "bytes_out": info["bytes_out"], "bytes_in": info["bytes_in"],
            "bytes_total": info["bytes_out"] + info["bytes_in"],
            "flows": info["flows"], "peer_count": len(info["peers"]),
            "protocols": list(info["protos"]),
            "owner": e["owner"], "hostname": e["hostname"], "service": e["service"],
            "country": e["country"], "country_code": e["country_code"],
            "geo_tag": e["geo_tag"], "isp": e["isp"],
        })

    # Top destinations
    top_dests = sorted(dst_stats.items(), key=lambda x: x[1]["bytes_in"], reverse=True)[:20]
    top_dst_list = []
    for ip, info in top_dests:
        e = _enrich(ip)
        top_dst_list.append({
            "ip": ip, "label": _label(ip), "internal": is_internal(ip),
            "bytes_in": info["bytes_in"], "bytes_out": info["bytes_out"],
            "bytes_total": info["bytes_in"] + info["bytes_out"],
            "flows": info["flows"], "peer_count": len(info["peers"]),
            "protocols": list(info["protos"]),
            "owner": e["owner"], "hostname": e["hostname"], "service": e["service"],
            "country": e["country"], "country_code": e["country_code"],
            "geo_tag": e["geo_tag"], "isp": e["isp"],
        })

    # Top conversations
    top_pairs = sorted(pair_stats.items(), key=lambda x: x[1]["bytes"], reverse=True)[:20]
    top_pair_list = []
    for pair, info in top_pairs:
        es = _enrich(pair[0])
        ed = _enrich(pair[1])
        top_pair_list.append({
            "src": pair[0], "dst": pair[1],
            "src_label": _label(pair[0]), "dst_label": _label(pair[1]),
            "src_internal": is_internal(pair[0]), "dst_internal": is_internal(pair[1]),
            "src_owner": es["owner"], "dst_owner": ed["owner"],
            "src_service": es["service"], "dst_service": ed["service"],
            "dst_hostname": ed["hostname"], "dst_country": ed["country"],
            "dst_country_code": ed["country_code"], "dst_geo_tag": ed["geo_tag"],
            "bytes": info["bytes"], "flows": info["flows"],
            "protocols": list(info["protos"]),
        })

    proto_sorted = sorted(proto_bytes.items(), key=lambda x: -x[1])
    proto_list = [{"protocol": p, "bytes": b} for p, b in proto_sorted[:15]]

    return {
        "top_sources": top_src_list,
        "top_destinations": top_dst_list,
        "top_conversations": top_pair_list,
        "protocol_bandwidth": proto_list,
        "summary": {
            "total_bytes": total_bytes,
            "total_flows": total_flows,
            "alert_count": alert_count,
            "unique_sources": len(src_stats),
            "unique_destinations": len(dst_stats),
        },
    }


def _build_priority_assets(minutes):
    conn = get_db()
    asset_rows = conn.execute("SELECT * FROM assets WHERE scope='internal'").fetchall()
    conn.close()
    asset_map_full = {r["ip"]: dict(r) for r in asset_rows}

    activity = defaultdict(lambda: {
        "bytes_in": 0, "bytes_out": 0, "flows": 0,
        "protocols": set(), "peers_int": set(), "peers_ext": set(),
        "dest_ports": set(), "alerts": [], "alert_count": 0,
    })

    for ev in iter_events(minutes=minutes):
        etype = ev.get("event_type")
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        if not is_ipv4(src) or not is_ipv4(dst):
            continue

        for ip in (src, dst):
            if ip not in asset_map_full:
                continue
            if etype == "flow":
                flow = ev.get("flow", {})
                a = activity[ip]
                if ip == src:
                    a["bytes_out"] += flow.get("bytes_toserver", 0)
                    a["bytes_in"] += flow.get("bytes_toclient", 0)
                else:
                    a["bytes_in"] += flow.get("bytes_toserver", 0)
                    a["bytes_out"] += flow.get("bytes_toclient", 0)
                a["flows"] += 1
                proto = ev.get("app_proto", "")
                if proto and proto != "failed":
                    a["protocols"].add(proto)
                peer = dst if ip == src else src
                dp = ev.get("dest_port", 0)
                if dp:
                    a["dest_ports"].add(dp)
                if is_internal(peer):
                    a["peers_int"].add(peer)
                else:
                    a["peers_ext"].add(peer)
            elif etype == "alert":
                alert = ev.get("alert", {})
                a = activity[ip]
                a["alert_count"] += 1
                if len(a["alerts"]) < 5:
                    a["alerts"].append({
                        "signature": alert.get("signature", ""),
                        "severity": alert.get("severity", 3),
                        "sid": alert.get("signature_id", 0),
                        "timestamp": ev.get("timestamp", ""),
                    })

    assets_out = []
    for ip, asset_info in asset_map_full.items():
        act = activity[ip]
        if not act["flows"] and not act["alert_count"]:
            continue
        risk = 0
        risk_factors = []
        crit_alerts = sum(1 for a in act["alerts"] if a["severity"] <= 1)
        high_alerts = sum(1 for a in act["alerts"] if a["severity"] == 2)
        if crit_alerts:
            risk += min(crit_alerts * 15, 40)
            risk_factors.append(f"{crit_alerts} critical alert(s)")
        if high_alerts:
            risk += min(high_alerts * 8, 25)
            risk_factors.append(f"{high_alerts} high alert(s)")
        if act["alert_count"] > 5:
            risk += 10
            risk_factors.append(f"{act['alert_count']} total alerts")
        ext_peers = len(act["peers_ext"])
        if ext_peers > 50:
            risk += 15
            risk_factors.append(f"high external exposure ({ext_peers} peers)")
        elif ext_peers > 20:
            risk += 8
            risk_factors.append(f"moderate external exposure ({ext_peers} peers)")
        total_mb = (act["bytes_in"] + act["bytes_out"]) / (1024 * 1024)
        if total_mb > 500:
            risk += 10
            risk_factors.append(f"high traffic volume ({total_mb:.0f} MB)")
        risk = min(risk, 100)
        priority = "critical" if risk >= 60 else "high" if risk >= 35 else "medium" if risk >= 15 else "low"

        assets_out.append({
            "ip": ip,
            "owner": asset_info.get("owner", ""),
            "hostname": asset_info.get("hostname", ""),
            "asset_type": asset_info.get("asset_type", ""),
            "department": asset_info.get("department", ""),
            "bytes_in": act["bytes_in"], "bytes_out": act["bytes_out"],
            "bytes_total": act["bytes_in"] + act["bytes_out"],
            "flows": act["flows"],
            "protocols": sorted(list(act["protocols"])),
            "internal_peers": len(act["peers_int"]),
            "external_peers": ext_peers,
            "active_ports": sorted(list(act["dest_ports"]))[:15],
            "alert_count": act["alert_count"], "alerts": act["alerts"],
            "risk_score": risk, "risk_factors": risk_factors, "priority": priority,
        })

    assets_out.sort(key=lambda x: -x["risk_score"])

    return {
        "assets": assets_out,
        "summary": {
            "total_monitored": len(assets_out),
            "critical_count": sum(1 for a in assets_out if a["priority"] == "critical"),
            "high_count": sum(1 for a in assets_out if a["priority"] == "high"),
            "medium_count": sum(1 for a in assets_out if a["priority"] == "medium"),
            "low_count": sum(1 for a in assets_out if a["priority"] == "low"),
        },
    }


def _build_engine_stats(minutes):
    """Calculate live detection engine metrics — EPS, verdict rates, rule stats."""
    from datetime import datetime
    from collections import Counter as Ctr

    # EPS calculation — measure from actual event timestamps
    total_events = 0
    alert_count = 0
    alert_by_sev = Ctr()
    alert_sids = Ctr()
    first_ts = None
    last_ts = None

    for ev in iter_events(minutes=minutes):
        total_events += 1
        ts = ev.get("timestamp", "")
        if ts:
            if not first_ts or ts < first_ts:
                first_ts = ts
            if not last_ts or ts > last_ts:
                last_ts = ts

        if ev.get("event_type") == "alert":
            alert_count += 1
            alert = ev.get("alert", {})
            alert_by_sev[alert.get("severity", 3)] += 1
            alert_sids[alert.get("signature_id", 0)] += 1

    # Calculate EPS
    duration_sec = 0
    if first_ts and last_ts:
        try:
            t1 = datetime.fromisoformat(first_ts)
            t2 = datetime.fromisoformat(last_ts)
            duration_sec = max((t2 - t1).total_seconds(), 1)
        except Exception:
            duration_sec = max(minutes * 60, 1)
    else:
        duration_sec = max(minutes * 60, 1)

    eps = round(total_events / duration_sec, 1) if duration_sec > 0 else 0

    # Verdict stats from DB
    conn = get_db()
    verdicts = conn.execute("SELECT verdict, COUNT(*) as cnt FROM alert_verdicts GROUP BY verdict").fetchall()
    verdict_map = {r["verdict"]: r["cnt"] for r in verdicts}
    total_verdicts = sum(verdict_map.values())
    conn.close()

    tp = verdict_map.get("true_positive", 0)
    fp = verdict_map.get("false_positive", 0)
    investigating = verdict_map.get("investigating", 0)

    # Rates (only meaningful if verdicts exist)
    tp_rate = round(tp / total_verdicts * 100, 1) if total_verdicts > 0 else None
    fp_rate = round(fp / total_verdicts * 100, 1) if total_verdicts > 0 else None

    # Unique rules that fired
    unique_rules_fired = len(alert_sids)

    # Authoritative rule counts come from parsing the live rules file — same
    # source the Monitoring tab uses, so the two views stay consistent.
    rule_stats = get_rule_stats()
    total_rules_loaded = rule_stats.get("total_active", 0)
    custom_rules_count = rule_stats.get("custom_rules", 0)

    return {
        "eps": eps,
        "total_events": total_events,
        "duration_seconds": round(duration_sec),
        "alert_count": alert_count,
        "alert_rate_pct": round(alert_count / total_events * 100, 2) if total_events else 0,
        "unique_rules_fired": unique_rules_fired,
        "total_rules_loaded": total_rules_loaded,
        "custom_rules": custom_rules_count,
        "severity_breakdown": {
            "critical": alert_by_sev.get(1, 0),
            "high": alert_by_sev.get(2, 0),
            "medium": alert_by_sev.get(3, 0),
            "low": sum(v for k, v in alert_by_sev.items() if k >= 4),
        },
        "verdicts": {
            "total_classified": total_verdicts,
            "true_positive": tp,
            "false_positive": fp,
            "investigating": investigating,
            "tp_rate": tp_rate,
            "fp_rate": fp_rate,
            "unclassified": alert_count - total_verdicts if alert_count > total_verdicts else 0,
        },
        "note": "FP/TP rates improve as analysts classify more alerts via Drill-Down > Evidence tab.",
    }
