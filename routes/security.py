"""
Security events (IDS alerts) API.
"""

import json
from collections import defaultdict
from bottle import request, response
from eve_reader import iter_events, is_internal, is_noise_alert, is_monitored
from db import cache_get, cache_set, get_db
from analyzers.correlation import correlate_alerts, SIGNATURE_MAP


_PHASE_NAMES = {
    0: "Unmapped", 1: "Reconnaissance", 2: "Weaponization", 3: "Delivery",
    4: "Exploitation", 5: "Installation", 6: "Command & Control",
    7: "Actions on Objectives",
}


def _classify_phase(signature):
    sig_lower = (signature or "").lower()
    for m in SIGNATURE_MAP:
        if m["pattern"] in sig_lower:
            p = m.get("phase", 0)
            return p, m.get("phase_name", _PHASE_NAMES.get(p, "Unmapped"))
    return 0, "Unmapped"


def register(app):

    @app.get("/api/alerts/correlate")
    def api_correlate():
        """Attack chain correlation — groups alerts into kill chain phases."""
        minutes = int(request.query.get("minutes", 60)) or 60
        cache_key = f"correlate_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        data = correlate_alerts(minutes=minutes)
        cache_set(cache_key, data, ttl=120)
        return data

    @app.get("/api/alerts")
    def api_alerts():
        minutes = int(request.query.get("minutes", 60)) or 60
        cache_key = f"alerts_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached

        # Look up registered internal assets so we can flag "protected asset"
        # alerts for the search/scope filter on the Security tab.
        try:
            conn = get_db()
            rows = conn.execute("SELECT ip FROM assets WHERE scope='internal'").fetchall()
            conn.close()
            asset_ips = {r["ip"] for r in rows}
        except Exception:
            asset_ips = set()

        alerts = []
        by_phase = defaultdict(int)
        by_category = defaultdict(int)
        by_signature = defaultdict(int)
        timeline = defaultdict(lambda: {"count": 0, "phases": defaultdict(int)})
        # Phase A: dedup groups keyed by (signature_id, src_ip, dest_ip)
        groups = {}

        for ev in iter_events(event_types={"alert"}, minutes=minutes):
            alert = ev.get("alert", {})
            src = ev.get("src_ip", "")
            dst = ev.get("dest_ip", "")
            category = alert.get("category", "") or "uncategorized"
            signature = alert.get("signature", "")
            sid = alert.get("signature_id")
            ts = ev.get("timestamp", "")

            if is_noise_alert(signature, category):
                continue
            if is_internal(src) and is_internal(dst) and "Port Scan" in signature:
                if not is_monitored(src) and not is_monitored(dst):
                    continue

            phase, phase_name = _classify_phase(signature)
            dest_is_internal = is_internal(dst)

            entry = {
                "timestamp": ts,
                "src_ip": src,
                "dest_ip": dst,
                "src_port": ev.get("src_port"),
                "dest_port": ev.get("dest_port"),
                "proto": ev.get("proto", ""),
                "signature": signature,
                "signature_id": sid,
                "phase": phase,
                "phase_name": phase_name,
                "category": category,
                "action": alert.get("action", ""),
                "direction": ev.get("direction", ""),
                "app_proto": ev.get("app_proto", ""),
                "src_internal": is_internal(src),
                "dest_internal": dest_is_internal,
                "is_protected_asset": dest_is_internal and dst in asset_ips,
            }
            alerts.append(entry)
            by_phase[phase] += 1
            by_category[category] += 1
            by_signature[signature] += 1

            hour_key = ts[:13] if len(ts) >= 13 else ts
            bucket = timeline[hour_key]
            bucket["count"] += 1
            bucket["phases"][phase] += 1

            # Group key — collapses duplicates of same signature between the
            # same source and destination into one row.
            gkey = (sid or 0, src, dst)
            g = groups.get(gkey)
            if g is None:
                g = {
                    "key": f"{sid or 0}_{src}_{dst}",
                    "signature_id": sid,
                    "signature": signature,
                    "src_ip": src,
                    "dest_ip": dst,
                    "phase": phase,
                    "phase_name": phase_name,
                    "category": category,
                    "action": alert.get("action", ""),
                    "is_protected_asset": entry["is_protected_asset"],
                    "src_internal": entry["src_internal"],
                    "dest_internal": dest_is_internal,
                    "count": 0,
                    "first_seen": ts,
                    "last_seen": ts,
                    "ports": set(),
                    "protos": set(),
                }
                groups[gkey] = g
            g["count"] += 1
            if ts < g["first_seen"]:
                g["first_seen"] = ts
            if ts > g["last_seen"]:
                g["last_seen"] = ts
            if ev.get("dest_port"):
                g["ports"].add(int(ev["dest_port"]))
            if ev.get("proto"):
                g["protos"].add(ev["proto"])

        alerts.sort(key=lambda x: x["timestamp"], reverse=True)

        timeline_list = []
        for hour, data in sorted(timeline.items()):
            timeline_list.append({
                "hour": hour,
                "count": data["count"],
                "phases": dict(data["phases"]),
            })

        # Build the kill-chain cycle structure (7 standard phases + Unmapped)
        kill_chain = []
        for p in [1, 2, 3, 4, 5, 6, 7]:
            kill_chain.append({"phase": p, "name": _PHASE_NAMES[p], "alerts": by_phase.get(p, 0)})
        unmapped_count = by_phase.get(0, 0)

        top_signatures = sorted(by_signature.items(), key=lambda x: -x[1])[:10]

        # Finalise groups (sets → sorted lists for JSON; sort by count desc)
        groups_list = []
        for g in groups.values():
            g["ports"] = sorted(g["ports"])
            g["protos"] = sorted(g["protos"])
            groups_list.append(g)
        groups_list.sort(key=lambda x: x["last_seen"], reverse=True)

        result = {
            "alerts": alerts,
            "groups": groups_list,
            "total": len(alerts),
            "total_groups": len(groups_list),
            "dedup_ratio": round(len(alerts) / len(groups_list), 1) if groups_list else 0,
            "by_phase": dict(by_phase),
            "kill_chain": kill_chain,
            "unmapped_count": unmapped_count,
            "by_category": dict(by_category),
            "top_signatures": [{"signature": s, "count": c} for s, c in top_signatures],
            "timeline": timeline_list,
            "protected_asset_count": sum(1 for a in alerts if a["is_protected_asset"]),
        }
        cache_set(cache_key, result, ttl=120)
        return result

    @app.get("/api/alerts/group-detail")
    def api_group_detail():
        """Deep-dive for a single (signature_id, src, dst) group: returns
        all matching raw events in the window, plus enrichment + related alerts.

        Query params:
          sid       signature_id (int)
          src       source IP
          dst       destination IP
          minutes   window
        """
        try:
            sid = int(request.query.get("sid", "0"))
        except ValueError:
            sid = 0
        src = request.query.get("src", "")
        dst = request.query.get("dst", "")
        minutes = int(request.query.get("minutes", 60)) or 60

        # Asset map for src/dst owner enrichment
        try:
            conn = get_db()
            asset_rows = conn.execute("SELECT * FROM assets").fetchall()
            geo_rows = conn.execute(
                "SELECT * FROM geo_cache WHERE ip IN (?, ?)", (src, dst)
            ).fetchall()
            rep_rows = conn.execute(
                "SELECT * FROM ip_reputation WHERE ip IN (?, ?)", (src, dst)
            ).fetchall()
            conn.close()
        except Exception:
            asset_rows, geo_rows, rep_rows = [], [], []
        assets_by_ip = {r["ip"]: dict(r) for r in asset_rows}
        geo_by_ip = {r["ip"]: dict(r) for r in geo_rows}
        rep_by_ip = {r["ip"]: dict(r) for r in rep_rows}

        # Try GeoLite2 enrichment for dst/src if not already cached
        try:
            from analyzers.geoip import lookup_batch as _gb
            need = [ip for ip in (src, dst) if ip and ip not in geo_by_ip and is_internal(ip) is False]
            if need:
                fresh = _gb(need)
                for ip, g in fresh.items():
                    geo_by_ip[ip] = g
        except Exception:
            pass

        # Query ingested_alerts DB instead of scanning eve.json (fast indexed lookup)
        import json as _json
        from collections import defaultdict as _dd
        try:
            db2 = get_db()
            cutoff_sql = f"-{min(minutes, 1440)} minutes"
            exact_rows = db2.execute(
                """SELECT event_json, timestamp FROM ingested_alerts
                   WHERE signature_id=? AND src_ip=? AND dest_ip=?
                     AND timestamp >= datetime('now','localtime', ?)
                   ORDER BY timestamp DESC LIMIT 50""",
                (sid, src, dst, cutoff_sql)
            ).fetchall()
            related_rows = db2.execute(
                """SELECT signature, signature_id, dest_ip, timestamp, category
                   FROM ingested_alerts
                   WHERE src_ip=? AND NOT (signature_id=? AND dest_ip=?)
                     AND timestamp >= datetime('now','localtime', ?)
                   ORDER BY timestamp DESC LIMIT 30""",
                (src, sid, dst, cutoff_sql)
            ).fetchall()
            db2.close()
        except Exception:
            exact_rows, related_rows = [], []

        raw_events = []
        for row in exact_rows:
            try:
                ev = _json.loads(row["event_json"]) if row["event_json"] else {}
                if not ev.get("timestamp"):
                    ev["timestamp"] = row["timestamp"]
                raw_events.append(ev)
            except Exception:
                pass

        related_from_src = []
        for row in related_rows:
            related_from_src.append({
                "timestamp": row["timestamp"] or "",
                "signature": row["signature"] or "",
                "signature_id": row["signature_id"] or 0,
                "dest_ip": row["dest_ip"] or "",
                "phase": _classify_phase(row["signature"] or "")[0],
                "category": row["category"] or "",
            })

        # Per-hour timeline
        hourly = _dd(int)
        for ev in raw_events:
            ts = ev.get("timestamp", "")
            if len(ts) >= 13:
                hourly[ts[:13]] += 1
        timeline_list = [{"hour": h, "count": hourly[h]} for h in sorted(hourly)]

        def _enrich(ip):
            asset = assets_by_ip.get(ip, {})
            geo = geo_by_ip.get(ip, {})
            rep = rep_by_ip.get(ip, {})
            return {
                "ip": ip,
                "internal": is_internal(ip),
                "owner": asset.get("owner", ""),
                "hostname": asset.get("hostname", ""),
                "department": asset.get("department", ""),
                "asset_type": asset.get("asset_type", ""),
                "purdue_level": asset.get("purdue_level", ""),
                "business_critical": bool(asset.get("business_critical", 0)),
                "country": geo.get("country", ""),
                "country_code": geo.get("country_code", ""),
                "city": geo.get("city", ""),
                "isp": geo.get("isp", ""),
                "org": geo.get("org", ""),
                "abuse_score": rep.get("abuse_score", 0) if rep else 0,
                "is_tor": bool(rep.get("is_tor", 0)) if rep else False,
            }

        return {
            "sid": sid,
            "src": src,
            "dst": dst,
            "minutes": minutes,
            "matched_count": len(raw_events),
            "raw_events": raw_events,
            "timeline": timeline_list,
            "src_enrichment": _enrich(src) if src else None,
            "dst_enrichment": _enrich(dst) if dst else None,
            "related_from_source": related_from_src,
        }

    @app.get("/api/export/logs")
    def export_logs():
        """Export eve.json events as downloadable JSON.

        Query params:
            minutes: time window (default 60, max 1440)
            type: event type filter (alert, flow, dns, http, tls, all). Default: all
            ip: filter by IP (src or dest)
            format: json (default) or csv
        """
        minutes = min(int(request.query.get("minutes", 60)), 1440)
        etype = request.query.get("type", "all").strip()
        ip_filter = request.query.get("ip", "").strip()
        fmt = request.query.get("format", "json").strip()

        event_types = None
        if etype and etype != "all":
            event_types = set(etype.split(","))

        events = []
        for ev in iter_events(event_types=event_types, minutes=minutes,
                              ip_filter=ip_filter or None, max_lines=500000):
            events.append(ev)
            if len(events) >= 50000:
                break

        if fmt == "csv":
            response.content_type = "text/csv"
            response.headers["Content-Disposition"] = f"attachment; filename=notice_logs_{minutes}m.csv"
            lines = []
            if events:
                fields = ["timestamp", "event_type", "src_ip", "src_port",
                          "dest_ip", "dest_port", "proto", "app_proto"]
                lines.append(",".join(fields))
                for ev in events:
                    row = []
                    for f in fields:
                        v = str(ev.get(f, "")).replace('"', '""')
                        row.append(f'"{v}"')
                    lines.append(",".join(row))
            return "\n".join(lines)

        response.content_type = "application/json"
        response.headers["Content-Disposition"] = f"attachment; filename=notice_logs_{minutes}m.json"
        return json.dumps(events, default=str)

    @app.get("/api/export/alerts")
    def export_alerts():
        """Export only alert events as downloadable JSON."""
        minutes = min(int(request.query.get("minutes", 60)), 1440)
        ip_filter = request.query.get("ip", "").strip()

        events = []
        for ev in iter_events(event_types={"alert"}, minutes=minutes,
                              ip_filter=ip_filter or None):
            alert = ev.get("alert", {})
            events.append({
                "timestamp": ev.get("timestamp", ""),
                "src_ip": ev.get("src_ip", ""),
                "src_port": ev.get("src_port", ""),
                "dest_ip": ev.get("dest_ip", ""),
                "dest_port": ev.get("dest_port", ""),
                "proto": ev.get("proto", ""),
                "signature": alert.get("signature", ""),
                "signature_id": alert.get("signature_id", ""),
                "severity": alert.get("severity", ""),
                "category": alert.get("category", ""),
            })
            if len(events) >= 50000:
                break

        response.content_type = "application/json"
        response.headers["Content-Disposition"] = f"attachment; filename=notice_alerts_{minutes}m.json"
        return json.dumps(events, default=str)
