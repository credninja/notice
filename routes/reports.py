"""
Report API — professional management PDF reports with full enrichment,
geo-intelligence, service mapping, and executive-ready formatting.
"""

import json
import os
from datetime import datetime, timedelta
from collections import Counter
from bottle import request, response
from db import get_db, safe_update, cache_get, cache_set
from analyzers.report import generate_report
from analyzers.anomaly import detect_anomalies
from analyzers.enrich import build_enrichment_context, enrich_ip, identify_service, get_asset_map


LOGO_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "logo.png")


def register(app):

    @app.get("/api/report")
    def api_report():
        minutes = int(request.query.get("minutes", 720)) or 720
        cache_key = f"report_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        data = generate_report(minutes=minutes)
        cache_set(cache_key, data, ttl=180)
        return data

    @app.get("/api/report/daily")
    def api_report_daily():
        """Daily security report: answers the 4 standard exec questions
        about asset protection, detection activity, adversaries, and attack progression.
        Pass ?refresh=1 to bypass the server-side cache and rebuild fresh."""
        minutes = int(request.query.get("minutes", 1440)) or 1440
        force_refresh = request.query.get("refresh", "0") == "1"
        cache_key = f"report_daily_{minutes}"
        if not force_refresh:
            cached = cache_get(cache_key)
            if cached:
                # Tell the browser not to cache — only the server's authoritative
                # short TTL should determine freshness.
                response.headers["Cache-Control"] = "no-store, must-revalidate"
                return cached
        data = _build_daily_report(minutes=minutes)
        # 5-minute server cache — within that window the user can switch tabs / time
        # ranges and instantly get the cached build instead of re-scanning eve.json.
        cache_set(cache_key, data, ttl=300)
        response.headers["Cache-Control"] = "no-store, must-revalidate"
        return data

    @app.get("/api/report/pdf")
    def api_report_pdf():
        minutes = int(request.query.get("minutes", 720)) or 720
        download = request.query.get("download", "0")
        data = generate_report(minutes=minutes)
        # Enrich with anomalies, geo, hostnames for the PDF
        anomaly_data = detect_anomalies(minutes=minutes)
        enrichment = build_enrichment_context(minutes=minutes)
        pdf_bytes = _generate_pdf(data, anomaly_data, enrichment)
        response.content_type = "application/pdf"
        filename = f"CyberManthan_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        if download == "1":
            response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        else:
            response.headers["Content-Disposition"] = f'inline; filename="{filename}"'
        return bytes(pdf_bytes)

    # --- Action Items CRUD (unchanged) ---

    @app.get("/api/actions")
    def list_actions():
        conn = get_db()
        status = request.query.get("status", "")
        if status:
            rows = conn.execute("SELECT * FROM action_items WHERE status = ? ORDER BY created_at DESC", (status,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM action_items ORDER BY created_at DESC").fetchall()
        conn.close()
        return {"action_items": [dict(r) for r in rows]}

    @app.post("/api/actions")
    def create_action():
        data = request.json or {}
        title = data.get("title", "").strip()
        if not title:
            response.status = 400
            return {"error": "Title is required"}
        sla_hours = int(data.get("sla_hours", 24))
        due_at = (datetime.now() + timedelta(hours=sla_hours)).isoformat()
        conn = get_db()
        conn.execute(
            """INSERT INTO action_items
               (title, description, assigned_to, assigned_role, priority, source_type, source_ip, incident_id, sla_hours, due_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (title, data.get("description", ""), data.get("assigned_to", ""),
             data.get("assigned_role", "network_admin"), data.get("priority", "medium"),
             data.get("source_type", ""), data.get("source_ip", ""),
             data.get("incident_id"), sla_hours, due_at),
        )
        conn.commit()
        conn.close()
        response.status = 201
        return {"ok": True}

    @app.put("/api/actions/<action_id:int>")
    def update_action(action_id):
        data = request.json or {}
        conn = get_db()
        row = conn.execute("SELECT * FROM action_items WHERE id = ?", (action_id,)).fetchone()
        if not row:
            conn.close()
            response.status = 404
            return {"error": "Action not found"}
        extra_sets = ["updated_at = datetime('now','localtime')"]
        if data.get("status") == "completed":
            extra_sets.append("completed_at = datetime('now','localtime')")
            if row["due_at"] and datetime.now().isoformat() > row["due_at"]:
                extra_sets.append("sla_breached = 1")

        _ACTION_FIELDS = frozenset({"title", "description", "assigned_to", "assigned_role",
                                     "priority", "status", "breach_reason"})
        safe_update("action_items", _ACTION_FIELDS, data, "WHERE id = ?", [action_id], extra_sets)
        result = dict(conn.execute("SELECT * FROM action_items WHERE id = ?", (action_id,)).fetchone())
        conn.close()
        return result

    @app.delete("/api/actions/<action_id:int>")
    def delete_action(action_id):
        conn = get_db()
        conn.execute("DELETE FROM action_items WHERE id = ?", (action_id,))
        conn.commit()
        conn.close()
        return {"ok": True}


# ============================================================================
# Daily Security Report Builder
# Composes data from existing endpoints (monitoring, mitre, killchain,
# proposals, anomalies) into a 4-group structure aligned with executive needs.
# ============================================================================

def _window_phrase(minutes):
    if minutes <= 60: return "1 hour"
    if minutes <= 360: return "6 hours"
    if minutes <= 720: return "12 hours"
    if minutes <= 1440: return "24 hours"
    if minutes <= 10080: return "7 days"
    return f"{minutes} minutes"

def _build_daily_report(minutes=1440):
    """Aggregate the 4 management groups + recommendations into one payload."""
    from analyzers.correlation import SIGNATURE_MAP
    from analyzers.mitre import build_mitre_heatmap
    from analyzers.rule_proposals import generate_proposals
    from analyzers.suricata_rules import get_rule_stats, get_rules_for_asset
    from analyzers.snapshots import get_trend_data
    from collections import defaultdict
    from eve_reader import iter_events, is_internal, is_ipv4

    now = datetime.now()
    period_start = now - timedelta(minutes=minutes)

    # ---- Asset protection (composition only — rule coverage & BOM are out of
    # the management report by user request; that detail lives in Monitoring) ----
    conn = get_db()
    assets = [dict(r) for r in conn.execute("SELECT * FROM assets WHERE scope='internal'").fetchall()]
    verdict_rows = conn.execute("SELECT verdict, COUNT(*) as c FROM alert_verdicts GROUP BY verdict").fetchall()
    verdicts = {r["verdict"]: r["c"] for r in verdict_rows}
    missed_count = conn.execute("SELECT COUNT(*) FROM missed_detections").fetchone()[0]
    open_inc = conn.execute("SELECT COUNT(*) FROM incidents WHERE status='open'").fetchone()[0]
    investigating_inc = conn.execute("SELECT COUNT(*) FROM incidents WHERE status='investigating'").fetchone()[0]
    resolved_inc = conn.execute("SELECT COUNT(*) FROM incidents WHERE status='resolved'").fetchone()[0]
    actions_overdue = conn.execute(
        "SELECT COUNT(*) FROM action_items WHERE status IN ('open','in_progress') AND due_at < datetime('now','localtime')"
    ).fetchone()[0]
    overdue_action_rows = [dict(r) for r in conn.execute(
        "SELECT id, title, assigned_to, assigned_role, priority, status, due_at, "
        "sla_hours, breach_reason, source_type, source_ip "
        "FROM action_items WHERE status IN ('open','in_progress') AND due_at < datetime('now','localtime') "
        "ORDER BY due_at ASC LIMIT 10"
    ).fetchall()]
    rep_rows = {r["ip"]: dict(r) for r in conn.execute("SELECT * FROM ip_reputation").fetchall()}
    seen_rows = {r["ip"]: dict(r) for r in conn.execute("SELECT * FROM adversary_seen").fetchall()}
    conn.close()

    asset_types = defaultdict(int)
    critical_assets = []
    for a in assets:
        asset_types[(a.get("asset_type") or "other").strip().lower() or "other"] += 1
        if a.get("business_critical"):
            critical_assets.append({
                "ip": a["ip"], "owner": a.get("owner",""), "hostname": a.get("hostname",""),
                "asset_type": a.get("asset_type",""), "purdue_level": a.get("purdue_level",""),
            })

    # ---- Rule coverage adequacy (re-added by user request) ----
    rule_stats = get_rule_stats()
    rule_buckets = {"none": 0, "partial": 0, "adequate": 0}
    for a in assets:
        try:
            ar = get_rules_for_asset(a["ip"])
            tot = ar.get("direct_count", 0) + ar.get("inherited_count", 0)
        except Exception:
            tot = 0
        if tot >= 5:
            rule_buckets["adequate"] += 1
        elif tot >= 1:
            rule_buckets["partial"] += 1
        else:
            rule_buckets["none"] += 1

    # ---- SINGLE-PASS alert iteration: collects everything we need from alerts
    #      in one scan instead of the previous 4 separate scans (alerts,
    #      adversaries, kill chain, owner alerts) plus build_mitre_heatmap.
    #      This is the main perf fix for slow report loads. ----
    alert_count = 0
    sev_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    blocked = 0
    sev_map = {1: "critical", 2: "high", 3: "medium"}
    targeted_internal = defaultdict(int)
    hourly_buckets = defaultdict(int)
    asset_owner = {a["ip"]: a.get("owner", "") for a in assets}
    asset_hostname = {a["ip"]: a.get("hostname", "") for a in assets}
    asset_critical = {a["ip"]: bool(a.get("business_critical")) for a in assets}
    ip_owner = {a["ip"]: a.get("owner") for a in assets if a.get("owner")}
    owner_alerts = defaultdict(int)
    attackers = defaultdict(lambda: {"first_seen": None, "last_seen": None, "alerts": 0, "internal": False, "country": "", "targets": set(), "high_or_critical": 0})
    phase_meta = {1: "Reconnaissance", 2: "Weaponization", 3: "Delivery", 4: "Exploitation",
                  5: "Installation", 6: "Command & Control", 7: "Actions on Objectives"}
    phase_counts = {p: 0 for p in phase_meta}
    technique_hits = defaultdict(lambda: {"count": 0, "name": "", "tactic": "", "sources": set(), "targets": set()})
    # Track signatures that don't match any SIGNATURE_MAP pattern so generate_proposals
    # can build kill-chain mapping suggestions without re-scanning eve.json.
    unmapped_sigs = defaultdict(lambda: {"count": 0, "sid": 0})
    # Phase R additions: protocol/port breakdown + signature volume (for noisy-signature analysis)
    proto_counts = defaultdict(int)         # transport proto: TCP/UDP/ICMP/...
    app_proto_counts = defaultdict(int)     # app proto: http/dns/tls/ssh/...
    dest_port_counts = defaultdict(int)
    signature_volume = defaultdict(int)     # signature → alert count

    for ev in iter_events(event_types={"alert"}, minutes=minutes):
        alert = ev.get("alert", {})
        sig = alert.get("signature", "")
        sig_lower = sig.lower()
        sid = alert.get("signature_id", 0)
        sev = alert.get("severity", 3)
        action = alert.get("action", "allowed")
        ts = ev.get("timestamp", "")
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        # Protocol / port aggregation (Phase R — protocol-wise & port-wise analysis)
        proto = (ev.get("proto") or "").upper()
        if proto:
            proto_counts[proto] += 1
        ap = ev.get("app_proto") or ""
        if ap and ap != "failed":
            app_proto_counts[ap] += 1
        dport = ev.get("dest_port")
        if dport:
            dest_port_counts[int(dport)] += 1
        if sig:
            signature_volume[sig] += 1
        # severity + alert count
        sev_breakdown[sev_map.get(sev, "low")] += 1
        alert_count += 1
        # blocked counter
        if action in ("blocked", "dropped"):
            blocked += 1
        # targeted internal hosts + owner aggregation
        if is_ipv4(dst) and is_internal(dst):
            targeted_internal[dst] += 1
            if dst in ip_owner:
                owner_alerts[ip_owner[dst]] += 1
        # hourly bucket
        if len(ts) >= 13:
            hourly_buckets[ts[:13]] += 1
        # adversary tracking (external→internal or lateral internal→internal)
        if is_ipv4(src) and is_ipv4(dst):
            is_src_int = is_internal(src); is_dst_int = is_internal(dst)
            if (not is_src_int and is_dst_int) or (is_src_int and is_dst_int and src != dst):
                a = attackers[src]
                a["alerts"] += 1
                a["internal"] = is_src_int
                a["targets"].add(dst)
                if sev in (1, 2):  # critical or high
                    a["high_or_critical"] += 1
                if not a["first_seen"] or ts < a["first_seen"]: a["first_seen"] = ts
                if not a["last_seen"] or ts > a["last_seen"]: a["last_seen"] = ts
                if not a["country"] and src in rep_rows:
                    a["country"] = rep_rows[src].get("country_code", "")
        # kill chain phase + MITRE technique + unmapped tracking
        # (single SIGNATURE_MAP lookup serves all three)
        matched = False
        for m in SIGNATURE_MAP:
            if m["pattern"] in sig_lower:
                p = m.get("phase", 0)
                if p in phase_counts:
                    phase_counts[p] += 1
                tech_id = m.get("technique", "")
                if tech_id:
                    t = technique_hits[tech_id]
                    t["count"] += 1
                    t["name"] = m.get("technique_name", "")
                    t["tactic"] = m.get("phase_name", "")
                    if is_ipv4(src): t["sources"].add(src)
                    if is_ipv4(dst): t["targets"].add(dst)
                matched = True
                break
        if not matched and sig:
            u = unmapped_sigs[sig]
            u["count"] += 1
            if not u["sid"]:
                u["sid"] = sid

    top_targeted = sorted(targeted_internal.items(), key=lambda x: -x[1])[:8]
    top_targeted_list = [
        {
            "ip": ip, "alerts": cnt,
            "owner": asset_owner.get(ip, ""),
            "hostname": asset_hostname.get(ip, ""),
            "is_critical": asset_critical.get(ip, False),
        }
        for ip, cnt in top_targeted
    ]
    # Crown-jewel attack table — separate section so executives see it first
    attacks_on_critical = [t for t in top_targeted_list if t["is_critical"]]
    alerts_by_hour = []
    if hourly_buckets:
        all_hours = sorted(hourly_buckets.keys())
        for h in all_hours[-48:]:
            alerts_by_hour.append({"hour": h, "count": hourly_buckets[h]})

    # Top protocols + ports for the report's protocol/port analysis section
    top_protocols = sorted(proto_counts.items(), key=lambda x: -x[1])[:8]
    top_app_protocols = sorted(app_proto_counts.items(), key=lambda x: -x[1])[:8]
    # Map common port → service name for readability
    PORT_SVC = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
        53: "DNS", 67: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP",
        143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
        465: "SMTPS", 587: "SUBMISSION", 636: "LDAPS", 993: "IMAPS",
        995: "POP3S", 1433: "MSSQL", 1521: "ORACLE", 3306: "MySQL",
        3389: "RDP", 5060: "SIP", 5432: "PostgreSQL", 5900: "VNC",
        8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MongoDB",
    }
    top_ports = sorted(dest_port_counts.items(), key=lambda x: -x[1])[:10]
    top_ports_list = [
        {"port": p, "service": PORT_SVC.get(p, ""), "count": c}
        for p, c in top_ports
    ]

    # Noisy signatures — top 10 by volume. Without per-signature verdict
    # tracking we can only surface volume; FP rate per signature comes from
    # alert_verdicts if the analyst has marked any. Pull that in next.
    sig_fp_count = defaultdict(int)
    sig_tp_count = defaultdict(int)
    try:
        _vc = get_db()
        # alert_verdicts is keyed by (signature_id, src, dst) — we want by signature label.
        # Best-effort: join with the most recent matching signature_id volume in this window
        # by aggregating verdicts per signature_id, then mapping signature_id → signature
        # via a dictionary built during the alert pass would be ideal, but we don't keep
        # that map yet (alert_count avoids it for memory). We approximate by signature text
        # using the verdicts table's `signature` column when present.
        for r in _vc.execute(
            "SELECT signature, verdict, COUNT(*) as c FROM alert_verdicts "
            "WHERE signature != '' GROUP BY signature, verdict"
        ).fetchall():
            if r["verdict"] == "false_positive":
                sig_fp_count[r["signature"]] += r["c"]
            elif r["verdict"] == "true_positive":
                sig_tp_count[r["signature"]] += r["c"]
        _vc.close()
    except Exception:
        pass

    noisy_signatures = []
    for sig, vol in sorted(signature_volume.items(), key=lambda x: -x[1])[:25]:
        fp = sig_fp_count.get(sig, 0)
        tp = sig_tp_count.get(sig, 0)
        marked = fp + tp
        fp_rate = round((fp / marked) * 100, 1) if marked else None
        # Surface a sig as "noisy" if either it's high volume OR demonstrably high-FP
        if vol >= 20 or (fp_rate is not None and fp_rate >= 50):
            noisy_signatures.append({
                "signature": sig, "volume": vol,
                "fp_marked": fp, "tp_marked": tp,
                "fp_rate_pct": fp_rate,
            })
        if len(noisy_signatures) >= 10:
            break

    # Anomaly detection — done once, then passed to proposals so it isn't redone.
    anomalies = detect_anomalies(minutes=minutes)
    anom_summary = anomalies.get("summary", {})

    # Proposals — reuse anomaly result + already-collected unmapped signatures,
    # and skip the hot-port flow scan (low-value for a daily exec report).
    # Eliminates 2 of the 3 eve.json scans inside generate_proposals.
    proposals = generate_proposals(minutes=minutes, anom=anomalies,
                                   unmapped=dict(unmapped_sigs), skip_port_scan=True)
    top_proposals = proposals.get("proposals", [])[:5]

    adv_known = adv_new = adv_unidentified = adv_compromised = 0
    top_attackers = []
    country_counts = defaultdict(int)  # country_code -> attacker IP count
    country_alerts = defaultdict(int)  # country_code -> total alert count
    for ip, info in attackers.items():
        # Compromised-insider heuristic: internal IP that hit ≥3 internal targets
        # or generated any high/critical alerts. Strong signal of lateral movement.
        is_compromised = info["internal"] and (
            len(info["targets"]) >= 3 or info["high_or_critical"] > 0
        )
        if is_compromised:
            cls = "compromised_insider"
        elif info["internal"]:
            cls = "known"
        elif ip in rep_rows and (rep_rows[ip].get("abuse_score", 0) > 0 or rep_rows[ip].get("is_tor")):
            cls = "known"
        elif ip not in seen_rows:
            cls = "new"
        else:
            cls = "unidentified"
        if cls == "known": adv_known += 1
        elif cls == "new": adv_new += 1
        elif cls == "compromised_insider": adv_compromised += 1
        else: adv_unidentified += 1
        top_attackers.append({"ip": ip, "alerts": info["alerts"], "internal": info["internal"], "classification": cls, "country": info["country"]})
        # Aggregate by country (external attackers only — internal "Unknown" buckets aren't useful)
        if not info["internal"]:
            cc = (info.get("country") or "??").upper() or "??"
            country_counts[cc] += 1
            country_alerts[cc] += info["alerts"]
    top_attackers.sort(key=lambda x: -x["alerts"])

    # Phase R: enrich top attackers with ASN/org from GeoLite2 (offline) where
    # available. Lookups are O(microseconds) so doing it for the top-10 list
    # is essentially free — only one HTTP call worst-case (and only if offline
    # lookup misses, which is rare for routable public IPs).
    try:
        from analyzers.geoip import lookup_batch as _geoip_batch
        ext_attacker_ips = [a["ip"] for a in top_attackers[:25] if not a["internal"]]
        if ext_attacker_ips:
            _geo = _geoip_batch(ext_attacker_ips)
            for a in top_attackers:
                g = _geo.get(a["ip"])
                if g:
                    a["org"] = g.get("org", "")
                    a["city"] = g.get("city", "")
                    if not a.get("country"):
                        a["country"] = g.get("country_code", "")
    except Exception:
        pass

    top_countries = sorted(country_counts.items(), key=lambda x: -x[1])[:6]
    top_countries_list = [
        {"country": cc, "attackers": country_counts[cc], "alerts": country_alerts[cc]}
        for cc, _ in top_countries
    ]

    # ---- Kill chain (already computed in the single alert pass above) ----
    deepest = max((p for p in phase_counts if phase_counts[p] > 0), default=0)
    kill_chain = [{"phase": p, "name": phase_meta[p], "alerts": phase_counts[p]} for p in sorted(phase_meta)]

    # ---- TTPs (MITRE) — derived inline from the same SIGNATURE_MAP lookups
    #      we did during the alert pass (saves another full eve.json scan). ----
    sorted_techniques = sorted(technique_hits.items(), key=lambda x: -x[1]["count"])[:8]
    top_techniques = [{
        "technique_id": tid, "technique_name": info["name"], "tactic": info["tactic"],
        "count": info["count"], "sources": len(info["sources"]), "targets": len(info["targets"]),
    } for tid, info in sorted_techniques]
    active_tactics = len({info["tactic"] for info in technique_hits.values() if info["tactic"]})
    total_tactics = 14  # MITRE Enterprise tactic count

    # ---- Cross-zone (PERA) violations — only meaningful when assets are tagged with purdue_level ----
    cross_zone_violations = []
    cross_zone_count = 0
    purdue_tagged_assets = sum(1 for a in assets if (a.get("purdue_level") or "").strip())
    if purdue_tagged_assets >= 2:
        # Reuse the cached purdue topology if available; fall back to recompute.
        purdue_data = cache_get(f"network_purdue_{minutes}")
        if not purdue_data:
            try:
                from routes.network_map import register as _nm  # noqa
                # Inline computation: replicate the per-asset purdue_level lookup
                pl_by_ip = {a["ip"]: (a.get("purdue_level") or "").strip() for a in assets}
                pair_stats = defaultdict(lambda: {"flows": 0, "alerts": 0})
                for ev in iter_events(event_types={"flow", "alert"}, minutes=minutes):
                    src = ev.get("src_ip", ""); dst = ev.get("dest_ip", "")
                    if not is_ipv4(src) or not is_ipv4(dst): continue
                    if not (src in pl_by_ip and dst in pl_by_ip): continue
                    key = tuple(sorted([src, dst]))
                    if ev.get("event_type") == "flow":
                        pair_stats[key]["flows"] += 1
                    else:
                        pair_stats[key]["alerts"] += 1
                for (a_ip, b_ip), stats in pair_stats.items():
                    la = pl_by_ip[a_ip]; lb = pl_by_ip[b_ip]
                    if not la or not lb or la == lb: continue
                    try:
                        ra = float(la); rb = float(lb)
                    except (TypeError, ValueError):
                        continue
                    jump = abs(ra - rb)
                    cross_zone = jump > 1 or (ra >= 4 and rb <= 2) or (rb >= 4 and ra <= 2)
                    if cross_zone:
                        cross_zone_count += 1
                        if len(cross_zone_violations) < 10:
                            cross_zone_violations.append({
                                "source": a_ip, "target": b_ip,
                                "source_level": la, "target_level": lb,
                                "flows": stats["flows"], "alerts": stats["alerts"],
                            })
            except Exception:
                pass
        else:
            edges = purdue_data.get("edges", [])
            for e in edges:
                if e.get("cross_zone"):
                    cross_zone_count += 1
                    if len(cross_zone_violations) < 10:
                        cross_zone_violations.append({
                            "source": e["source"], "target": e["target"],
                            "source_level": e.get("source_level", ""), "target_level": e.get("target_level", ""),
                            "flows": e.get("flows", 0), "alerts": 1 if e.get("has_alerts") else 0,
                        })

    # ---- Day-over-day trend (uses daily_snapshots; if fewer than 2 days, trend = None) ----
    trends = {"alerts": None, "critical": None, "bytes": None, "violations": None, "health": None}
    try:
        snap = get_trend_data(days=2)
        if len(snap) >= 2:
            yesterday = snap[-2]
            today = snap[-1]
            def _pct(prev, curr):
                if prev is None or prev == 0:
                    return None if (curr or 0) == 0 else 100
                return round(((curr or 0) - prev) / prev * 100)
            trends["alerts"]     = _pct(yesterday.get("total_alerts"), today.get("total_alerts"))
            trends["critical"]   = _pct(yesterday.get("critical_alerts"), today.get("critical_alerts"))
            trends["bytes"]      = _pct(yesterday.get("total_bytes"), today.get("total_bytes"))
            trends["violations"] = _pct(yesterday.get("policy_violations"), today.get("policy_violations"))
            trends["health"]     = _pct(yesterday.get("health_score"), today.get("health_score"))
    except Exception:
        pass

    # ---- Owners ranked by alert volume (already aggregated in single alert pass) ----
    top_owners = sorted(owner_alerts.items(), key=lambda x: -x[1])[:5]

    # ---- Auto-generated executive narrative ----
    successful = verdicts.get("true_positive", 0)
    high_props = proposals.get("summary", {}).get("by_severity", {}).get("high", 0)
    deepest_phase_text = phase_meta.get(deepest, "no progression observed") if deepest else "no attack progression"
    summary_lines = []
    if alert_count == 0:
        summary_lines.append(f"Quiet window: {len(assets)} protected assets, no IDS alerts and no anomalies recorded.")
    else:
        summary_lines.append(
            f"In the last {_window_phrase(minutes)}, the IDS recorded {alert_count:,} alerts targeting "
            f"{len(targeted_internal)} of your {len(assets)} protected assets. "
            f"{len(attackers)} distinct attackers were observed "
            f"({adv_known} known, {adv_new} new, {adv_unidentified} unidentified)."
        )
        if successful > 0:
            summary_lines.append(
                f"⚠ {successful} confirmed successful breach{'es' if successful != 1 else ''} require immediate review."
            )
        else:
            summary_lines.append("No analyst-confirmed breaches; current verdicts indicate detection without compromise.")
        if deepest >= 6:
            summary_lines.append(
                f"Adversaries reached Phase {deepest} — {deepest_phase_text} — the most advanced kill-chain stage observed."
            )
        elif deepest >= 1:
            summary_lines.append(
                f"Deepest kill-chain phase observed: P{deepest} ({deepest_phase_text})."
            )
        if high_props > 0:
            summary_lines.append(
                f"{high_props} high-severity rule proposal{'s' if high_props != 1 else ''} pending review to close detection gaps."
            )
        if open_inc > 0 or actions_overdue > 0:
            summary_lines.append(
                f"Operational: {open_inc} open incident{'s' if open_inc != 1 else ''}, "
                f"{actions_overdue} overdue action{'s' if actions_overdue != 1 else ''}."
            )

    # ---- Prioritized action items engine (Phase R) ----
    # Generates a numbered to-do list from the signals we already have.
    # Categorised: TODAY (urgent), THIS_WEEK (medium), THIS_SPRINT (hygiene).
    action_items = []

    # TODAY — anything that suggests active compromise
    if adv_compromised > 0:
        comp_list = [a for a in top_attackers if a.get("classification") == "compromised_insider"]
        if comp_list:
            top_comp = comp_list[0]
            action_items.append({
                "priority": "today", "owner": "soc_analyst",
                "title": f"Triage compromised insider {top_comp['ip']}",
                "evidence": f"Internal IP exhibiting attacker behaviour — {top_comp['alerts']} alerts.",
            })
    if attacks_on_critical:
        most_hit = attacks_on_critical[0]
        action_items.append({
            "priority": "today", "owner": "soc_analyst",
            "title": f"Investigate attacks on business-critical asset {most_hit['ip']} ({most_hit.get('owner') or most_hit.get('hostname') or 'unowned'})",
            "evidence": f"{most_hit['alerts']} alerts in the window.",
        })
    if successful > 0:
        action_items.append({
            "priority": "today", "owner": "soc_analyst",
            "title": f"Review {successful} confirmed successful breach{'es' if successful != 1 else ''}",
            "evidence": "Analyst-marked true positives indicate compromise.",
        })
    new_attackers = [a for a in top_attackers if a.get("classification") == "new" and not a["internal"]]
    for newa in new_attackers[:2]:
        action_items.append({
            "priority": "today", "owner": "soc_analyst",
            "title": f"Investigate new attacker {newa['ip']} ({(newa.get('country') or '?')})",
            "evidence": f"First contact in our environment, {newa['alerts']} alerts so far.",
        })

    # THIS WEEK — tuning + closing detection gaps
    if noisy_signatures:
        worst = noisy_signatures[0]
        if worst.get("fp_rate_pct") and worst["fp_rate_pct"] >= 50:
            action_items.append({
                "priority": "this_week", "owner": "network_admin",
                "title": f"Tune noisy signature: '{worst['signature'][:80]}'",
                "evidence": f"{worst['volume']:,} fires; {worst['fp_rate_pct']}% FP rate among marked alerts.",
            })
        elif worst["volume"] >= 500:
            action_items.append({
                "priority": "this_week", "owner": "network_admin",
                "title": f"Review high-volume signature: '{worst['signature'][:80]}'",
                "evidence": f"{worst['volume']:,} fires — verify whether tuning is needed.",
            })
    if high_props > 0:
        action_items.append({
            "priority": "this_week", "owner": "network_admin",
            "title": f"Review {high_props} high-severity rule proposal{'s' if high_props != 1 else ''}",
            "evidence": "Auto-generated mappings + new IDS rules pending in the Rule Proposals tab.",
        })
    if cross_zone_count > 0:
        action_items.append({
            "priority": "this_week", "owner": "network_admin",
            "title": f"Review {cross_zone_count} cross-zone segmentation violation{'s' if cross_zone_count != 1 else ''}",
            "evidence": "PERA boundaries crossed (e.g. L4 ↔ L1 directly, skipping the DMZ).",
        })

    # THIS SPRINT — hygiene
    untagged = sum(1 for a in assets if not (a.get("purdue_level") or "").strip())
    if untagged > 0:
        action_items.append({
            "priority": "this_sprint", "owner": "asset_custodian",
            "title": f"Tag {untagged} asset{'s' if untagged != 1 else ''} with Purdue level",
            "evidence": "Untagged assets are excluded from PERA segmentation analysis.",
        })
    if rule_buckets["none"] > 0:
        action_items.append({
            "priority": "this_sprint", "owner": "network_admin",
            "title": f"Add detection rules for {rule_buckets['none']} asset{'s' if rule_buckets['none'] != 1 else ''} with zero coverage",
            "evidence": "These hosts have no asset-specific or inherited IDS rules protecting them.",
        })
    if actions_overdue > 0:
        action_items.append({
            "priority": "this_sprint", "owner": "management",
            "title": f"Close {actions_overdue} overdue action item{'s' if actions_overdue != 1 else ''}",
            "evidence": "SLA-breached items in the action queue — see SLA Breaches table for owners.",
        })

    # Cap to keep the report scannable
    action_items = action_items[:12]

    # ---- 7-day trend (vs last week) — from daily_snapshots if available ----
    trends_week = {"alerts": None, "critical": None}
    try:
        weekly = get_trend_data(days=14)
        if len(weekly) >= 14:
            this_week_alerts = sum(s.get("total_alerts", 0) for s in weekly[-7:])
            last_week_alerts = sum(s.get("total_alerts", 0) for s in weekly[-14:-7])
            if last_week_alerts > 0:
                trends_week["alerts"] = round((this_week_alerts - last_week_alerts) / last_week_alerts * 100)
            this_week_crit = sum(s.get("critical_alerts", 0) for s in weekly[-7:])
            last_week_crit = sum(s.get("critical_alerts", 0) for s in weekly[-14:-7])
            if last_week_crit > 0:
                trends_week["critical"] = round((this_week_crit - last_week_crit) / last_week_crit * 100)
    except Exception:
        pass
    trends["alerts_week"] = trends_week["alerts"]
    trends["critical_week"] = trends_week["critical"]

    # ---- Coverage / scope disclaimer ----
    coverage_note = (
        "This report covers IDS events from the network detection sensor monitoring 10.0.0.0/8. "
        "Cloud workloads (AWS / GCP / Azure), encrypted SNI / ECH, USB exfiltration, "
        "process-level activity, and endpoint-only events are NOT in scope. "
        "Findings are based on the assets currently registered in NOTICE — "
        f"{len(assets)} internal hosts, {sum(1 for a in assets if (a.get('purdue_level') or '').strip())} with Purdue tagging."
    )

    report_id = "RPT-" + now.strftime("%Y%m%d-%H%M")

    return {
        "report_time": now.isoformat(),
        "report_id": report_id,
        "period_minutes": minutes,
        "period_start": period_start.isoformat(),
        "period_end": now.isoformat(),
        "executive_summary": " ".join(summary_lines),
        "coverage_note": coverage_note,
        "action_items": action_items,
        # ----- Group A: Asset Protection -----
        "asset_protection": {
            "total_protected": len(assets),
            "asset_types": dict(asset_types),
            "critical_assets_count": len(critical_assets),
            "critical_assets": critical_assets,
            "rule_coverage": {
                "total_active": rule_stats.get("total_active", 0),
                "general_rules": rule_stats.get("general_rules", 0),
                "asset_specific_rules": rule_stats.get("asset_specific_rules", 0),
                "custom_rules": rule_stats.get("custom_rules", 0),
                "adequate_assets": rule_buckets["adequate"],
                "partial_assets": rule_buckets["partial"],
                "no_coverage_assets": rule_buckets["none"],
            },
        },
        # ----- Group B: Detection Activity -----
        "detection": {
            "total_alerts": alert_count,
            "severity_breakdown": sev_breakdown,
            "top_targeted_internal": top_targeted_list,
            "attacks_on_critical_assets": attacks_on_critical,
            "alerts_by_hour": alerts_by_hour,
            "protocol_breakdown": [{"proto": p, "count": c} for p, c in top_protocols],
            "app_protocol_breakdown": [{"proto": p, "count": c} for p, c in top_app_protocols],
            "top_destination_ports": top_ports_list,
            "noisy_signatures": noisy_signatures,
            "anomalies_detected": anom_summary.get("total_anomalies", 0),
            "anomaly_breakdown": {
                "nmap_scanners": anom_summary.get("nmap_scanners", 0),
                "high_volume_flows": anom_summary.get("high_volume_count", 0),
                "dns_suspicious": anom_summary.get("dns_suspicious_hosts", 0),
                "deprecated_tls": anom_summary.get("deprecated_tls_pairs", 0),
                "unusual_ports": anom_summary.get("unusual_port_count", 0),
            },
            "verdicts": {
                "true_positive": verdicts.get("true_positive", 0),
                "false_positive": verdicts.get("false_positive", 0),
                "false_negative": (verdicts.get("false_negative", 0) + missed_count),
                "investigating": verdicts.get("investigating", 0),
            },
            "attempts": {
                "blocked": blocked,
                "successful": verdicts.get("true_positive", 0),
                "failed_or_unsuccessful": max(0, alert_count - blocked - verdicts.get("true_positive", 0) - verdicts.get("false_positive", 0)),
            },
            "rule_proposals": {
                "total": proposals.get("summary", {}).get("total", 0),
                "high_severity": proposals.get("summary", {}).get("by_severity", {}).get("high", 0),
                "top_5": [{"title": p.get("title",""), "severity": p.get("severity",""), "confidence": p.get("confidence","")} for p in top_proposals],
            },
        },
        # ----- Group C: Adversary Intelligence -----
        "adversaries": {
            "total_attempted": len(attackers),
            "known": adv_known,
            "new": adv_new,
            "unidentified": adv_unidentified,
            "compromised_insider": adv_compromised,
            "top_10": top_attackers[:10],
            "top_countries": top_countries_list,
        },
        # ----- Group D: Attack Analysis -----
        "attack_analysis": {
            "kill_chain": kill_chain,
            "deepest_phase_reached": deepest,
            "deepest_phase_name": phase_meta.get(deepest, "None"),
            "mitre_active_tactics": active_tactics,
            "mitre_total_tactics": total_tactics,
            "top_techniques": top_techniques,
            "cross_zone_violations_count": cross_zone_count,
            "cross_zone_violations": cross_zone_violations,
            "purdue_tagged_assets": purdue_tagged_assets,
        },
        "trends": trends,
        # ----- Recommendations / additional management context -----
        "recommendations": {
            "open_incidents": open_inc,
            "investigating_incidents": investigating_inc,
            "resolved_incidents": resolved_inc,
            "overdue_actions": actions_overdue,
            "overdue_action_details": overdue_action_rows,
            "top_owners_by_alert_volume": [{"owner": o, "alerts": c} for o, c in top_owners],
        },
    }


# ============================================================================
# Professional Report PDF Generator — Cyber Manthan Theme
# ============================================================================

# Color palette
_NAVY = (26, 26, 46)
_DARK_SURFACE = (30, 33, 50)
_WHITE = (255, 255, 255)
_TEXT = (30, 30, 40)
_DIM = (120, 120, 140)
_ACCENT = (59, 130, 246)
_CRITICAL = (220, 38, 38)
_HIGH = (239, 68, 68)
_MEDIUM = (245, 158, 11)
_LOW = (59, 130, 246)
_SUCCESS = (16, 185, 129)
_BORDER = (200, 205, 220)
_ROW_ALT = (245, 247, 252)
_CLASSIFICATION = (180, 30, 30)
_GOLD = (212, 175, 55)


def _s(text):
    """Sanitize text for PDF (latin-1)."""
    return str(text).encode("latin-1", errors="replace").decode("latin-1")


def _fb(b):
    """Format bytes."""
    b = b or 0
    if b < 1024: return f"{b} B"
    if b < 1048576: return f"{b/1024:.1f} KB"
    if b < 1073741824: return f"{b/1048576:.1f} MB"
    return f"{b/1073741824:.2f} GB"


def _ft(ts):
    """Format timestamp."""
    if not ts: return "-"
    try:
        d = datetime.fromisoformat(ts)
        return d.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ts[:16] if len(ts) >= 16 else ts


def _sev_color(sev):
    if sev in (1, "critical"): return _CRITICAL
    if sev in (2, "high"): return _HIGH
    if sev in (3, "medium"): return _MEDIUM
    return _LOW


def _risk_color(score):
    if score >= 75: return _CRITICAL
    if score >= 50: return _HIGH
    if score >= 25: return _MEDIUM
    return _SUCCESS


def _generate_pdf(data, anomaly_data, enrichment_ctx):
    from fpdf import FPDF

    asset_map, hostname_map, geo_map = enrichment_ctx

    class ReportPDF(FPDF):
        def header(self):
            if self.page_no() <= 1:
                return
            self.set_fill_color(*_NAVY)
            self.rect(0, 0, 210, 12, "F")
            self.set_y(2.5)
            self.set_font("Helvetica", "B", 7)
            self.set_text_color(*_WHITE)
            self.cell(95, 5, "Cyber Manthan - Network Security Report")
            self.set_font("Helvetica", "", 7)
            self.cell(95, 5, f"Generated: {_ft(data.get('report_time', ''))}", align="R")
            self.set_y(16)

        def footer(self):
            self.set_y(-12)
            self.set_fill_color(*_NAVY)
            self.rect(0, self.get_y(), 210, 12, "F")
            self.set_font("Helvetica", "", 6)
            self.set_text_color(*_DIM)
            self.cell(60, 5, "Cyber Manthan | IIIT Hyderabad")
            self.set_font("Helvetica", "B", 6)
            self.set_text_color(*_MEDIUM)
            self.cell(70, 5, "CONFIDENTIAL - INTERNAL USE ONLY", align="C")
            self.set_font("Helvetica", "", 6)
            self.set_text_color(*_DIM)
            self.cell(60, 5, f"Page {self.page_no()}/{{nb}}", align="R")

    pdf = ReportPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)

    s = data["summary"]
    es = data.get("executive_summary", {})
    tt = data.get("top_threats", {})
    tv = data.get("traffic_overview", {})
    rs = data.get("risk_score", {})
    score = rs.get("risk_score", 0)
    risk_label = rs.get("risk_label", "Low")
    health = es.get("health_status", "Healthy")
    minutes = data.get("period_minutes", 60)
    period = f"Last {minutes} minutes" if minutes <= 60 else f"Last {minutes//60} hours" if minutes <= 1440 else f"Last {minutes//1440} days"

    # ================================================================
    # PAGE 1: COVER PAGE
    # ================================================================
    pdf.add_page()
    pdf.set_fill_color(*_NAVY)
    pdf.rect(0, 0, 210, 297, "F")

    # Classification banner
    pdf.set_y(10)
    pdf.set_fill_color(*_CLASSIFICATION)
    pdf.rect(20, 8, 170, 9, "F")
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*_WHITE)
    pdf.cell(0, 9, "CONFIDENTIAL - INTERNAL USE ONLY", align="C")
    pdf.ln(18)

    # Logo / Branding
    if os.path.exists(LOGO_PATH):
        try:
            pdf.image(LOGO_PATH, x=65, y=35, w=80)
            pdf.set_y(70)
        except Exception:
            _text_logo(pdf)
    else:
        _text_logo(pdf)

    # Report Title
    pdf.set_y(90)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(*_WHITE)
    pdf.cell(0, 13, "Network Security Monitoring", align="C")
    pdf.ln(14)
    pdf.set_font("Helvetica", "B", 24)
    pdf.cell(0, 13, "& Threat Analysis Report", align="C")
    pdf.ln(16)

    # Accent line
    pdf.set_fill_color(*_ACCENT)
    pdf.rect(65, pdf.get_y(), 80, 1.5, "F")
    pdf.ln(14)

    # Metadata
    meta = [
        ("Reporting Period", period),
        ("Generated On", _ft(data.get("report_time", ""))),
        ("Network Scope", "10.0.0.0/8 (Corporate Internal)"),
        ("Monitoring Engine", "NOTICE Detection Engine"),
        ("Prepared By", "NOTICE Security Monitor"),
        ("Organization", "Cyber Manthan - IIIT Hyderabad"),
        ("Classification", "Confidential - Internal Use Only"),
    ]
    for label, value in meta:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(150, 155, 175)
        pdf.cell(95, 7, label, align="R")
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*_WHITE)
        pdf.cell(95, 7, f"  {value}", align="L")
        pdf.ln(7)

    # Risk Assessment Badge
    pdf.ln(14)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(150, 155, 175)
    pdf.cell(0, 8, "OVERALL SECURITY POSTURE", align="C")
    pdf.ln(10)
    color = _risk_color(score)
    pdf.set_font("Helvetica", "B", 40)
    pdf.set_text_color(*color)
    pdf.cell(0, 18, f"{score}/100", align="C")
    pdf.ln(12)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 8, risk_label.upper(), align="C")

    # Bottom classification
    pdf.set_auto_page_break(auto=False)
    pdf.set_y(270)
    pdf.set_fill_color(*_CLASSIFICATION)
    pdf.rect(20, 270, 170, 9, "F")
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*_WHITE)
    pdf.cell(0, 9, "CONFIDENTIAL - INTERNAL USE ONLY", align="C")
    pdf.set_auto_page_break(auto=True, margin=18)

    # ================================================================
    # PAGE 2: TABLE OF CONTENTS
    # ================================================================
    pdf.add_page()
    _sec_hdr(pdf, "i", "Table of Contents", _ACCENT)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*_TEXT)
    toc = [
        ("1", "Executive Summary", "Key findings, business impact, security posture"),
        ("2", "Key Metrics Dashboard", "Alerts, anomalies, traffic, protocol distribution"),
        ("3", "Anomaly Analysis", "Detected anomalies with enrichment and reasoning"),
        ("4", "External Communication Insights", "Geo-distribution, service mapping, unknown IPs"),
        ("5", "Internal Asset Analysis", "Priority-ranked assets with behavioral observations"),
        ("6", "Threat & Alert Summary", "Detection rules, categories, correlations"),
        ("7", "Network Behavior Insights", "Protocol trends, DNS, TLS, HTTP analysis"),
        ("8", "Recommendations", "Immediate actions and strategic improvements"),
        ("9", "Security Assessment", "Overall rating, concerns, readiness level"),
    ]
    for num, title, desc in toc:
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*_ACCENT)
        pdf.cell(10, 7, num)
        pdf.set_text_color(*_TEXT)
        pdf.cell(60, 7, title)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*_DIM)
        pdf.cell(0, 7, desc, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    # ================================================================
    # SECTION 1: EXECUTIVE SUMMARY
    # ================================================================
    pdf.add_page()
    _sec_hdr(pdf, "1", "Executive Summary", _ACCENT)

    # Health badge
    hc = _CRITICAL if health == "Critical" else _MEDIUM if health == "At Risk" else _SUCCESS
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*_TEXT)
    pdf.cell(48, 7, "Security Posture:")
    pdf.set_fill_color(*hc)
    pdf.set_text_color(*_WHITE)
    pdf.set_font("Helvetica", "B", 10)
    w = pdf.get_string_width(f"  {health.upper()}  ") + 6
    pdf.cell(w, 7, f"  {health.upper()}  ", fill=True)
    pdf.ln(12)

    # Key findings cards
    metrics = [
        ("Total Events", f"{es.get('total_events', 0):,}"),
        ("Total Alerts", f"{es.get('total_alerts', 0):,}"),
        ("Alert Rate", f"{es.get('alert_rate_pct', 0):.2f}%"),
        ("Unique Sources Flagged", f"{es.get('unique_src_flagged', 0):,}"),
        ("Unique Dests Flagged", f"{es.get('unique_dst_flagged', 0):,}"),
        ("Total Flows", f"{es.get('total_flows', 0):,}"),
    ]
    _metric_grid(pdf, metrics, cols=3)

    # Most targeted
    targeted = es.get("top_targeted_internal", [])
    if targeted:
        _sub_hdr(pdf, "Most Targeted Internal Hosts")
        _tbl_hdr(pdf, ["Internal IP", "Owner", "Alert Count"], [50, 50, 30])
        for i, t in enumerate(targeted[:5]):
            owner = asset_map.get(t["ip"], {}).get("owner", "")
            _tbl_row(pdf, [t["ip"], _s(owner or "-"), str(t["count"])], [50, 50, 30], i)
        pdf.ln(4)

    # Executive paragraph — plain language for management
    _sub_hdr(pdf, "Situational Assessment")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*_TEXT)
    pdf.multi_cell(0, 5, _s(es.get("paragraph", "No summary available.")))
    pdf.ln(3)

    # Business impact statement
    _sub_hdr(pdf, "Business Impact")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*_TEXT)
    impact = _generate_business_impact(es, rs, s)
    pdf.multi_cell(0, 5, _s(impact))
    pdf.ln(2)

    # ================================================================
    # SECTION 2: KEY METRICS DASHBOARD
    # ================================================================
    pdf.add_page()
    _sec_hdr(pdf, "2", "Key Metrics Dashboard", _ACCENT)

    anom_s = anomaly_data.get("summary", {})
    dash_metrics = [
        ("Total Alerts", f"{es.get('total_alerts', 0):,}"),
        ("Real Anomalies", f"{anom_s.get('real_anomaly_count', 0)}"),
        ("Suspected Anomalies", f"{anom_s.get('suspected_count', 0)}"),
        ("DNS Suspicious", f"{anom_s.get('dns_suspicious_hosts', 0)}"),
        ("Deprecated TLS", f"{anom_s.get('deprecated_tls_pairs', 0)}"),
        ("Unusual Ports", f"{anom_s.get('unusual_port_count', 0)}"),
        ("Critical Assets", f"{s.get('critical_assets', 0)}"),
        ("Warning Assets", f"{s.get('warning_assets', 0)}"),
        ("Total Traffic", _fb(tv.get("total_bytes", 0))),
    ]
    _metric_grid(pdf, dash_metrics, cols=3)
    pdf.ln(2)

    # Traffic direction
    _sub_hdr(pdf, "Traffic Direction Summary")
    _metric_grid(pdf, [
        ("Inbound Volume", _fb(tv.get("total_bytes_inbound", 0))),
        ("Outbound Volume", _fb(tv.get("total_bytes_outbound", 0))),
        ("Peak Window", str(tv.get("peak_hour", "N/A")).replace("T", " ")),
    ], cols=3)

    # Protocol breakdown
    proto_bd = tv.get("app_proto_breakdown", [])
    if proto_bd:
        _sub_hdr(pdf, "Application Protocol Distribution")
        _tbl_hdr(pdf, ["Protocol", "Volume", "Share"], [50, 50, 30])
        for i, p in enumerate(proto_bd[:8]):
            _tbl_row(pdf, [p["proto"], _fb(p["bytes"]), f"{p['pct']}%"], [50, 50, 30], i)
        pdf.ln(4)

    # ================================================================
    # SECTION 3: ANOMALY ANALYSIS (with enrichment)
    # ================================================================
    pdf.add_page()
    _sec_hdr(pdf, "3", "Anomaly Analysis", _HIGH)

    real = anomaly_data.get("real_anomalies", [])
    if real:
        _sub_hdr(pdf, f"Confirmed & Suspected Anomalies ({len(real)} detected)")
        _tbl_hdr(pdf, ["Severity", "Type", "Confidence", "Source IP (Owner)", "Destination", "Reasoning"], [16, 28, 18, 38, 30, 55])
        for i, a in enumerate(real[:15]):
            owner = a.get("src_asset", "")
            src_label = f"{a['src_ip']}" + (f" ({owner})" if owner else "")
            _tbl_row(pdf, [
                a["severity"].upper(), _s(a["anomaly_type"][:18]),
                a["confidence"], _s(src_label[:25]),
                _s(str(a.get("dest_ip", "-"))[:20]),
                _s(a.get("reasoning", "")[:40]),
            ], [16, 28, 18, 38, 30, 55], i, sev_col_idx=0)
        pdf.ln(4)

        # Detailed reasoning for top anomalies
        _sub_hdr(pdf, "Anomaly Details & Forensic Reasoning")
        for a in real[:5]:
            owner = a.get("src_asset", "")
            src_label = f"{a['src_ip']}" + (f" ({owner})" if owner else "")
            pdf.set_fill_color(*_sev_color(a["severity"]))
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(*_WHITE)
            pdf.cell(0, 5, _s(f"  [{a['severity'].upper()}] {a['anomaly_type']} | {src_label} -> {a.get('dest_ip', '-')} | Confidence: {a['confidence']}"), fill=True, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*_TEXT)
            pdf.set_font("Helvetica", "", 8)
            pdf.multi_cell(0, 4, _s(f"  {a.get('reasoning', 'No reasoning available.')}"))
            pdf.ln(2)
    else:
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(*_SUCCESS)
        pdf.cell(0, 6, "No confirmed anomalies detected in this period.", new_x="LMARGIN", new_y="NEXT")

    # ================================================================
    # SECTION 4: EXTERNAL COMMUNICATION INSIGHTS
    # ================================================================
    pdf.add_page()
    _sec_hdr(pdf, "4", "External Communication Insights", _MEDIUM)

    # Country distribution
    _sub_hdr(pdf, "Geographic Distribution of External Traffic")
    countries = Counter()
    for ip, geo in geo_map.items():
        c = geo.get("country", "")
        if c:
            countries[c] += 1
    india_count = sum(1 for g in geo_map.values() if g.get("country_code") == "IN")
    intl_count = sum(1 for g in geo_map.values() if g.get("country_code") and g.get("country_code") != "IN")

    _metric_grid(pdf, [
        ("External IPs Resolved", f"{len(geo_map)}"),
        ("India (Domestic)", f"{india_count}"),
        ("International", f"{intl_count}"),
    ], cols=3)

    if countries:
        _tbl_hdr(pdf, ["Country", "External IPs", "Classification"], [60, 40, 40])
        for i, (country, count) in enumerate(countries.most_common(10)):
            cc = [g.get("country_code", "") for g in geo_map.values() if g.get("country") == country]
            code = cc[0] if cc else ""
            tag = "Domestic" if code == "IN" else "International"
            _tbl_row(pdf, [_s(country), str(count), tag], [60, 40, 40], i)
        pdf.ln(4)

    # Top external destinations with service mapping
    top_ext = tv.get("top_external_dst", [])
    if top_ext:
        _sub_hdr(pdf, "Top External Destinations (Enriched)")
        _tbl_hdr(pdf, ["IP", "Hostname", "Service", "Volume", "Country"], [30, 45, 25, 25, 30])
        for i, ext in enumerate(top_ext):
            ip = ext["ip"]
            hn = hostname_map.get(ip, {}).get("hostname", "")
            svc = hostname_map.get(ip, {}).get("service", "")
            geo = geo_map.get(ip, {})
            ctry = geo.get("country", "")
            _tbl_row(pdf, [ip, _s(hn[:28]), _s(svc[:16]), _fb(ext["bytes"]), _s(ctry[:18])], [30, 45, 25, 25, 30], i)
        pdf.ln(4)

    # Unknown/unresolved external IPs
    unknown_ext = [ip for ip in geo_map if ip not in hostname_map and not any(
        ip.startswith(p) for p in ("224.", "239.", "255.", "0."))]
    if unknown_ext:
        _sub_hdr(pdf, f"Unknown External IPs ({len(unknown_ext)} unresolved - higher risk)")
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*_TEXT)
        shown = unknown_ext[:20]
        for i in range(0, len(shown), 4):
            row = shown[i:i+4]
            pdf.cell(0, 5, _s("  " + "  |  ".join(row)), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # ================================================================
    # SECTION 5: INTERNAL ASSET ANALYSIS
    # ================================================================
    pdf.add_page()
    _sec_hdr(pdf, "5", "Internal Asset Analysis", _ACCENT)

    _sub_hdr(pdf, "Asset Risk Summary")
    _metric_grid(pdf, [
        ("Monitored Assets", str(s.get("monitored_assets", 0))),
        ("Critical Risk", str(s.get("critical_assets", 0))),
        ("Warning", str(s.get("warning_assets", 0))),
        ("Normal", str(s.get("normal_assets", 0))),
    ], cols=4)

    if data["asset_reports"]:
        _sub_hdr(pdf, "Asset Activity (ranked by risk)")
        _tbl_hdr(pdf, ["IP", "Owner", "Sent", "Recv", "Alerts", "Ext Peers", "Risk", "Key Findings"], [25, 22, 18, 18, 12, 14, 16, 55])
        for i, a in enumerate(data["asset_reports"][:20]):
            risk = a["risk_level"]
            _tbl_row(pdf, [
                a["ip"], _s((a["owner"] or "-")[:14]),
                _fb(a["bytes_out"]), _fb(a["bytes_in"]),
                str(a["alert_count"]), str(a["external_peer_count"]),
                risk.upper(), _s("; ".join(a["risk_reasons"])[:38]),
            ], [25, 22, 18, 18, 12, 14, 16, 55], i, sev_col_idx=6)
        pdf.ln(4)

    # Suspicious assets detail
    if data["suspicious_assets"]:
        _sub_hdr(pdf, "Assets Requiring Immediate Attention")
        for asset in data["suspicious_assets"][:8]:
            rc = _CRITICAL if asset["risk_level"] == "critical" else _MEDIUM
            pdf.set_fill_color(*rc)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(*_WHITE)
            label = f"  [{asset['risk_level'].upper()}] {asset['owner'] or ''} ({asset['ip']})"
            pdf.cell(0, 5, _s(label), fill=True, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*_TEXT)
            pdf.set_font("Helvetica", "", 7)
            for reason in asset["risk_reasons"]:
                pdf.cell(0, 4, _s(f"    - {reason}"), new_x="LMARGIN", new_y="NEXT")
            if asset["alerts"]:
                for al in asset["alerts"][:2]:
                    pdf.set_text_color(*_HIGH)
                    pdf.cell(0, 4, _s(f"    Alert: {al['signature']} (sev {al['severity']})"), new_x="LMARGIN", new_y="NEXT")
                    pdf.set_text_color(*_TEXT)
            pdf.ln(1)

    # ================================================================
    # SECTION 6: THREAT & ALERT SUMMARY
    # ================================================================
    pdf.add_page()
    _sec_hdr(pdf, "6", "Threat & Alert Summary", _CRITICAL)

    top_alerts = tt.get("top_alerts", [])
    if top_alerts:
        _sub_hdr(pdf, "Top 10 Critical & High Severity Alerts")
        _tbl_hdr(pdf, ["Time", "Signature", "Source", "Dest", "Sev", "SID"], [18, 60, 28, 28, 16, 18])
        for i, a in enumerate(top_alerts):
            sv = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}.get(a["severity"], "LOW")
            _tbl_row(pdf, [
                _ft(a.get("timestamp", ""))[-5:],
                _s(a["signature"][:40]),
                a["src_ip"], a["dest_ip"],
                sv, str(a.get("sid", "")),
            ], [18, 60, 28, 28, 16, 18], i, sev_col_idx=4)
        pdf.ln(4)

    # Alert category distribution
    categories = Counter(a.get("category", "unknown") for a in data.get("all_alerts", []))
    if categories:
        _sub_hdr(pdf, "Alert Category Distribution")
        _tbl_hdr(pdf, ["Category", "Count", "Percentage"], [70, 30, 30])
        total_a = sum(categories.values())
        for i, (cat, cnt) in enumerate(categories.most_common(10)):
            pct = f"{cnt/total_a*100:.1f}%" if total_a else "0%"
            _tbl_row(pdf, [_s(cat), str(cnt), pct], [70, 30, 30], i)
        pdf.ln(4)

    # Repeated offenders
    offenders = tt.get("repeated_offenders", [])
    if offenders:
        _sub_hdr(pdf, "Repeated Offenders (3+ Unique Signatures)")
        _tbl_hdr(pdf, ["Source IP", "Owner", "Int/Ext", "Unique Sigs", "Samples"], [28, 24, 14, 16, 80])
        for i, o in enumerate(offenders[:8]):
            owner = asset_map.get(o["ip"], {}).get("owner", "")
            loc = "INT" if o["internal"] else "EXT"
            sigs = "; ".join(o["signatures"][:2])
            _tbl_row(pdf, [o["ip"], _s(owner[:16]), loc, str(o["unique_signatures"]), _s(sigs[:50])], [28, 24, 14, 16, 80], i)

    # ================================================================
    # SECTION 7: NETWORK BEHAVIOR INSIGHTS
    # ================================================================
    pdf.add_page()
    _sec_hdr(pdf, "7", "Network Behavior Insights", _MEDIUM)

    # Transport protocol breakdown
    proto = tv.get("proto_breakdown", [])
    if proto:
        _sub_hdr(pdf, "Transport Protocol Distribution")
        _tbl_hdr(pdf, ["Protocol", "Volume", "Share"], [50, 50, 30])
        for i, p in enumerate(proto):
            _tbl_row(pdf, [p["proto"], _fb(p["bytes"]), f"{p['pct']}%"], [50, 50, 30], i)
        pdf.ln(4)

    # Top internal sources
    top_src = tv.get("top_internal_src", [])
    if top_src:
        _sub_hdr(pdf, "Top Internal Source IPs by Volume")
        _tbl_hdr(pdf, ["Internal IP", "Owner", "Bytes Sent"], [50, 50, 40])
        for i, src in enumerate(top_src):
            owner = asset_map.get(src["ip"], {}).get("owner", "")
            _tbl_row(pdf, [src["ip"], _s(owner or "-"), _fb(src["bytes"])], [50, 50, 40], i)
        pdf.ln(4)

    # Risk score breakdown
    _sub_hdr(pdf, "Risk Score Composition")
    # Risk meter bar
    bar_x, bar_y, bar_w, bar_h = 30, pdf.get_y(), 150, 10
    pdf.set_fill_color(230, 230, 235)
    pdf.rect(bar_x, bar_y, bar_w, bar_h, "F")
    fill_w = bar_w * score / 100
    pdf.set_fill_color(*_risk_color(score))
    pdf.rect(bar_x, bar_y, fill_w, bar_h, "F")
    pdf.set_y(bar_y + 1)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*_WHITE)
    pdf.cell(0, 7, f"{score}/100  ({risk_label.upper()})", align="C")
    pdf.set_y(bar_y + bar_h + 3)
    pdf.set_text_color(*_TEXT)

    comps = rs.get("components", {})
    _tbl_hdr(pdf, ["Component", "Count", "Weight", "Score"], [55, 25, 25, 25])
    for i, (name, c) in enumerate([
        ("Critical Alerts", comps.get("critical_alerts", {})),
        ("High Alerts", comps.get("high_alerts", {})),
        ("Medium Alerts", comps.get("medium_alerts", {})),
        ("Attacking IPs", comps.get("attacking_ips", {})),
    ]):
        _tbl_row(pdf, [name, str(c.get("count", 0)), f"{c.get('weight', 0)}%", str(c.get("score", 0))], [55, 25, 25, 25], i)

    # ================================================================
    # SECTION 8: RECOMMENDATIONS
    # ================================================================
    pdf.add_page()
    _sec_hdr(pdf, "8", "Recommendations", _SUCCESS)

    # Immediate actions
    _sub_hdr(pdf, "A. Immediate Actions Required")
    immediate = []
    if health == "Critical":
        immediate.append("Activate incident response procedures for all critical-severity findings.")
    if es.get("total_alerts", 0) > 100:
        immediate.append("Review and triage the high volume of alerts to identify true positives.")
    if s.get("critical_assets", 0) > 0:
        immediate.append(f"Immediately investigate {s['critical_assets']} critical-risk asset(s) for signs of compromise.")
    anom_real = anomaly_data.get("summary", {}).get("real_anomaly_count", 0)
    if anom_real > 0:
        immediate.append(f"Investigate {anom_real} confirmed anomalies — these represent real deviations from baseline behavior.")
    deprecated_tls = anomaly_data.get("summary", {}).get("deprecated_tls_pairs", 0)
    if deprecated_tls > 0:
        immediate.append(f"Remediate {deprecated_tls} deprecated TLS connection pair(s) to eliminate cryptographic vulnerabilities.")
    if not immediate:
        immediate.append("No immediate critical actions required. Maintain standard monitoring posture.")

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*_TEXT)
    for rec in immediate:
        pdf.cell(5, 5, "")
        pdf.cell(0, 5, _s(f"- {rec}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Recommendations from report data
    if data["recommendations"]:
        _sub_hdr(pdf, "B. Detailed Action Plan")
        _tbl_hdr(pdf, ["Priority", "Role", "Asset", "Action"], [18, 26, 24, 100])
        for i, rec in enumerate(data["recommendations"][:15]):
            _tbl_row(pdf, [
                rec["priority"].upper(),
                _s(rec["target_role"].replace("_", " ")),
                _s((rec["asset_owner"] or "")[:16]),
                _s(rec["action"][:65]),
            ], [18, 26, 24, 100], i, sev_col_idx=0)
        pdf.ln(4)

    # Strategic improvements
    _sub_hdr(pdf, "C. Strategic Improvements")
    strategic = [
        "Implement network segmentation to limit lateral movement between subnets.",
        "Deploy a Web Application Firewall (WAF) in front of internal web servers.",
        "Establish DNS query logging and monitoring on all internal resolvers.",
        "Add threat intelligence feeds for IP reputation scoring and automated blocking.",
        "Migrate all internal services from plaintext HTTP/FTP to encrypted protocols.",
        "Implement anomaly baselining with adaptive thresholds instead of static values.",
        "Deploy endpoint detection and response (EDR) on all identified critical assets.",
        "Conduct regular vulnerability assessments on exposed internal services.",
    ]
    pdf.set_font("Helvetica", "", 9)
    for rec in strategic:
        pdf.cell(5, 5, "")
        pdf.cell(0, 5, _s(f"- {rec}"), new_x="LMARGIN", new_y="NEXT")

    # ================================================================
    # SECTION 9: FINAL SECURITY ASSESSMENT
    # ================================================================
    pdf.add_page()
    _sec_hdr(pdf, "9", "Final Security Assessment", _NAVY)

    # Overall rating
    _sub_hdr(pdf, "Overall Risk Rating")
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*_risk_color(score))
    pdf.cell(0, 8, f"{risk_label.upper()} ({score}/100)", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Key concerns
    _sub_hdr(pdf, "Key Concerns")
    concerns = []
    if es.get("total_alerts", 0) > 50:
        concerns.append(f"Alert volume ({es['total_alerts']}) indicates active threats or noisy rules requiring tuning.")
    if s.get("critical_assets", 0) > 0:
        concerns.append(f"{s['critical_assets']} asset(s) at critical risk level require immediate attention.")
    if intl_count > india_count:
        concerns.append(f"More international destinations ({intl_count}) than domestic ({india_count}) — verify all foreign connections are authorized.")
    if anom_real > 0:
        concerns.append(f"{anom_real} confirmed anomalies detected — behavioral deviations from expected baseline.")
    if deprecated_tls > 0:
        concerns.append(f"Deprecated TLS versions in active use — cryptographic vulnerabilities present.")
    if len(unknown_ext) > 10:
        concerns.append(f"{len(unknown_ext)} unresolved external IPs with no hostname — potential unknown threats.")
    if not concerns:
        concerns.append("No critical concerns identified. Network operating within acceptable risk parameters.")

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*_TEXT)
    for c in concerns:
        pdf.cell(5, 5, "")
        pdf.cell(0, 5, _s(f"- {c}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Confidence level
    _sub_hdr(pdf, "Detection Confidence")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*_TEXT)
    pdf.multi_cell(0, 5, _s(
        f"Detections are based on {len(anomaly_data.get('real_anomalies', []))} anomaly indicators, "
        f"{es.get('total_alerts', 0)} detection rule matches, and behavioral analysis across "
        f"{es.get('total_flows', 0):,} network flows. "
        f"Hostname resolution covered {len(hostname_map)} external IPs via DNS/TLS/HTTP correlation. "
        f"Geo-intelligence enriched {len(geo_map)} external IPs across {len(countries)} countries."
    ))
    pdf.ln(4)

    # Organizational readiness
    _sub_hdr(pdf, "Organizational Readiness Assessment")
    readiness = []
    readiness.append(("Asset Visibility", "Moderate" if len(asset_map) > 20 else "Low", f"{len(asset_map)} assets identified"))
    readiness.append(("Detection Coverage", "High", "NOTICE engine + 80,000+ threat signatures + 77 custom rules"))
    readiness.append(("Anomaly Detection", "Active", f"{anomaly_data['summary']['total_anomalies']} anomalies tracked"))
    readiness.append(("Incident Response", "Available", "NOTICE tool with SLA tracking"))
    readiness.append(("Threat Intelligence", "Partial", "Service mapping + GeoIP active, no external TI feeds"))

    _tbl_hdr(pdf, ["Capability", "Status", "Details"], [50, 30, 80])
    for i, (cap, status, detail) in enumerate(readiness):
        _tbl_row(pdf, [cap, status, _s(detail)], [50, 30, 80], i)

    # End of report
    pdf.ln(10)
    pdf.set_fill_color(*_NAVY)
    pdf.rect(30, pdf.get_y(), 150, 0.5, "F")
    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*_DIM)
    pdf.cell(0, 5, "--- End of Report ---", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, f"Prepared by NOTICE Security Monitor | Cyber Manthan - IIIT Hyderabad | {_ft(data.get('report_time', ''))}", align="C")

    return pdf.output()


# ============================================================================
# PDF Helper Functions
# ============================================================================

def _text_logo(pdf):
    """Render text-based branding when no logo image is available."""
    pdf.set_y(38)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*_GOLD)
    pdf.cell(0, 10, "CYBER MANTHAN", align="C")
    pdf.ln(8)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(180, 185, 200)
    pdf.cell(0, 6, "IIIT Hyderabad", align="C")
    pdf.ln(4)
    # Accent underline
    pdf.set_fill_color(*_GOLD)
    pdf.rect(80, pdf.get_y(), 50, 1, "F")


def _generate_business_impact(es, rs, s):
    """Generate business-impact statement for executives."""
    score = rs.get("risk_score", 0)
    alerts = es.get("total_alerts", 0)
    critical = s.get("critical_assets", 0)

    if score >= 75:
        impact = (
            "The current risk score of {}/100 represents a CRITICAL security posture. "
            "Active threats have been detected that may lead to data breach, service disruption, "
            "or unauthorized access to corporate resources. Immediate containment and investigation "
            "is required to prevent potential financial and reputational damage."
        ).format(score)
    elif score >= 50:
        impact = (
            "The risk score of {}/100 indicates HIGH risk. Multiple security concerns have been "
            "identified that require prompt attention. Without remediation, these vulnerabilities "
            "could be exploited, potentially impacting business continuity and data integrity."
        ).format(score)
    elif score >= 25:
        impact = (
            "The risk score of {}/100 indicates MODERATE risk. While no critical threats are "
            "immediately apparent, several areas require attention to maintain a robust security "
            "posture. Proactive remediation is recommended to reduce exposure."
        ).format(score)
    else:
        impact = (
            "The risk score of {}/100 indicates LOW risk. The network is operating within "
            "acceptable security parameters. Routine monitoring and periodic review of "
            "security controls is recommended to maintain this positive posture."
        ).format(score)

    if critical > 0:
        impact += f" {critical} asset(s) have been flagged at critical risk level, requiring priority investigation."

    return impact


def _sec_hdr(pdf, number, title, color):
    """Render a styled section header with number badge."""
    y = pdf.get_y()
    pdf.set_fill_color(*_DARK_SURFACE)
    pdf.rect(10, y, 190, 10, "F")
    pdf.set_fill_color(*color)
    pdf.rect(10, y, 22, 10, "F")
    pdf.set_y(y + 1.5)
    pdf.set_x(10)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*_WHITE)
    pdf.cell(22, 7, f"  {number}", align="L")
    pdf.cell(0, 7, f"  {title}")
    pdf.ln(14)
    pdf.set_text_color(*_TEXT)


def _sub_hdr(pdf, title):
    """Render a sub-section header."""
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*_ACCENT)
    pdf.cell(0, 6, title, new_x="LMARGIN", new_y="NEXT")
    pdf.set_fill_color(*_ACCENT)
    pdf.rect(10, pdf.get_y(), 40, 0.4, "F")
    pdf.ln(3)
    pdf.set_text_color(*_TEXT)


def _tbl_hdr(pdf, headers, widths):
    """Render table header row."""
    pdf.set_fill_color(*_NAVY)
    pdf.set_text_color(*_WHITE)
    pdf.set_font("Helvetica", "B", 7)
    for i, h in enumerate(headers):
        w = widths[i] if i < len(widths) else 30
        pdf.cell(w, 6, h, fill=True)
    pdf.ln()
    pdf.set_text_color(*_TEXT)


def _tbl_row(pdf, values, widths, idx, sev_col_idx=None):
    """Render table data row with alternating backgrounds."""
    if idx % 2 == 1:
        pdf.set_fill_color(*_ROW_ALT)
    else:
        pdf.set_fill_color(*_WHITE)
    pdf.set_font("Helvetica", "", 7)
    for i, v in enumerate(values):
        w = widths[i] if i < len(widths) else 30
        if i == sev_col_idx:
            u = str(v).upper().strip()
            if u in ("CRITICAL", "1"):
                pdf.set_text_color(*_CRITICAL)
                pdf.set_font("Helvetica", "B", 7)
            elif u in ("HIGH", "2"):
                pdf.set_text_color(*_HIGH)
                pdf.set_font("Helvetica", "B", 7)
            elif u in ("MEDIUM", "3", "WARNING"):
                pdf.set_text_color(*_MEDIUM)
                pdf.set_font("Helvetica", "B", 7)
            elif u in ("LOW", "NORMAL"):
                pdf.set_text_color(*_LOW)
                pdf.set_font("Helvetica", "B", 7)
            else:
                pdf.set_text_color(*_TEXT)
            pdf.cell(w, 5, _s(v), fill=True)
            pdf.set_text_color(*_TEXT)
            pdf.set_font("Helvetica", "", 7)
        else:
            pdf.set_text_color(*_TEXT)
            pdf.cell(w, 5, _s(v), fill=True)
    pdf.ln()


def _metric_grid(pdf, metrics, cols=3):
    """Render metrics in a grid of cards."""
    col_w = (190 - (cols - 1) * 4) / cols
    card_h = 14
    gap = 3
    start_y = pdf.get_y()
    rows = (len(metrics) + cols - 1) // cols

    if start_y + rows * (card_h + gap) > 270:
        pdf.add_page()
        start_y = pdf.get_y()

    for i, (label, value) in enumerate(metrics):
        row = i // cols
        col = i % cols
        x = 10 + col * (col_w + 4)
        y = start_y + row * (card_h + gap)

        pdf.set_fill_color(*_ROW_ALT)
        pdf.rect(x, y, col_w, card_h, "F")
        pdf.set_draw_color(*_BORDER)
        pdf.rect(x, y, col_w, card_h, "D")

        pdf.set_xy(x + 3, y + 1.5)
        pdf.set_font("Helvetica", "", 6)
        pdf.set_text_color(*_DIM)
        pdf.cell(col_w - 6, 4, label.upper())

        pdf.set_xy(x + 3, y + 6.5)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*_TEXT)
        pdf.cell(col_w - 6, 5, _s(value))

    pdf.set_y(start_y + rows * (card_h + gap) + 2)
    pdf.set_text_color(*_TEXT)
