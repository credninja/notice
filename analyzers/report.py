"""
Shift/overnight report generator — enhanced for management reporting.
Compiles monitored asset activity, executive summary, top threats,
network traffic overview, risk scoring, and action plans.
"""

from collections import defaultdict, Counter
from datetime import datetime
from eve_reader import iter_events, is_internal, is_ipv4
from db import get_db


def generate_report(minutes=720):
    """
    Generate a comprehensive management report covering the last N minutes.
    Returns structured report data for rendering and PDF generation.
    """
    conn = get_db()
    asset_rows = conn.execute("SELECT * FROM assets").fetchall()
    asset_map = {r["ip"]: dict(r) for r in asset_rows}

    action_rows = conn.execute("SELECT * FROM action_items ORDER BY created_at DESC").fetchall()
    action_items = [dict(r) for r in action_rows]

    incident_rows = conn.execute(
        "SELECT * FROM incidents ORDER BY created_at DESC LIMIT 20"
    ).fetchall()
    incidents = [dict(r) for r in incident_rows]
    conn.close()

    # --- Per-asset activity tracking ---
    asset_activity = defaultdict(lambda: {
        "bytes_out": 0, "bytes_in": 0, "flows": 0,
        "protocols": set(), "app_protos": set(),
        "peers": set(), "external_peers": set(),
        "alerts": [], "anomalies": [],
        "http_requests": 0, "dns_queries": 0,
        "tls_deprecated": 0, "plaintext_flows": 0,
        "first_seen": None, "last_seen": None,
    })

    # --- Global counters for management sections ---
    total_bytes = 0
    total_bytes_inbound = 0
    total_bytes_outbound = 0
    total_flows = 0
    total_alerts = 0
    all_alerts = []

    # Protocol counters
    proto_bytes = Counter()     # TCP/UDP/ICMP etc
    app_proto_bytes = Counter() # http/dns/tls etc

    # IP traffic volume tracking
    src_ip_bytes = Counter()
    dst_ip_bytes = Counter()

    # Unique flagged IPs
    flagged_src_ips = set()
    flagged_dst_ips = set()

    # Targeted internal hosts
    targeted_internal = Counter()

    # Severity counters
    severity_counts = Counter()  # 1=critical, 2=high, 3=medium, 4+=low

    # Hourly traffic for peak detection
    hourly_events = Counter()

    # Attacker IPs (unique external sources of alerts)
    attacking_ips = set()

    # ET Pro rule tracking
    et_pro_alerts = []

    # Repeated offenders: src_ip -> set of signatures
    offender_sigs = defaultdict(set)

    for ev in iter_events(minutes=minutes):
        etype = ev.get("event_type")
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        ts = ev.get("timestamp", "")
        proto = ev.get("proto", "")

        if not is_ipv4(src) or not is_ipv4(dst):
            continue

        # Hourly bucket
        if ts:
            try:
                hour_key = ts[:13]  # YYYY-MM-DDTHH
                hourly_events[hour_key] += 1
            except Exception:
                pass

        # Track activity for known assets
        for ip in (src, dst):
            if ip not in asset_map:
                continue
            a = asset_activity[ip]
            if not a["first_seen"] or ts < a["first_seen"]:
                a["first_seen"] = ts
            if not a["last_seen"] or ts > a["last_seen"]:
                a["last_seen"] = ts

        if etype == "flow":
            flow = ev.get("flow", {})
            b_out = flow.get("bytes_toserver", 0)
            b_in = flow.get("bytes_toclient", 0)
            total_bytes += b_out + b_in
            total_flows += 1
            app_proto = ev.get("app_proto", "")

            # Track directional bytes
            if is_internal(src) and not is_internal(dst):
                total_bytes_outbound += b_out
                total_bytes_inbound += b_in
            elif not is_internal(src) and is_internal(dst):
                total_bytes_inbound += b_out
                total_bytes_outbound += b_in

            # Protocol tracking
            if proto:
                proto_bytes[proto] += b_out + b_in
            if app_proto and app_proto != "failed":
                app_proto_bytes[app_proto] += b_out + b_in

            # IP volume tracking
            src_ip_bytes[src] += b_out
            dst_ip_bytes[dst] += b_in + b_out

            for ip in (src, dst):
                if ip not in asset_map:
                    continue
                a = asset_activity[ip]
                if ip == src:
                    a["bytes_out"] += b_out
                    a["bytes_in"] += b_in
                else:
                    a["bytes_in"] += b_out
                    a["bytes_out"] += b_in
                a["flows"] += 1
                if proto:
                    a["protocols"].add(proto)
                if app_proto and app_proto != "failed":
                    a["app_protos"].add(app_proto)
                peer = dst if ip == src else src
                a["peers"].add(peer)
                if not is_internal(peer):
                    a["external_peers"].add(peer)
                if app_proto == "http" and ev.get("dest_port") == 80:
                    a["plaintext_flows"] += 1

        elif etype == "alert":
            total_alerts += 1
            alert = ev.get("alert", {})
            severity = alert.get("severity", 3)
            sig = alert.get("signature", "")
            sid = alert.get("signature_id", 0)
            category = alert.get("category", "")

            severity_counts[severity] += 1

            entry = {
                "timestamp": ts,
                "src_ip": src, "dest_ip": dst,
                "signature": sig,
                "severity": severity,
                "category": category,
                "action": alert.get("action", ""),
                "sid": sid,
                "proto": proto,
            }
            all_alerts.append(entry)

            # Track flagged IPs
            flagged_src_ips.add(src)
            flagged_dst_ips.add(dst)

            # Targeted internal hosts
            if is_internal(dst):
                targeted_internal[dst] += 1

            # Attacking IPs
            if not is_internal(src):
                attacking_ips.add(src)

            # ET Pro tracking (SIDs 2800000-2900000)
            if 2800000 <= sid <= 2900000:
                et_pro_alerts.append(entry)

            # Repeated offender tracking
            offender_sigs[src].add(sig)

            for ip in (src, dst):
                if ip in asset_map:
                    asset_activity[ip]["alerts"].append(entry)

        elif etype == "http":
            for ip in (src, dst):
                if ip in asset_map:
                    asset_activity[ip]["http_requests"] += 1

        elif etype == "dns":
            dns = ev.get("dns", {})
            if dns.get("type") == "request":
                if src in asset_map:
                    asset_activity[src]["dns_queries"] += 1

        elif etype == "tls":
            tls = ev.get("tls", {})
            version = tls.get("version", "")
            if version in ("TLSv1", "TLS 1.0", "TLS 1.1"):
                for ip in (src, dst):
                    if ip in asset_map:
                        asset_activity[ip]["tls_deprecated"] += 1

        elif etype == "anomaly":
            anom = ev.get("anomaly", {})
            for ip in (src, dst):
                if ip in asset_map:
                    asset_activity[ip]["anomalies"].append({
                        "timestamp": ts, "event": anom.get("event", ""),
                        "peer": dst if ip == src else src,
                    })

    # --- Build monitored asset report ---
    asset_reports = []
    for ip, asset in asset_map.items():
        if asset.get("scope") == "external":
            continue
        act = asset_activity[ip]
        if not act["flows"] and not act["alerts"]:
            continue

        risk_level = "normal"
        risk_reasons = []

        if act["alerts"]:
            sev1 = sum(1 for a in act["alerts"] if a["severity"] <= 2)
            if sev1 > 0:
                risk_level = "critical"
                risk_reasons.append(f"{sev1} high-severity alert(s)")
            else:
                risk_level = "warning"
                risk_reasons.append(f"{len(act['alerts'])} alert(s)")

        if act["plaintext_flows"] > 0:
            if risk_level == "normal":
                risk_level = "warning"
            risk_reasons.append(f"{act['plaintext_flows']} plaintext HTTP flows")

        if act["tls_deprecated"] > 0:
            if risk_level == "normal":
                risk_level = "warning"
            risk_reasons.append(f"{act['tls_deprecated']} deprecated TLS connections")

        if len(act["external_peers"]) > 50:
            if risk_level == "normal":
                risk_level = "warning"
            risk_reasons.append(f"high external peer count ({len(act['external_peers'])})")

        if len(act["anomalies"]) > 10:
            if risk_level == "normal":
                risk_level = "warning"
            risk_reasons.append(f"{len(act['anomalies'])} protocol anomalies")

        asset_reports.append({
            "ip": ip,
            "owner": asset.get("owner", ""),
            "hostname": asset.get("hostname", ""),
            "asset_type": asset.get("asset_type", ""),
            "department": asset.get("department", ""),
            "bytes_out": act["bytes_out"],
            "bytes_in": act["bytes_in"],
            "flows": act["flows"],
            "protocols": list(act["app_protos"]),
            "peer_count": len(act["peers"]),
            "external_peer_count": len(act["external_peers"]),
            "alert_count": len(act["alerts"]),
            "alerts": act["alerts"][:5],
            "anomaly_count": len(act["anomalies"]),
            "http_requests": act["http_requests"],
            "dns_queries": act["dns_queries"],
            "plaintext_flows": act["plaintext_flows"],
            "tls_deprecated": act["tls_deprecated"],
            "first_seen": act["first_seen"],
            "last_seen": act["last_seen"],
            "risk_level": risk_level,
            "risk_reasons": risk_reasons,
        })

    asset_reports.sort(key=lambda x: {"critical": 0, "warning": 1, "normal": 2}[x["risk_level"]])
    suspicious = [a for a in asset_reports if a["risk_level"] in ("critical", "warning")]
    recommendations = _generate_recommendations(asset_reports, all_alerts)

    # --- Action items ---
    open_items = [a for a in action_items if a["status"] in ("open", "in_progress")]
    completed_items = [a for a in action_items if a["status"] == "completed"]
    overdue_items = [a for a in action_items if a["sla_breached"]]

    now = datetime.now().isoformat()
    for item in open_items:
        if item["due_at"] and item["due_at"] < now and not item["sla_breached"]:
            item["sla_breached"] = 1
            item["status"] = "overdue"
            db = get_db()
            db.execute(
                "UPDATE action_items SET sla_breached=1, status='overdue', updated_at=datetime('now','localtime') WHERE id=?",
                (item["id"],))
            db.commit()
            db.close()
            overdue_items.append(item)

    # =============================================
    # MANAGEMENT REPORT SECTIONS
    # =============================================

    # --- Section 1: Executive Summary ---
    crit_count = severity_counts.get(1, 0)
    high_count = severity_counts.get(2, 0)
    med_count = severity_counts.get(3, 0)
    low_count = sum(v for k, v in severity_counts.items() if k >= 4)

    if crit_count > 0:
        health_status = "Critical"
    elif high_count > 5:
        health_status = "At Risk"
    elif high_count > 0 or med_count > 20:
        health_status = "At Risk"
    else:
        health_status = "Healthy"

    alert_rate = round((total_alerts / total_flows * 100), 4) if total_flows > 0 else 0

    top_targeted = targeted_internal.most_common(10)

    # Auto-generated situational summary
    exec_paragraph = _generate_executive_paragraph(
        health_status, total_flows, total_alerts, crit_count, high_count,
        len(flagged_src_ips), len(attacking_ips), top_targeted, minutes
    )

    executive_summary = {
        "health_status": health_status,
        "total_events": total_flows + total_alerts,
        "total_flows": total_flows,
        "total_alerts": total_alerts,
        "unique_src_flagged": len(flagged_src_ips),
        "unique_dst_flagged": len(flagged_dst_ips),
        "alert_rate_pct": alert_rate,
        "top_targeted_internal": [{"ip": ip, "count": c} for ip, c in top_targeted],
        "paragraph": exec_paragraph,
    }

    # --- Section 2: Top Threats & Alerts ---
    # Sort alerts by severity (ascending = most critical first), then by timestamp (newest)
    sorted_alerts = sorted(all_alerts, key=lambda a: (a["severity"], a.get("timestamp", "") or ""))
    top_threats = sorted_alerts[:10]

    # Repeated offenders: IPs triggering 3+ different signatures
    repeated_offenders = []
    for src_ip, sigs in offender_sigs.items():
        if len(sigs) >= 3:
            repeated_offenders.append({
                "ip": src_ip,
                "internal": is_internal(src_ip),
                "unique_signatures": len(sigs),
                "signatures": list(sigs)[:5],
            })
    repeated_offenders.sort(key=lambda x: x["unique_signatures"], reverse=True)

    top_threats_section = {
        "top_alerts": top_threats,
        "et_pro_alerts": et_pro_alerts[:10],
        "repeated_offenders": repeated_offenders[:10],
    }

    # --- Section 3: Network Traffic Overview ---
    # Top 5 internal source IPs by volume
    top_internal_src = [
        {"ip": ip, "bytes": b}
        for ip, b in src_ip_bytes.most_common(50)
        if is_internal(ip)
    ][:5]

    # Top 5 external destination IPs by volume
    top_external_dst = [
        {"ip": ip, "bytes": b}
        for ip, b in dst_ip_bytes.most_common(50)
        if not is_internal(ip)
    ][:5]

    # Peak traffic window
    peak_hour = hourly_events.most_common(1)[0] if hourly_events else ("N/A", 0)

    # Protocol breakdown
    proto_breakdown = [
        {"proto": p, "bytes": b, "pct": round(b / total_bytes * 100, 1) if total_bytes else 0}
        for p, b in proto_bytes.most_common(10)
    ]
    app_proto_breakdown = [
        {"proto": p, "bytes": b, "pct": round(b / total_bytes * 100, 1) if total_bytes else 0}
        for p, b in app_proto_bytes.most_common(10)
    ]

    # Anomalous patterns
    anomalies_detected = []
    if total_bytes_outbound > total_bytes_inbound * 3 and total_bytes_outbound > 100_000_000:
        anomalies_detected.append("Outbound traffic volume is 3x+ higher than inbound — possible data exfiltration")
    high_port_external = sum(1 for a in all_alerts if "Uncommon High Port" in a.get("signature", ""))
    if high_port_external > 10:
        anomalies_detected.append(f"{high_port_external} connections on uncommon high ports to external hosts")
    dns_tunnel_alerts = sum(1 for a in all_alerts if "DNS Tunnel" in a.get("signature", "") or "DNS Query with Long Subdomain" in a.get("signature", ""))
    if dns_tunnel_alerts > 0:
        anomalies_detected.append(f"{dns_tunnel_alerts} potential DNS tunneling indicators detected")

    traffic_overview = {
        "total_bytes_inbound": total_bytes_inbound,
        "total_bytes_outbound": total_bytes_outbound,
        "total_bytes": total_bytes,
        "proto_breakdown": proto_breakdown,
        "app_proto_breakdown": app_proto_breakdown,
        "top_internal_src": top_internal_src,
        "top_external_dst": top_external_dst,
        "peak_hour": peak_hour[0],
        "peak_hour_events": peak_hour[1],
        "anomalies_detected": anomalies_detected,
    }

    # --- Section 4: Risk Score & Severity Breakdown ---
    # Risk score 0-100:
    # Critical alerts: 40% weight (each critical = 8 points, max 40)
    # High alerts: 30% weight (each high = 3 points, max 30)
    # Medium alerts: 20% weight (each medium = 1 point, max 20)
    # Unique attacking IPs: 10% weight (each = 2 points, max 10)
    risk_critical_component = min(crit_count * 8, 40)
    risk_high_component = min(high_count * 3, 30)
    risk_medium_component = min(med_count * 1, 20)
    risk_ip_component = min(len(attacking_ips) * 2, 10)
    risk_score = risk_critical_component + risk_high_component + risk_medium_component + risk_ip_component

    if risk_score >= 75:
        risk_label = "Critical"
    elif risk_score >= 50:
        risk_label = "High"
    elif risk_score >= 25:
        risk_label = "Medium"
    else:
        risk_label = "Low"

    total_sev = crit_count + high_count + med_count + low_count
    risk_section = {
        "risk_score": risk_score,
        "risk_label": risk_label,
        "components": {
            "critical_alerts": {"count": crit_count, "weight": 40, "score": risk_critical_component},
            "high_alerts": {"count": high_count, "weight": 30, "score": risk_high_component},
            "medium_alerts": {"count": med_count, "weight": 20, "score": risk_medium_component},
            "attacking_ips": {"count": len(attacking_ips), "weight": 10, "score": risk_ip_component},
        },
        "severity_distribution": {
            "critical": {"count": crit_count, "pct": round(crit_count / total_sev * 100, 1) if total_sev else 0},
            "high": {"count": high_count, "pct": round(high_count / total_sev * 100, 1) if total_sev else 0},
            "medium": {"count": med_count, "pct": round(med_count / total_sev * 100, 1) if total_sev else 0},
            "low": {"count": low_count, "pct": round(low_count / total_sev * 100, 1) if total_sev else 0},
        },
        "trend": "stable",  # placeholder — would compare to previous period
    }

    return {
        "report_time": datetime.now().isoformat(),
        "period_minutes": minutes,
        "summary": {
            "total_bytes": total_bytes,
            "total_flows": total_flows,
            "total_alerts": total_alerts,
            "monitored_assets": len(asset_reports),
            "critical_assets": sum(1 for a in asset_reports if a["risk_level"] == "critical"),
            "warning_assets": sum(1 for a in asset_reports if a["risk_level"] == "warning"),
            "normal_assets": sum(1 for a in asset_reports if a["risk_level"] == "normal"),
        },
        "executive_summary": executive_summary,
        "top_threats": top_threats_section,
        "traffic_overview": traffic_overview,
        "risk_score": risk_section,
        "asset_reports": asset_reports,
        "suspicious_assets": suspicious,
        "all_alerts": all_alerts[-50:],
        "recommendations": recommendations,
        "action_items": {
            "open": open_items,
            "completed": completed_items,
            "overdue": overdue_items,
            "total": len(action_items),
        },
    }


def _generate_executive_paragraph(health, flows, alerts, crit, high, flagged_src, attackers, targeted, minutes):
    """Generate a plain-language executive summary paragraph."""
    period = f"{minutes} minutes" if minutes < 1440 else f"{minutes // 60} hours" if minutes < 10080 else f"{minutes // 1440} days"

    if health == "Critical":
        opener = f"The network security posture is currently CRITICAL. Over the past {period}, the monitoring system detected {crit} critical-severity and {high} high-severity security events requiring immediate attention."
    elif health == "At Risk":
        opener = f"The network is currently at elevated risk. Over the past {period}, {alerts:,} security alerts were generated from {flows:,} network flows, including {high} high-severity events."
    else:
        opener = f"The network is operating within normal security parameters. Over the past {period}, {flows:,} network flows were monitored with {alerts:,} alerts generated, none at critical severity."

    details = []
    if attackers > 0:
        details.append(f"{attackers} unique external IP address{'es' if attackers != 1 else ''} triggered security rules")
    if flagged_src > 0:
        details.append(f"{flagged_src} unique source IPs were flagged across all alerts")
    if targeted:
        top3 = ", ".join(ip for ip, _ in targeted[:3])
        details.append(f"the most targeted internal hosts were {top3}")

    detail_str = ". ".join(details) + "." if details else ""

    if health == "Critical":
        closing = " Immediate investigation and containment actions are recommended for all critical-severity findings."
    elif health == "At Risk":
        closing = " Review of flagged assets and recommended actions is advised before the next reporting period."
    else:
        closing = " No immediate action is required, though routine review of monitoring data is recommended."

    return f"{opener} {detail_str}{closing}"


def _generate_recommendations(asset_reports, alerts):
    """Auto-generate action recommendations based on findings."""
    recs = []

    for asset in asset_reports:
        if asset["risk_level"] == "critical":
            recs.append({
                "priority": "critical",
                "target_role": "asset_custodian",
                "asset_ip": asset["ip"],
                "asset_owner": asset["owner"] or asset["ip"],
                "action": f"Immediately investigate {asset['owner'] or asset['ip']} ({asset['ip']}) — {'; '.join(asset['risk_reasons'])}",
                "detail": "Isolate the host if compromise is confirmed. Preserve logs for forensic analysis.",
            })
            recs.append({
                "priority": "high",
                "target_role": "network_admin",
                "asset_ip": asset["ip"],
                "asset_owner": asset["owner"] or asset["ip"],
                "action": f"Review firewall logs and consider blocking suspicious external peers of {asset['ip']}",
                "detail": f"Host has {asset['external_peer_count']} external connections. Check for unauthorized outbound traffic.",
            })

        if asset["plaintext_flows"] > 0:
            recs.append({
                "priority": "medium",
                "target_role": "asset_custodian",
                "asset_ip": asset["ip"],
                "asset_owner": asset["owner"] or asset["ip"],
                "action": f"Migrate {asset['owner'] or asset['ip']} from plaintext HTTP to HTTPS ({asset['plaintext_flows']} unencrypted flows)",
                "detail": "Plaintext traffic exposes credentials and data to interception.",
            })

        if asset["tls_deprecated"] > 0:
            recs.append({
                "priority": "medium",
                "target_role": "network_admin",
                "asset_ip": asset["ip"],
                "asset_owner": asset["owner"] or asset["ip"],
                "action": f"Upgrade TLS configuration for {asset['ip']} — {asset['tls_deprecated']} deprecated TLS connections",
                "detail": "Deprecated TLS v1.0/1.1 is vulnerable to POODLE, BEAST, and other attacks.",
            })

    prio_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    recs.sort(key=lambda x: prio_order.get(x["priority"], 4))
    return recs
