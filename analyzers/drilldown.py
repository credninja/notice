"""
Drill-down analysis engine for management Q1-Q10 interrogation.
Single-pass event scan that structures data for each question.
"""

from collections import defaultdict
from datetime import datetime
from eve_reader import iter_events, is_internal, is_ipv4
from db import get_db
from analyzers.geoip import lookup_batch


def compute_drilldown(minutes=1440):
    """Compute all Q1-Q10 drill-down data in a single pass."""

    # Load DB context
    conn = get_db()
    asset_rows = conn.execute("SELECT * FROM assets").fetchall()
    asset_map = {r["ip"]: dict(r) for r in asset_rows}

    verdict_rows = conn.execute("SELECT * FROM alert_verdicts").fetchall()
    verdict_map = {}
    for v in verdict_rows:
        key = (v["signature_id"], v["src_ip"], v["dest_ip"])
        verdict_map[key] = dict(v)

    incident_rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
    incidents = [dict(r) for r in incident_rows]

    action_rows = conn.execute("SELECT * FROM action_items ORDER BY created_at DESC").fetchall()
    action_items = [dict(r) for r in action_rows]

    inc_note_counts = {}
    for inc in incidents:
        cnt = conn.execute("SELECT COUNT(*) FROM incident_notes WHERE incident_id=?", (inc["id"],)).fetchone()[0]
        inc_note_counts[inc["id"]] = cnt
    conn.close()

    # Single-pass event collection
    alerts = []
    alert_src_count = defaultdict(int)
    alert_dst_count = defaultdict(int)
    external_alert_ips = set()

    # For lateral movement: track which internal IPs connect to which other internal IPs
    internal_connections = defaultdict(set)  # ip -> set of internal peers
    alerted_ips = set()

    # For exfiltration: track outbound bytes per internal IP
    outbound_bytes = defaultdict(int)
    dns_query_count = defaultdict(int)
    dns_long_domains = defaultdict(int)

    # Internal suspicious
    internal_alerts = []
    nmap_sources = defaultdict(lambda: {"targets": set(), "software": set()})

    total_flows = 0
    total_bytes = 0

    for ev in iter_events(minutes=minutes):
        etype = ev.get("event_type")
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        ts = ev.get("timestamp", "")

        if not is_ipv4(src) or not is_ipv4(dst):
            continue

        src_int = is_internal(src)
        dst_int = is_internal(dst)

        if etype == "alert":
            alert_data = ev.get("alert", {})
            sig_id = alert_data.get("signature_id", 0)
            vkey = (sig_id, src, dst)
            verdict_info = verdict_map.get(vkey, {})

            entry = {
                "timestamp": ts,
                "src_ip": src, "dest_ip": dst,
                "src_port": ev.get("src_port"), "dest_port": ev.get("dest_port"),
                "proto": ev.get("proto", ""),
                "signature": alert_data.get("signature", ""),
                "signature_id": sig_id,
                "severity": alert_data.get("severity", 3),
                "category": alert_data.get("category", ""),
                "action": alert_data.get("action", ""),
                "verdict": verdict_info.get("verdict", "investigating"),
                "src_internal": src_int, "dest_internal": dst_int,
                "src_owner": asset_map.get(src, {}).get("owner", ""),
                "src_hostname": asset_map.get(src, {}).get("hostname", ""),
                "dst_owner": asset_map.get(dst, {}).get("owner", ""),
                "dst_hostname": asset_map.get(dst, {}).get("hostname", ""),
                "src_identified": src in asset_map,
                "dst_identified": dst in asset_map,
                "src_business_critical": asset_map.get(src, {}).get("business_critical", 0),
                "dst_business_critical": asset_map.get(dst, {}).get("business_critical", 0),
            }
            alerts.append(entry)
            alert_src_count[src] += 1
            alert_dst_count[dst] += 1
            alerted_ips.add(src)
            alerted_ips.add(dst)

            if not src_int:
                external_alert_ips.add(src)
            if not dst_int:
                external_alert_ips.add(dst)

            # Internal-to-internal alerts
            if src_int and dst_int:
                internal_alerts.append(entry)

        elif etype == "flow":
            flow = ev.get("flow", {})
            b_out = flow.get("bytes_toserver", 0)
            b_in = flow.get("bytes_toclient", 0)
            total_flows += 1
            total_bytes += b_out + b_in

            if src_int and dst_int:
                internal_connections[src].add(dst)
                internal_connections[dst].add(src)

            # Outbound bytes from internal to external
            if src_int and not dst_int:
                outbound_bytes[src] += b_out
            if dst_int and not src_int:
                outbound_bytes[dst] += b_in

        elif etype == "dns":
            dns = ev.get("dns", {})
            if dns.get("type") == "request" and src_int:
                dns_query_count[src] += 1
                for q in dns.get("queries", []):
                    if len(q.get("rrname", "")) > 60:
                        dns_long_domains[src] += 1

        elif etype == "ssh":
            ssh = ev.get("ssh", {})
            client_sw = ssh.get("client", {}).get("software_version", "")
            if "nmap" in client_sw.lower() and src_int:
                nmap_sources[src]["targets"].add(dst)
                nmap_sources[src]["software"].add(client_sw)

    # Sort alerts by severity then timestamp
    alerts.sort(key=lambda a: (a["severity"], a["timestamp"]))

    # === Q1: Alert Summary ===
    by_severity = defaultdict(int)
    for a in alerts:
        by_severity[a["severity"]] += 1
    crit_high = by_severity.get(1, 0) + by_severity.get(2, 0)
    q1_answer = f"Yes, {len(alerts)} alert(s). {crit_high} critical/high." if alerts else "No alerts detected. Check monitoring health and logging gaps."
    q1_color = "red" if crit_high > 0 else ("amber" if alerts else "green")

    # === Q2: Verdicts ===
    tp = sum(1 for a in alerts if a["verdict"] == "true_positive")
    fp = sum(1 for a in alerts if a["verdict"] == "false_positive")
    inv = sum(1 for a in alerts if a["verdict"] == "investigating")
    fp_recurring = _count_recurring_fp(verdict_map)
    q2_answer = f"{tp} true positive, {fp} false positive, {inv} pending review."
    q2_color = "red" if tp > 0 else ("amber" if inv > 0 else "green")

    # === Q3: Compromise ===
    tp_incidents = [i for i in incidents if i.get("verdict") == "true_positive" and i["status"] in ("open", "investigating")]
    compromised_assets = []
    for inc in tp_incidents:
        # Find related IPs from incident events
        conn = get_db()
        evts = conn.execute("SELECT src_ip, dest_ip FROM incident_events WHERE incident_id=?", (inc["id"],)).fetchall()
        conn.close()
        for e in evts:
            for ip in (e["src_ip"], e["dest_ip"]):
                if ip and ip in asset_map:
                    a = asset_map[ip]
                    compromised_assets.append({
                        "ip": ip, "owner": a.get("owner", ""), "hostname": a.get("hostname", ""),
                        "business_critical": a.get("business_critical", 0),
                        "asset_type": a.get("asset_type", ""), "incident_id": inc["id"],
                    })
    q3_answer = f"{len(tp_incidents)} confirmed compromise(s)." if tp_incidents else "No confirmed compromise."
    q3_color = "red" if tp_incidents else "green"

    # === Q4: Lateral Movement + Exfiltration ===
    lateral = []
    for ip in alerted_ips:
        if is_internal(ip) and len(internal_connections.get(ip, set())) >= 3:
            lateral.append({
                "ip": ip, "owner": asset_map.get(ip, {}).get("owner", ""),
                "internal_peers": len(internal_connections[ip]),
                "identified": ip in asset_map,
            })

    exfil = []
    HIGH_OUTBOUND = 50 * 1024 * 1024  # 50MB
    for ip, b in sorted(outbound_bytes.items(), key=lambda x: -x[1])[:20]:
        reasons = []
        if b > HIGH_OUTBOUND:
            reasons.append(f"high outbound ({b / 1048576:.1f} MB)")
        if dns_long_domains.get(ip, 0) > 0:
            reasons.append(f"{dns_long_domains[ip]} long DNS domains")
        if dns_query_count.get(ip, 0) > 500:
            reasons.append(f"high DNS queries ({dns_query_count[ip]})")
        if reasons:
            exfil.append({
                "ip": ip, "owner": asset_map.get(ip, {}).get("owner", ""),
                "bytes_out": b, "reasons": reasons,
            })

    q4_answer_parts = []
    if lateral:
        q4_answer_parts.append(f"{len(lateral)} IP(s) with lateral movement indicators")
    if exfil:
        q4_answer_parts.append(f"{len(exfil)} IP(s) with exfiltration indicators")
    q4_answer = ". ".join(q4_answer_parts) + "." if q4_answer_parts else "No lateral movement or exfiltration detected."
    q4_color = "red" if lateral else ("amber" if exfil else "green")

    # === Q5: Attack Patterns + GeoIP ===
    # Repetitive attackers (external IPs with 3+ alerts)
    repetitive = []
    for ip, count in sorted(alert_src_count.items(), key=lambda x: -x[1]):
        if count >= 2 and not is_internal(ip):
            repetitive.append({"ip": ip, "alert_count": count})
    repetitive = repetitive[:20]

    # Targeted assets (internal IPs receiving alerts from 2+ sources)
    targeted = []
    dst_sources = defaultdict(set)
    for a in alerts:
        if is_internal(a["dest_ip"]):
            dst_sources[a["dest_ip"]].add(a["src_ip"])
    for ip, sources in sorted(dst_sources.items(), key=lambda x: -len(x[1])):
        if len(sources) >= 2:
            targeted.append({
                "ip": ip, "owner": asset_map.get(ip, {}).get("owner", ""),
                "source_count": len(sources), "identified": ip in asset_map,
                "business_critical": asset_map.get(ip, {}).get("business_critical", 0),
            })
    targeted = targeted[:15]

    # GeoIP enrichment for external alert IPs
    geo_data = lookup_batch(list(external_alert_ips)[:100])
    for r in repetitive:
        r["geo"] = geo_data.get(r["ip"], {"country": "Unknown", "country_code": "??"})

    # Country breakdown
    country_counts = defaultdict(lambda: {"count": 0, "ips": []})
    for ip, geo in geo_data.items():
        c = geo.get("country", "Unknown")
        country_counts[c]["count"] += alert_src_count.get(ip, 0)
        country_counts[c]["ips"].append(ip)
    country_breakdown = [
        {"country": c, "count": info["count"], "ip_count": len(info["ips"])}
        for c, info in sorted(country_counts.items(), key=lambda x: -x[1]["count"])
    ]

    q5_answer_parts = []
    if repetitive:
        q5_answer_parts.append(f"{len(repetitive)} repetitive attacker IP(s)")
    if targeted:
        q5_answer_parts.append(f"{len(targeted)} targeted asset(s)")
    if country_breakdown:
        top_countries = ", ".join(f"{c['country']} ({c['count']})" for c in country_breakdown[:3])
        q5_answer_parts.append(f"Top countries: {top_countries}")
    q5_answer = ". ".join(q5_answer_parts) + "." if q5_answer_parts else "No attack patterns detected."
    q5_color = "red" if repetitive else ("amber" if targeted else "green")

    # === Q6: Internal Suspicious + Subnet Graph ===
    nmap_list = [
        {"ip": ip, "targets": len(info["targets"]), "software": list(info["software"]),
         "owner": asset_map.get(ip, {}).get("owner", "")}
        for ip, info in nmap_sources.items()
    ]
    # Build subnet graph: group internal IPs by /24 subnet
    subnet_nodes = defaultdict(lambda: {"ips": set(), "bytes": 0, "flows": 0, "alerts": 0, "has_suspicious": False})
    subnet_links = defaultdict(lambda: {"bytes": 0, "flows": 0, "has_alerts": False})
    for ip, peers in internal_connections.items():
        s = ".".join(ip.split(".")[:3]) + ".0/24"
        subnet_nodes[s]["ips"].add(ip)
        if ip in alerted_ips:
            subnet_nodes[s]["alerts"] += 1
            subnet_nodes[s]["has_suspicious"] = True
        for peer in peers:
            ps = ".".join(peer.split(".")[:3]) + ".0/24"
            subnet_nodes[ps]["ips"].add(peer)
            if s != ps:
                lk = tuple(sorted([s, ps]))
                subnet_links[lk]["flows"] += 1

    i6_subnet_nodes = []
    for sn, info in subnet_nodes.items():
        i6_subnet_nodes.append({
            "id": sn, "host_count": len(info["ips"]),
            "alerts": info["alerts"], "has_suspicious": info["has_suspicious"],
            "sample_ips": sorted(list(info["ips"]))[:5],
        })
    i6_subnet_nodes.sort(key=lambda x: x["host_count"], reverse=True)

    i6_subnet_links = []
    for (s1, s2), info in subnet_links.items():
        i6_subnet_links.append({
            "source": s1, "target": s2,
            "flows": info["flows"], "has_alerts": info["has_alerts"],
        })

    q6_answer_parts = []
    if internal_alerts:
        q6_answer_parts.append(f"{len(internal_alerts)} internal-to-internal alert(s)")
    if nmap_list:
        q6_answer_parts.append(f"{len(nmap_list)} internal Nmap scanner(s)")
    q6_answer_parts.append(f"{len(i6_subnet_nodes)} active subnets")
    q6_answer = ". ".join(q6_answer_parts) + "." if q6_answer_parts else "No internal suspicious traffic."
    q6_color = "red" if internal_alerts else ("amber" if nmap_list else "green")

    # === Q7: SLA / Response ===
    open_actions = [a for a in action_items if a["status"] in ("open", "in_progress", "overdue")]
    completed_actions = [a for a in action_items if a["status"] == "completed"]
    breached = [a for a in action_items if a.get("sla_breached")]
    within_sla = len(completed_actions) - len([a for a in completed_actions if a.get("sla_breached")])
    q7_answer = f"{len(action_items)} action items. {within_sla} within SLA, {len(breached)} breached." if action_items else "No action items defined."
    q7_color = "red" if breached else ("amber" if open_actions else "green")

    # === Q8: Root Cause ===
    inc_with_rca = [i for i in incidents if inc_note_counts.get(i["id"], 0) > 0]
    inc_without_rca = [i for i in incidents if i["status"] in ("open", "investigating") and inc_note_counts.get(i["id"], 0) == 0]
    breach_reasons = [a for a in action_items if a.get("sla_breached") and a.get("breach_reason")]
    q8_answer = f"{len(inc_with_rca)} incident(s) with RCA. {len(inc_without_rca)} pending." if incidents else "No incidents to analyze."
    q8_color = "amber" if inc_without_rca else "green"

    # === Q9: Prevention ===
    recommendations = []
    if repetitive:
        ips = ", ".join(r["ip"] for r in repetitive[:5])
        recommendations.append({"action": f"Block repetitive attacker IPs at firewall: {ips}", "type": "firewall"})
    if exfil:
        recommendations.append({"action": "Investigate and restrict outbound data transfer for flagged hosts", "type": "dlp"})
    if nmap_list:
        recommendations.append({"action": "Investigate internal scanning activity — possible compromised host", "type": "investigation"})
    unid_count = sum(1 for ip in alerted_ips if is_internal(ip) and ip not in asset_map)
    if unid_count:
        recommendations.append({"action": f"Identify {unid_count} unidentified internal IP(s) that triggered alerts", "type": "asset_mgmt"})
    q9_answer = f"{len(recommendations)} prevention action(s) recommended." if recommendations else "No specific preventive actions needed."
    q9_color = "amber" if recommendations else "green"

    # === Q10: Gaps ===
    unidentified_alerted = [ip for ip in alerted_ips if is_internal(ip) and ip not in asset_map]
    untriaged = sum(1 for a in alerts if a["verdict"] == "investigating")
    gaps = []
    if unidentified_alerted:
        gaps.append(f"{len(unidentified_alerted)} alerted internal IP(s) not in asset inventory")
    if untriaged:
        gaps.append(f"{untriaged} alert(s) pending triage (no TP/FP verdict)")
    if not action_items:
        gaps.append("No action items defined — response tracking not active")
    q10_answer = " | ".join(gaps) if gaps else "No significant gaps identified."
    q10_color = "red" if unidentified_alerted else ("amber" if untriaged > 0 else "green")

    return {
        "generated_at": datetime.now().isoformat(),
        "period_minutes": minutes,
        "total_flows": total_flows,
        "total_bytes": total_bytes,

        "q1": {
            "question": "Any alerts in the monitoring period?",
            "answer": q1_answer, "color": q1_color,
            "total": len(alerts), "by_severity": dict(by_severity),
            "critical_high": crit_high,
            "alerts": alerts[:100],
        },
        "q2": {
            "question": "Are these alerts true positive or false positive?",
            "answer": q2_answer, "color": q2_color,
            "true_positive": tp, "false_positive": fp, "investigating": inv,
            "recurring_fp": fp_recurring,
        },
        "q3": {
            "question": "Any confirmed compromise? Which asset? Business critical?",
            "answer": q3_answer, "color": q3_color,
            "compromises": tp_incidents[:10],
            "affected_assets": compromised_assets,
        },
        "q4": {
            "question": "Lateral movement observed? Data exfiltration signs?",
            "answer": q4_answer, "color": q4_color,
            "lateral_movement": lateral,
            "exfiltration": exfil,
        },
        "q5": {
            "question": "Attack pattern analysis — repetitive IPs? Targeted assets? Country of origin?",
            "answer": q5_answer, "color": q5_color,
            "repetitive_attackers": repetitive,
            "targeted_assets": targeted,
            "country_breakdown": country_breakdown,
        },
        "q6": {
            "question": "Any internal suspicious traffic?",
            "answer": q6_answer, "color": q6_color,
            "internal_alerts": internal_alerts[:20],
            "nmap_scanners": nmap_list,
            "subnet_nodes": i6_subnet_nodes,
            "subnet_links": i6_subnet_links,
        },
        "q7": {
            "question": "Was response within SLA? Were actions sufficient?",
            "answer": q7_answer, "color": q7_color,
            "total_actions": len(action_items),
            "open": open_actions, "completed": completed_actions, "breached": breached,
        },
        "q8": {
            "question": "Root cause analysis — what caused this?",
            "answer": q8_answer, "color": q8_color,
            "with_rca": [{"id": i["id"], "title": i["title"], "status": i["status"]} for i in inc_with_rca],
            "without_rca": [{"id": i["id"], "title": i["title"], "status": i["status"]} for i in inc_without_rca],
            "breach_reasons": [{"title": a["title"], "reason": a["breach_reason"]} for a in breach_reasons],
        },
        "q9": {
            "question": "Can this be prevented next time? What needs to be done?",
            "answer": q9_answer, "color": q9_color,
            "recommendations": recommendations,
        },
        "q10": {
            "question": "What is the ONE thing we might be missing today?",
            "answer": q10_answer, "color": q10_color,
            "gaps": gaps,
            "unidentified_alerted_ips": unidentified_alerted[:20],
            "untriaged_alerts": untriaged,
        },
    }


def _count_recurring_fp(verdict_map):
    """Count signatures marked false positive more than once."""
    fp_sigs = defaultdict(int)
    for (sig_id, _, _), v in verdict_map.items():
        if v.get("verdict") == "false_positive":
            fp_sigs[sig_id] += 1
    return sum(1 for c in fp_sigs.values() if c > 1)
