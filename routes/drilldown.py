"""
Drill-down API — management Q1-Q10 interrogation support.
"""

from bottle import request, response
from db import get_db, close_db, cache_get, cache_set
from analyzers.drilldown import compute_drilldown
from analyzers.nist import compute_nist
from analyzers.geoip import lookup_single, lookup_batch
from eve_reader import iter_events, is_internal, is_ipv4
from collections import defaultdict


def register(app):

    @app.get("/api/drilldown")
    def api_drilldown():
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"drilldown_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        data = compute_drilldown(minutes=minutes)
        cache_set(cache_key, data, ttl=120)
        return data

    @app.get("/api/nist/activity")
    def api_nist_activity():
        """Holistic view of all network activity for identified assets."""
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"nist_activity_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached

        conn = get_db()
        asset_rows = conn.execute(
            "SELECT ip, owner, hostname, asset_type, department, scope FROM assets WHERE scope='internal'"
        ).fetchall()
        conn.close()
        asset_map = {r["ip"]: dict(r) for r in asset_rows}
        identified_ips = set(asset_map.keys())

        # Collect all events involving identified assets
        events = []
        external_ips = set()

        # TTP mapping from IDS alert categories/signatures
        ttp_map = {
            "recon": ["scan", "nmap", "probe", "enum", "discovery"],
            "exploit": ["exploit", "overflow", "injection", "rce", "cve"],
            "malware": ["trojan", "malware", "backdoor", "rat", "c2", "beacon", "turkojan"],
            "exfiltration": ["exfil", "tunnel", "dns tunnel", "data leak"],
            "credential": ["brute", "login", "credential", "password", "auth"],
            "policy": ["policy", "violation", "unauthorized"],
        }

        def classify_ttp(signature, category):
            sig_lower = (signature + " " + category).lower()
            for ttp, keywords in ttp_map.items():
                for kw in keywords:
                    if kw in sig_lower:
                        return ttp
            return "unknown"

        for ev in iter_events(minutes=minutes):
            etype = ev.get("event_type")
            src = ev.get("src_ip", "")
            dst = ev.get("dest_ip", "")
            ts = ev.get("timestamp", "")

            if not is_ipv4(src) or not is_ipv4(dst):
                continue

            # Only events involving at least one identified asset
            src_identified = src in identified_ips
            dst_identified = dst in identified_ips
            if not src_identified and not dst_identified:
                continue

            asset_ip = src if src_identified else dst
            peer_ip = dst if src_identified else src
            direction = "outbound" if src_identified else "inbound"
            asset = asset_map.get(asset_ip, {})

            if not is_internal(peer_ip):
                external_ips.add(peer_ip)

            entry = {
                "timestamp": ts,
                "event_type": etype,
                "asset_ip": asset_ip,
                "asset_owner": asset.get("owner", ""),
                "asset_hostname": asset.get("hostname", ""),
                "asset_type": asset.get("asset_type", ""),
                "custodian": asset.get("owner", "") or asset.get("department", ""),
                "peer_ip": peer_ip,
                "peer_internal": is_internal(peer_ip),
                "direction": direction,
                "proto": ev.get("proto", ""),
                "src_port": ev.get("src_port"),
                "dest_port": ev.get("dest_port"),
            }

            if etype == "alert":
                alert = ev.get("alert", {})
                entry["signature"] = alert.get("signature", "")
                entry["signature_id"] = alert.get("signature_id")
                entry["severity"] = alert.get("severity", 3)
                entry["category"] = alert.get("category", "")
                entry["action"] = alert.get("action", "")
                entry["ttp"] = classify_ttp(alert.get("signature", ""), alert.get("category", ""))

            elif etype == "flow":
                flow = ev.get("flow", {})
                entry["bytes_out"] = flow.get("bytes_toserver", 0)
                entry["bytes_in"] = flow.get("bytes_toclient", 0)
                entry["app_proto"] = ev.get("app_proto", "")

            elif etype == "http":
                http = ev.get("http", {})
                entry["hostname"] = http.get("hostname", "")
                entry["url"] = http.get("url", "")
                entry["method"] = http.get("http_method", "")
                entry["status"] = http.get("status")

            elif etype == "dns":
                dns = ev.get("dns", {})
                entry["dns_type"] = dns.get("type", "")
                queries = dns.get("queries", [])
                entry["dns_query"] = queries[0].get("rrname", "") if queries else ""

            elif etype == "tls":
                tls = ev.get("tls", {})
                entry["tls_version"] = tls.get("version", "")
                entry["tls_sni"] = tls.get("sni", "")
                entry["tls_ja4"] = tls.get("ja4", "")

            elif etype == "ssh":
                ssh = ev.get("ssh", {})
                entry["ssh_client"] = ssh.get("client", {}).get("software_version", "")
                entry["ssh_server"] = ssh.get("server", {}).get("software_version", "")

            elif etype == "anomaly":
                anom = ev.get("anomaly", {})
                entry["anomaly_event"] = anom.get("event", "")

            events.append(entry)

        # GeoIP enrich external peers
        geo = lookup_batch(list(external_ips)[:200])
        for ev in events:
            if not ev["peer_internal"] and ev["peer_ip"] in geo:
                g = geo[ev["peer_ip"]]
                ev["peer_country"] = g.get("country", "")
                ev["peer_org"] = g.get("org", g.get("isp", ""))

        # Sort by timestamp descending
        events.sort(key=lambda e: e["timestamp"], reverse=True)

        # Summary stats
        custodians = sorted(set(a.get("owner", "") for a in asset_map.values() if a.get("owner")))
        alert_events = [e for e in events if e["event_type"] == "alert"]
        ttps = defaultdict(int)
        for e in alert_events:
            ttps[e.get("ttp", "unknown")] += 1

        result = {
            "events": events[:2000],
            "total_events": len(events),
            "custodians": custodians,
            "identified_assets": [
                {"ip": ip, "owner": a.get("owner", ""), "hostname": a.get("hostname", ""),
                 "asset_type": a.get("asset_type", ""), "department": a.get("department", "")}
                for ip, a in sorted(asset_map.items())
            ],
            "summary": {
                "total": len(events),
                "alerts": len(alert_events),
                "flows": sum(1 for e in events if e["event_type"] == "flow"),
                "http": sum(1 for e in events if e["event_type"] == "http"),
                "dns": sum(1 for e in events if e["event_type"] == "dns"),
                "tls": sum(1 for e in events if e["event_type"] == "tls"),
                "anomalies": sum(1 for e in events if e["event_type"] == "anomaly"),
                "ttps": dict(ttps),
            },
        }
        cache_set(cache_key, result, ttl=90)
        return result

    @app.get("/api/nist/evidence")
    def api_evidence():
        """
        Pull raw evidence from eve.json for a given finding.
        Query params: ip (required), peer (optional), signature (optional), minutes
        Returns: all correlated raw events as proof chain.
        """
        ip = request.query.get("ip", "").strip()
        peer = request.query.get("peer", "").strip()
        sig = request.query.get("signature", "").strip()
        flow_id = request.query.get("flow_id", "").strip()
        minutes = int(request.query.get("minutes", 1440)) or 1440

        if not ip and not flow_id:
            response.status = 400
            return {"error": "ip or flow_id parameter required"}

        conn = get_db()
        asset_rows = conn.execute("SELECT ip, owner, hostname, asset_type FROM assets").fetchall()
        conn.close()
        asset_map = {r["ip"]: dict(r) for r in asset_rows}

        evidence = []
        flow_ids = set()
        seen_types = defaultdict(int)

        for ev in iter_events(minutes=minutes):
            src = ev.get("src_ip", "")
            dst = ev.get("dest_ip", "")
            etype = ev.get("event_type", "")
            fid = str(ev.get("flow_id", ""))

            # Match by flow_id
            if flow_id and fid == flow_id:
                evidence.append(_raw_evidence(ev, asset_map))
                seen_types[etype] += 1
                continue

            # Match by IP
            if ip and (src != ip and dst != ip):
                continue

            # Match by peer
            if peer:
                if not ((src == ip and dst == peer) or (src == peer and dst == ip)):
                    continue

            # Match by signature
            if sig and etype == "alert":
                alert = ev.get("alert", {})
                if sig.lower() not in alert.get("signature", "").lower():
                    continue
            elif sig and etype != "alert":
                continue

            entry = _raw_evidence(ev, asset_map)
            evidence.append(entry)
            seen_types[etype] += 1

            # Collect flow_ids from alerts to correlate
            if etype == "alert" and ev.get("flow_id"):
                flow_ids.add(str(ev["flow_id"]))

        # Second pass: find correlated events by flow_id (events in same session as alerts)
        if flow_ids and not flow_id:
            correlated = []
            for ev in iter_events(minutes=minutes):
                fid = str(ev.get("flow_id", ""))
                if fid in flow_ids:
                    src = ev.get("src_ip", "")
                    dst = ev.get("dest_ip", "")
                    etype = ev.get("event_type", "")
                    # Don't duplicate
                    key = (ev.get("timestamp", ""), etype, src, dst)
                    if not any(e["timestamp"] == ev.get("timestamp", "") and e["event_type"] == etype
                               and e["src_ip"] == src and e["dest_ip"] == dst for e in evidence):
                        entry = _raw_evidence(ev, asset_map)
                        entry["correlated"] = True
                        correlated.append(entry)
                        seen_types[etype + "_corr"] += 1
            evidence.extend(correlated)

        # Sort chronologically
        evidence.sort(key=lambda e: e["timestamp"])

        # GeoIP for external IPs
        ext_ips = set()
        for e in evidence:
            for eip in (e.get("src_ip", ""), e.get("dest_ip", "")):
                if eip and is_ipv4(eip) and not is_internal(eip):
                    ext_ips.add(eip)
        geo = lookup_batch(list(ext_ips)[:50])

        # Build proof summary
        alert_sigs = list(set(e.get("signature", "") for e in evidence if e["event_type"] == "alert" and e.get("signature")))
        proof_summary = []
        for e in evidence:
            if e["event_type"] == "alert":
                proof_summary.append(f"ALERT: {e.get('signature','')} (severity {e.get('severity','?')}) at {e['timestamp'][:19]}")
            elif e["event_type"] == "flow" and not e.get("correlated"):
                b = (e.get("bytes_toserver", 0) or 0) + (e.get("bytes_toclient", 0) or 0)
                if b > 0:
                    proof_summary.append(f"FLOW: {e.get('app_proto',e.get('proto',''))} {b} bytes at {e['timestamp'][:19]}")
            elif e["event_type"] == "http":
                proof_summary.append(f"HTTP: {e.get('method','GET')} {e.get('hostname','')}{e.get('url','/')} at {e['timestamp'][:19]}")
            elif e["event_type"] == "dns" and e.get("dns_query"):
                proof_summary.append(f"DNS: {e.get('dns_type','')} {e.get('dns_query','')} at {e['timestamp'][:19]}")

        return {
            "query": {"ip": ip, "peer": peer, "signature": sig, "flow_id": flow_id, "minutes": minutes},
            "asset": asset_map.get(ip, {}),
            "total_evidence": len(evidence),
            "event_types": dict(seen_types),
            "alert_signatures": alert_sigs,
            "proof_summary": proof_summary[:50],
            "geo": geo,
            "evidence": evidence[:500],
        }

    @app.get("/api/nist")
    def api_nist():
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"nist_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        data = compute_nist(minutes=minutes)
        cache_set(cache_key, data, ttl=90)
        return data

    @app.post("/api/alerts/verdict")
    def set_verdict():
        data = request.json or {}
        sig_id = data.get("signature_id")
        src_ip = data.get("src_ip", "")
        dst_ip = data.get("dest_ip", "")
        verdict = data.get("verdict", "investigating")
        notes = data.get("analyst_notes", "")
        if not sig_id:
            response.status = 400
            return {"error": "signature_id required"}
        conn = get_db()
        conn.execute(
            """INSERT INTO alert_verdicts (signature_id, signature, src_ip, dest_ip, verdict, analyst_notes)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(signature_id, src_ip, dest_ip)
               DO UPDATE SET verdict=?, analyst_notes=?, marked_at=datetime('now','localtime')""",
            (sig_id, data.get("signature", ""), src_ip, dst_ip, verdict, notes,
             verdict, notes),
        )
        conn.commit()
        conn.close()
        # Invalidate drill-down cache
        conn = get_db()
        conn.execute("DELETE FROM cache WHERE key LIKE 'drilldown_%'")
        conn.commit()
        conn.close()
        return {"ok": True, "verdict": verdict}

    @app.get("/api/alerts/verdicts")
    def list_verdicts():
        conn = get_db()
        rows = conn.execute("SELECT * FROM alert_verdicts ORDER BY marked_at DESC").fetchall()
        conn.close()
        return {"verdicts": [dict(r) for r in rows]}

    @app.post("/api/alerts/bulk-verdict")
    def bulk_verdict():
        data = request.json or {}
        alert_ids = data.get("alert_ids", [])
        verdict = (data.get("verdict") or "").strip()

        if not alert_ids or not isinstance(alert_ids, list):
            response.status = 400
            return {"error": "alert_ids list is required"}
        if verdict not in ("true_positive", "false_positive", "investigating", "dismiss"):
            response.status = 400
            return {"error": "Invalid verdict"}

        conn = get_db()
        try:
            updated = 0
            for aid in alert_ids:
                try:
                    aid = int(aid)
                except (ValueError, TypeError):
                    continue

                # Get alert details
                alert = conn.execute(
                    "SELECT signature_id, signature, src_ip, dest_ip FROM ingested_alerts WHERE id = ?",
                    (aid,)
                ).fetchone()
                if not alert:
                    continue

                a = dict(alert)
                if verdict == "dismiss":
                    # Just mark as notified/acknowledged
                    conn.execute("UPDATE ingested_alerts SET notified = 1 WHERE id = ?", (aid,))
                    updated += 1
                else:
                    # Upsert into alert_verdicts
                    conn.execute(
                        "INSERT OR REPLACE INTO alert_verdicts (signature_id, signature, src_ip, dest_ip, verdict, analyst_notes, marked_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, datetime('now','localtime'))",
                        (a.get("signature_id"), a.get("signature", ""), a.get("src_ip", ""), a.get("dest_ip", ""), verdict, "Bulk action"),
                    )
                    updated += 1

            conn.commit()
            return {"ok": True, "updated": updated}
        finally:
            close_db(conn)

    @app.get("/api/geo/<ip>")
    def geo_lookup(ip):
        data = lookup_single(ip)
        return data


def _raw_evidence(ev, asset_map):
    """Extract a structured evidence entry from a raw eve.json event."""
    src = ev.get("src_ip", "")
    dst = ev.get("dest_ip", "")
    etype = ev.get("event_type", "")
    entry = {
        "timestamp": ev.get("timestamp", ""),
        "event_type": etype,
        "flow_id": ev.get("flow_id"),
        "src_ip": src, "dest_ip": dst,
        "src_port": ev.get("src_port"), "dest_port": ev.get("dest_port"),
        "proto": ev.get("proto", ""),
        "src_owner": asset_map.get(src, {}).get("owner", ""),
        "dst_owner": asset_map.get(dst, {}).get("owner", ""),
        "vlan": ev.get("vlan"),
        "correlated": False,
    }
    if etype == "alert":
        alert = ev.get("alert", {})
        entry["signature"] = alert.get("signature", "")
        entry["signature_id"] = alert.get("signature_id")
        entry["severity"] = alert.get("severity", 3)
        entry["category"] = alert.get("category", "")
        entry["action"] = alert.get("action", "")
        flow = ev.get("flow", {})
        entry["bytes_toserver"] = flow.get("bytes_toserver", 0)
        entry["bytes_toclient"] = flow.get("bytes_toclient", 0)
        entry["pkts_toserver"] = flow.get("pkts_toserver", 0)
        entry["pkts_toclient"] = flow.get("pkts_toclient", 0)
    elif etype == "flow":
        flow = ev.get("flow", {})
        entry["app_proto"] = ev.get("app_proto", "")
        entry["bytes_toserver"] = flow.get("bytes_toserver", 0)
        entry["bytes_toclient"] = flow.get("bytes_toclient", 0)
        entry["pkts_toserver"] = flow.get("pkts_toserver", 0)
        entry["pkts_toclient"] = flow.get("pkts_toclient", 0)
        entry["flow_age"] = flow.get("age")
        entry["flow_state"] = flow.get("state", "")
        tcp = ev.get("tcp", {})
        if tcp:
            entry["tcp_flags"] = tcp.get("tcp_flags", "")
            entry["tcp_state"] = tcp.get("state", "")
    elif etype == "http":
        http = ev.get("http", {})
        entry["hostname"] = http.get("hostname", "")
        entry["url"] = http.get("url", "")
        entry["method"] = http.get("http_method", "")
        entry["status"] = http.get("status")
        entry["user_agent"] = http.get("http_user_agent", "")
        entry["content_type"] = http.get("http_content_type", "")
        entry["length"] = http.get("length")
    elif etype == "dns":
        dns = ev.get("dns", {})
        entry["dns_type"] = dns.get("type", "")
        queries = dns.get("queries", [])
        entry["dns_query"] = queries[0].get("rrname", "") if queries else ""
        entry["dns_rrtype"] = queries[0].get("rrtype", "") if queries else ""
        entry["dns_rcode"] = dns.get("rcode", "")
        answers = dns.get("answers", [])
        entry["dns_answers"] = [a.get("rdata", "") for a in answers[:5]]
    elif etype == "tls":
        tls = ev.get("tls", {})
        entry["tls_version"] = tls.get("version", "")
        entry["tls_sni"] = tls.get("sni", "")
        entry["tls_ja4"] = tls.get("ja4", "")
        entry["tls_subject"] = tls.get("subject", "")
        entry["tls_issuer"] = tls.get("issuerdn", "")
    elif etype == "ssh":
        ssh = ev.get("ssh", {})
        entry["ssh_client"] = ssh.get("client", {}).get("software_version", "")
        entry["ssh_server"] = ssh.get("server", {}).get("software_version", "")
        entry["ssh_client_proto"] = ssh.get("client", {}).get("proto_version", "")
    elif etype == "anomaly":
        anom = ev.get("anomaly", {})
        entry["anomaly_type"] = anom.get("type", "")
        entry["anomaly_event"] = anom.get("event", "")
        entry["anomaly_layer"] = anom.get("layer", "")
    elif etype == "fileinfo":
        fi = ev.get("fileinfo", {})
        entry["filename"] = fi.get("filename", "")
        entry["filesize"] = fi.get("size", 0)
        entry["sha256"] = fi.get("sha256", "")
    return entry
