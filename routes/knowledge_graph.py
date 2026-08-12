"""
Knowledge Graph — derives a node/edge JSON view of security activity
in a bounded time window from existing tables. No new ingestion,
no embeddings, no external calls.

Endpoint:
  GET /api/graph/knowledge
    ?minutes=<N>                  (default 1440)
    &from=<ISO>&to=<ISO>          (overrides minutes if both present)
    &scope=incident:<id>          (limit to a single incident and everything
                                   directly related to it — optional)
    &max_nodes=<N>                (safety cap, default 300)

Returns: {
  "window": {"from": "...", "to": "...", "label": "..."},
  "nodes": [{"id":"asset:10.1.96.53","type":"asset","label":"darlene","meta":{...}}, ...],
  "edges": [{"from":"asset:10.2.139.119","to":"asset:10.1.96.53","kind":"alerted","weight":42,"meta":{"top_sigs":[...]}}, ...],
  "stats": {"node_count":N,"edge_count":M,"by_type":{...}}
}

Node id conventions:
  asset:<ip>          — internal or external IP node
  incident:<id>       — incident node
  signature:<sid>     — Suricata signature id
  ioc:<type>:<value>  — indicator of compromise (domain/hash/etc.)
  technique:<T####>   — MITRE ATT&CK technique
"""

from datetime import datetime as _dt, timedelta as _td
from bottle import request, response
from db import get_db


def _parse_window():
    """Returns (from_str, to_str, label) matching the situation-report parser."""
    minutes_q = request.query.get("minutes", "").strip()
    from_q = request.query.get("from", "").strip()
    to_q = request.query.get("to", "").strip()
    now = _dt.now()
    if from_q and to_q:
        try:
            t_from = _dt.fromisoformat(from_q.replace("Z", ""))
            t_to = _dt.fromisoformat(to_q.replace("Z", ""))
        except ValueError:
            return None, None, None
        label = f"{t_from.strftime('%Y-%m-%d %H:%M')} to {t_to.strftime('%Y-%m-%d %H:%M')}"
    else:
        try:
            mins = int(minutes_q) if minutes_q else 1440
        except ValueError:
            mins = 1440
        mins = max(1, min(mins, 60 * 24 * 90))
        t_to = now
        t_from = now - _td(minutes=mins)
        if mins < 60:
            label = f"last {mins} minutes"
        elif mins < 60 * 24:
            label = f"last {mins // 60} hours"
        else:
            label = f"last {mins // (60 * 24)} days"
    return t_from.strftime("%Y-%m-%d %H:%M:%S"), t_to.strftime("%Y-%m-%d %H:%M:%S"), label


def register(app):
    @app.get("/api/graph/knowledge")
    def knowledge_graph():
        from_str, to_str, label = _parse_window()
        if from_str is None:
            response.status = 400
            return {"error": "from/to must be ISO 8601"}
        try:
            max_nodes = int(request.query.get("max_nodes", "300"))
        except ValueError:
            max_nodes = 300
        max_nodes = max(20, min(max_nodes, 1000))
        scope = request.query.get("scope", "").strip()

        # ── Node registry (id -> node dict); dedup by id ──
        nodes = {}
        edges = []

        def _add_node(nid, ntype, label_text, meta=None):
            if nid not in nodes:
                nodes[nid] = {
                    "id": nid, "type": ntype,
                    "label": label_text, "meta": meta or {}
                }
            return nodes[nid]

        conn = get_db()

        # If scope=incident:<id>, narrow everything to that incident and its
        # directly-related IPs / alerts / IOCs / techniques.
        incident_filter = None
        if scope.startswith("incident:"):
            try:
                incident_filter = int(scope.split(":", 1)[1])
            except ValueError:
                pass

        # ── 1. Incidents in the window ──
        if incident_filter is not None:
            incidents_rows = conn.execute(
                "SELECT id, title, severity, status, verdict, attacker_ip, "
                "victim_ip, signature_id, signature, closure_mitre_technique, created_at "
                "FROM incidents WHERE id=?",
                (incident_filter,)
            ).fetchall()
        else:
            incidents_rows = conn.execute(
                "SELECT id, title, severity, status, verdict, attacker_ip, "
                "victim_ip, signature_id, signature, closure_mitre_technique, created_at "
                "FROM incidents WHERE created_at >= ? AND created_at < ? "
                "ORDER BY created_at DESC LIMIT ?",
                (from_str, to_str, max_nodes)
            ).fetchall()

        scoped_incident_ids = [r["id"] for r in incidents_rows]

        for inc in incidents_rows:
            inc_id = f"incident:{inc['id']}"
            _add_node(inc_id, "incident",
                      f"INC-{inc['id']:04d} {(inc['title'] or '')[:40]}",
                      {"severity": inc["severity"], "status": inc["status"],
                       "verdict": inc["verdict"], "signature_id": inc["signature_id"],
                       "created_at": inc["created_at"],
                       "incident_id": inc["id"]})
            # Src/dst IP nodes and edges
            for role, ip in (("attacker", inc["attacker_ip"]), ("victim", inc["victim_ip"])):
                if not ip:
                    continue
                asset_id = f"asset:{ip}"
                # Try to enrich from assets table
                a = conn.execute(
                    "SELECT owner, asset_type, business_critical FROM assets WHERE ip=?",
                    (ip,)
                ).fetchone()
                if a:
                    _add_node(asset_id, "asset", f"{a['owner'] or ip}",
                              {"asset_type": a["asset_type"],
                               "business_critical": bool(a["business_critical"]),
                               "ip": ip, "registered": True})
                else:
                    _add_node(asset_id, "asset", ip,
                              {"ip": ip, "registered": False})
                edges.append({
                    "from": asset_id, "to": inc_id, "kind": role,
                    "weight": 1, "meta": {}
                })
            # Signature node
            if inc["signature_id"]:
                sig_id = f"signature:{inc['signature_id']}"
                _add_node(sig_id, "signature",
                          (inc["signature"] or f"sid {inc['signature_id']}")[:60],
                          {"sid": inc["signature_id"]})
                edges.append({
                    "from": inc_id, "to": sig_id, "kind": "matched",
                    "weight": 1, "meta": {}
                })
            # MITRE technique node
            if inc["closure_mitre_technique"]:
                for tech in str(inc["closure_mitre_technique"]).split(","):
                    tech = tech.strip()
                    if not tech:
                        continue
                    tid = f"technique:{tech}"
                    _add_node(tid, "technique", tech, {"technique_id": tech})
                    edges.append({
                        "from": inc_id, "to": tid, "kind": "uses_technique",
                        "weight": 1, "meta": {}
                    })

        # ── 2. IOCs attached to those incidents ──
        if scoped_incident_ids:
            placeholders = ",".join("?" * len(scoped_incident_ids))
            ioc_rows = conn.execute(
                f"SELECT incident_id, ioc_type, ioc_value, is_primary, frequency "
                f"FROM incident_iocs WHERE incident_id IN ({placeholders}) "
                f"ORDER BY is_primary DESC, frequency DESC LIMIT 200",
                scoped_incident_ids
            ).fetchall()
            for ioc in ioc_rows:
                if not ioc["ioc_value"]:
                    continue
                ioc_id = f"ioc:{ioc['ioc_type']}:{ioc['ioc_value']}"
                _add_node(ioc_id, "ioc",
                          f"{ioc['ioc_type']}: {ioc['ioc_value'][:40]}",
                          {"ioc_type": ioc["ioc_type"],
                           "value": ioc["ioc_value"],
                           "primary": bool(ioc["is_primary"])})
                edges.append({
                    "from": f"incident:{ioc['incident_id']}",
                    "to": ioc_id, "kind": "has_ioc",
                    "weight": ioc["frequency"] or 1, "meta": {}
                })

        # ── 3. Alert-derived communication edges (asset -> asset) ──
        # We only add edges for src/dst pairs that appear alongside the
        # scoped incidents. If no incidents in window, we fall back to
        # a top-communication view over all alerts in the window.
        if incident_filter is None and len(nodes) < max_nodes:
            # Top N most-active src->dst pairs in the window
            remaining = max_nodes - len(nodes)
            pairs = conn.execute(
                "SELECT src_ip, dest_ip, COUNT(*) as c, "
                "COUNT(DISTINCT signature_id) as sig_count "
                "FROM ingested_alerts "
                "WHERE timestamp >= ? AND timestamp < ? "
                "AND src_ip IS NOT NULL AND dest_ip IS NOT NULL "
                "GROUP BY src_ip, dest_ip ORDER BY c DESC LIMIT ?",
                (from_str, to_str, min(50, remaining))
            ).fetchall()
            for p in pairs:
                for ip in (p["src_ip"], p["dest_ip"]):
                    asset_id = f"asset:{ip}"
                    if asset_id in nodes:
                        continue
                    a = conn.execute(
                        "SELECT owner FROM assets WHERE ip=?", (ip,)
                    ).fetchone()
                    label_text = (a["owner"] if a and a["owner"] else ip)
                    _add_node(asset_id, "asset", label_text,
                              {"ip": ip, "registered": bool(a)})
                edges.append({
                    "from": f"asset:{p['src_ip']}",
                    "to": f"asset:{p['dest_ip']}",
                    "kind": "alerted",
                    "weight": p["c"],
                    "meta": {"unique_signatures": p["sig_count"]}
                })

        conn.close()

        # Enforce max_nodes cap by trimming edges pointing to trimmed nodes
        node_list = list(nodes.values())
        if len(node_list) > max_nodes:
            keep = {n["id"] for n in node_list[:max_nodes]}
            node_list = node_list[:max_nodes]
            edges = [e for e in edges if e["from"] in keep and e["to"] in keep]

        # Compute stats
        by_type = {}
        for n in node_list:
            by_type[n["type"]] = by_type.get(n["type"], 0) + 1

        return {
            "window": {"from": from_str, "to": to_str, "label": label,
                       "scope": scope or None},
            "nodes": node_list,
            "edges": edges,
            "stats": {
                "node_count": len(node_list),
                "edge_count": len(edges),
                "by_type": by_type,
            },
        }
