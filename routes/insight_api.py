"""
Incident insight + knowledge graph + asset timeline endpoints.

  GET  /api/incidents/<id>/impact         — compromised vs suspected, scope, entry point
  GET  /api/incidents/<id>/origin         — first alert + patient zero + escalation seq
  GET  /api/incidents/<id>/graph          — D3 nodes/links payload
  GET  /api/assets/<ip>/timeline?minutes  — pre-detection 24h activity stream

  GET  /api/asset-states                  — current asset_compromise_state list
  POST /api/asset-states                  — upsert (asset_ip, status, incident_id?, last_indicator?)
  POST /api/reinfection-check             — manual run
"""

from bottle import request, response

from analyzers.insight import (
    compute_impact, compute_origin, asset_timeline,
    update_asset_state, get_asset_states, reinfection_check,
)
from analyzers.knowledge_graph import build_incident_graph


def register(app):

    @app.get("/api/incidents/<incident_id:int>/impact")
    def api_impact(incident_id):
        result = compute_impact(incident_id)
        if not result:
            response.status = 404
            return {"error": "Incident not found"}
        return result

    @app.get("/api/incidents/<incident_id:int>/origin")
    def api_origin(incident_id):
        result = compute_origin(incident_id)
        if not result:
            response.status = 404
            return {"error": "Incident not found or has no events"}
        return result

    @app.get("/api/incidents/<incident_id:int>/graph")
    def api_graph(incident_id):
        result = build_incident_graph(incident_id)
        if not result:
            response.status = 404
            return {"error": "Incident not found"}
        return result

    @app.get("/api/assets/<ip>/timeline")
    def api_timeline(ip):
        minutes = int(request.query.get("minutes", 1440) or 1440)
        return asset_timeline(ip, minutes=minutes)

    @app.get("/api/asset-states")
    def api_asset_states():
        return {"states": get_asset_states()}

    @app.post("/api/asset-states")
    def api_asset_state_upsert():
        d = request.json or {}
        ip = (d.get("asset_ip") or "").strip()
        status = (d.get("status") or "").strip().lower()
        if not ip or status not in ("active", "contained", "resolved", "reinfected", "suspected"):
            response.status = 400
            return {"error": "asset_ip + valid status required (active/contained/resolved/reinfected/suspected)"}
        update_asset_state(ip, status,
                           incident_id=d.get("incident_id"),
                           last_indicator=d.get("last_indicator", ""))
        return {"ok": True}

    @app.post("/api/reinfection-check")
    def api_reinfection_run():
        fired = reinfection_check()
        return {"reinfected": fired, "count": len(fired)}
