"""
Auto-promote engine REST API.

  GET    /api/auto-promote/rules                — list rules
  POST   /api/auto-promote/rules                — create rule
  PUT    /api/auto-promote/rules/<id:int>       — update rule
  DELETE /api/auto-promote/rules/<id:int>       — delete rule
  POST   /api/auto-promote/run                  — run engine now (returns summary)
  POST   /api/auto-promote/dry-run              — same but no DB writes
  GET    /api/auto-promote/decisions            — recent decision audit
"""

from bottle import request, response

from db import get_db
from analyzers.auto_promote import evaluate_and_promote, recent_decisions


_VALID_CRITERIA = {"ti_malicious", "alert_burst", "killchain_phase", "critical_asset"}


def register(app):

    @app.get("/api/auto-promote/rules")
    def list_rules():
        conn = get_db()
        rows = conn.execute("SELECT * FROM auto_promote_rules ORDER BY id").fetchall()
        conn.close()
        return {"rules": [dict(r) for r in rows]}

    @app.post("/api/auto-promote/rules")
    def create_rule():
        d = request.json or {}
        name = (d.get("name") or "").strip()
        criterion = (d.get("criterion") or "").strip()
        if not name or criterion not in _VALID_CRITERIA:
            response.status = 400
            return {"error": f"name + valid criterion required (got '{criterion}')"}
        conn = get_db()
        try:
            cur = conn.execute(
                "INSERT INTO auto_promote_rules (name, criterion, threshold, window_minutes, "
                "severity_floor, enabled) VALUES (?,?,?,?,?,?)",
                (name, criterion,
                 float(d.get("threshold", 0) or 0),
                 int(d.get("window_minutes", 10) or 10),
                 (d.get("severity_floor") or "medium"),
                 1 if d.get("enabled", True) else 0),
            )
        except Exception as e:
            conn.close(); response.status = 400
            return {"error": str(e)}
        rid = cur.lastrowid
        conn.commit()
        row = conn.execute("SELECT * FROM auto_promote_rules WHERE id=?", (rid,)).fetchone()
        conn.close()
        response.status = 201
        return dict(row)

    @app.put("/api/auto-promote/rules/<rid:int>")
    def update_rule(rid):
        d = request.json or {}
        conn = get_db()
        row = conn.execute("SELECT id FROM auto_promote_rules WHERE id=?", (rid,)).fetchone()
        if not row:
            conn.close(); response.status = 404
            return {"error": "not found"}
        # Build SET clause from supplied fields
        sets, vals = [], []
        for f in ("name", "criterion", "severity_floor"):
            if f in d:
                sets.append(f"{f}=?"); vals.append(d[f])
        if "threshold" in d:
            sets.append("threshold=?"); vals.append(float(d["threshold"] or 0))
        if "window_minutes" in d:
            sets.append("window_minutes=?"); vals.append(int(d["window_minutes"] or 10))
        if "enabled" in d:
            sets.append("enabled=?"); vals.append(1 if d["enabled"] else 0)
        if sets:
            vals.append(rid)
            conn.execute(f"UPDATE auto_promote_rules SET {', '.join(sets)} WHERE id=?", vals)
            conn.commit()
        out = dict(conn.execute("SELECT * FROM auto_promote_rules WHERE id=?", (rid,)).fetchone())
        conn.close()
        return out

    @app.delete("/api/auto-promote/rules/<rid:int>")
    def delete_rule(rid):
        conn = get_db()
        conn.execute("DELETE FROM auto_promote_rules WHERE id=?", (rid,))
        conn.commit()
        conn.close()
        return {"ok": True, "deleted": rid}

    @app.post("/api/auto-promote/run")
    def run_now():
        d = request.json or {}
        win = int(d.get("window_minutes", 10) or 10)
        return evaluate_and_promote(window_minutes=win, dry_run=False)

    @app.post("/api/auto-promote/dry-run")
    def dry_run():
        d = request.json or {}
        win = int(d.get("window_minutes", 10) or 10)
        return evaluate_and_promote(window_minutes=win, dry_run=True)

    @app.get("/api/auto-promote/decisions")
    def decisions():
        win = int(request.query.get("minutes", 60) or 60)
        limit = int(request.query.get("limit", 50) or 50)
        return {"decisions": recent_decisions(minutes=win, limit=limit)}
