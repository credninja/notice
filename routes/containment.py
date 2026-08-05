"""
Incident-response containment actions: blocklist, quarantine, watchlist.

These tables are the source of truth — UI and the rule generator both read
from them. The rule generator includes blocklisted IPs in `notice-user.rules`
on the next regenerate; quarantined assets are visually flagged in the UI;
watchlist hits are counted against future alerts.

API:
    GET    /api/containment/blocklist             list active blocked IPs
    POST   /api/containment/blocklist             add an IP   {ip, reason?, incident_id?, expires_at?}
    DELETE /api/containment/blocklist/<id:int>    remove

    GET    /api/containment/quarantine            list quarantined assets
    POST   /api/containment/quarantine            add         {asset_ip, reason?, incident_id?}
    DELETE /api/containment/quarantine/<id:int>   release

    GET    /api/containment/watchlist             list active watch IOCs
    POST   /api/containment/watchlist             add         {ioc_value, ioc_type?, note?, incident_id?, expires_at?}
    DELETE /api/containment/watchlist/<id:int>    remove

    GET    /api/containment/summary               counts of all three categories
"""

from bottle import request, response

from db import get_db


def register(app):

    # ─── BLOCKLIST ───────────────────────────────────────────────────────

    @app.get("/api/containment/blocklist")
    def list_blocklist():
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM blocklist WHERE active=1 ORDER BY created_at DESC"
        ).fetchall()
        conn.close()
        return {"blocklist": [dict(r) for r in rows]}

    @app.post("/api/containment/blocklist")
    def add_blocklist():
        data = request.json or {}
        ip = (data.get("ip") or "").strip()
        if not ip:
            response.status = 400
            return {"error": "ip is required"}
        conn = get_db()
        # Same IP already active? Refresh it instead of duplicating.
        existing = conn.execute(
            "SELECT id FROM blocklist WHERE ip=? AND active=1", (ip,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE blocklist SET reason=?, incident_id=?, expires_at=?, created_at=datetime('now','localtime') WHERE id=?",
                (data.get("reason", ""), data.get("incident_id"), data.get("expires_at"), existing["id"]),
            )
            row_id = existing["id"]
        else:
            cur = conn.execute(
                "INSERT INTO blocklist (ip, reason, incident_id, created_by, expires_at) "
                "VALUES (?,?,?,?,?)",
                (ip, data.get("reason", ""), data.get("incident_id"),
                 data.get("created_by", "analyst"), data.get("expires_at")),
            )
            row_id = cur.lastrowid
        conn.commit()
        row = dict(conn.execute("SELECT * FROM blocklist WHERE id=?", (row_id,)).fetchone())
        conn.close()
        response.status = 201
        return row

    @app.delete("/api/containment/blocklist/<row_id:int>")
    def remove_blocklist(row_id):
        conn = get_db()
        # Soft-delete: keep history, mark inactive
        conn.execute("UPDATE blocklist SET active=0 WHERE id=?", (row_id,))
        conn.commit()
        conn.close()
        return {"ok": True, "removed": row_id}

    # ─── QUARANTINE ──────────────────────────────────────────────────────

    @app.get("/api/containment/quarantine")
    def list_quarantine():
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM quarantine WHERE active=1 ORDER BY created_at DESC"
        ).fetchall()
        conn.close()
        return {"quarantine": [dict(r) for r in rows]}

    @app.post("/api/containment/quarantine")
    def add_quarantine():
        data = request.json or {}
        asset_ip = (data.get("asset_ip") or "").strip()
        if not asset_ip:
            response.status = 400
            return {"error": "asset_ip is required"}
        conn = get_db()
        existing = conn.execute(
            "SELECT id FROM quarantine WHERE asset_ip=? AND active=1", (asset_ip,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE quarantine SET reason=?, incident_id=?, created_at=datetime('now','localtime') WHERE id=?",
                (data.get("reason", ""), data.get("incident_id"), existing["id"]),
            )
            row_id = existing["id"]
        else:
            cur = conn.execute(
                "INSERT INTO quarantine (asset_ip, reason, incident_id, created_by) VALUES (?,?,?,?)",
                (asset_ip, data.get("reason", ""), data.get("incident_id"),
                 data.get("created_by", "analyst")),
            )
            row_id = cur.lastrowid
        conn.commit()
        row = dict(conn.execute("SELECT * FROM quarantine WHERE id=?", (row_id,)).fetchone())
        conn.close()
        response.status = 201
        return row

    @app.delete("/api/containment/quarantine/<row_id:int>")
    def release_quarantine(row_id):
        conn = get_db()
        conn.execute(
            "UPDATE quarantine SET active=0, released_at=datetime('now','localtime') WHERE id=?",
            (row_id,),
        )
        conn.commit()
        conn.close()
        return {"ok": True, "released": row_id}

    # ─── WATCHLIST ───────────────────────────────────────────────────────

    @app.get("/api/containment/watchlist")
    def list_watchlist():
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM watchlist WHERE active=1 ORDER BY created_at DESC"
        ).fetchall()
        conn.close()
        return {"watchlist": [dict(r) for r in rows]}

    @app.post("/api/containment/watchlist")
    def add_watchlist():
        data = request.json or {}
        value = (data.get("ioc_value") or "").strip()
        if not value:
            response.status = 400
            return {"error": "ioc_value is required"}
        ioc_type = (data.get("ioc_type") or "ip").strip().lower()
        if ioc_type not in {"ip", "signature_id", "signature", "domain", "asset_ip"}:
            ioc_type = "ip"
        conn = get_db()
        existing = conn.execute(
            "SELECT id FROM watchlist WHERE ioc_value=? AND ioc_type=? AND active=1",
            (value, ioc_type),
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE watchlist SET note=?, incident_id=?, expires_at=?, created_at=datetime('now','localtime') WHERE id=?",
                (data.get("note", ""), data.get("incident_id"), data.get("expires_at"), existing["id"]),
            )
            row_id = existing["id"]
        else:
            cur = conn.execute(
                """INSERT INTO watchlist (ioc_value, ioc_type, note, incident_id, created_by, expires_at)
                   VALUES (?,?,?,?,?,?)""",
                (value, ioc_type, data.get("note", ""), data.get("incident_id"),
                 data.get("created_by", "analyst"), data.get("expires_at")),
            )
            row_id = cur.lastrowid
        conn.commit()
        row = dict(conn.execute("SELECT * FROM watchlist WHERE id=?", (row_id,)).fetchone())
        conn.close()
        response.status = 201
        return row

    @app.delete("/api/containment/watchlist/<row_id:int>")
    def remove_watchlist(row_id):
        conn = get_db()
        conn.execute("UPDATE watchlist SET active=0 WHERE id=?", (row_id,))
        conn.commit()
        conn.close()
        return {"ok": True, "removed": row_id}

    # ─── SUMMARY ─────────────────────────────────────────────────────────

    @app.get("/api/containment/summary")
    def containment_summary():
        conn = get_db()
        b = conn.execute("SELECT COUNT(*) FROM blocklist WHERE active=1").fetchone()[0]
        q = conn.execute("SELECT COUNT(*) FROM quarantine WHERE active=1").fetchone()[0]
        w = conn.execute("SELECT COUNT(*) FROM watchlist WHERE active=1").fetchone()[0]
        conn.close()
        return {"blocklist": b, "quarantine": q, "watchlist": w}
