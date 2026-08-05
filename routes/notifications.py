"""
Notification management API routes — CRUD for rules, test Discord/email, log, stats.
"""

import json
from datetime import datetime

import bottle
from bottle import request, response
from db import get_db, close_db
from analyzers.alerting import send_email, send_test_discord, get_notification_stats


def register(app):

    # ------------------------------------------------------------------
    # GET /api/notifications/rules — list all notification rules
    # ------------------------------------------------------------------
    @app.get("/api/notifications/rules")
    def list_rules():
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT * FROM notification_rules ORDER BY id DESC"
            ).fetchall()
            rules = [dict(r) for r in rows]
        finally:
            close_db(conn)
        return {"rules": rules}

    # ------------------------------------------------------------------
    # POST /api/notifications/rules — create a rule
    # ------------------------------------------------------------------
    @app.post("/api/notifications/rules")
    def create_rule():
        data = request.json or {}
        name = (data.get("name") or "").strip()
        condition_type = (data.get("condition_type") or "").strip()
        condition_value = (data.get("condition_value") or "").strip()
        recipients = (data.get("recipients") or "discord").strip()
        cooldown_minutes = int(data.get("cooldown_minutes", 30) or 30)

        if not name:
            response.status = 400
            return {"error": "name is required"}
        if not condition_type:
            response.status = 400
            return {"error": "condition_type is required"}

        conn = get_db()
        try:
            cur = conn.execute(
                "INSERT INTO notification_rules "
                "(name, condition_type, condition_value, recipients, cooldown_minutes) "
                "VALUES (?, ?, ?, ?, ?)",
                (name, condition_type, condition_value, recipients, cooldown_minutes),
            )
            conn.commit()
            rule_id = cur.lastrowid
            row = conn.execute(
                "SELECT * FROM notification_rules WHERE id = ?", (rule_id,)
            ).fetchone()
            result = dict(row)
        finally:
            close_db(conn)

        response.status = 201
        return result

    # ------------------------------------------------------------------
    # PUT /api/notifications/rules/<id> — update a rule
    # ------------------------------------------------------------------
    @app.put("/api/notifications/rules/<rule_id:int>")
    def update_rule(rule_id):
        data = request.json or {}
        conn = get_db()
        try:
            existing = conn.execute(
                "SELECT id FROM notification_rules WHERE id = ?", (rule_id,)
            ).fetchone()
            if not existing:
                response.status = 404
                return {"error": "Rule not found"}

            allowed = {
                "name", "condition_type", "condition_value",
                "recipients", "cooldown_minutes", "enabled",
            }
            sets = []
            params = []
            for key, val in data.items():
                if key in allowed:
                    sets.append("{} = ?".format(key))
                    params.append(val)
            if not sets:
                response.status = 400
                return {"error": "No valid fields to update"}

            params.append(rule_id)
            conn.execute(
                "UPDATE notification_rules SET {} WHERE id = ?".format(", ".join(sets)),
                params,
            )
            conn.commit()

            row = conn.execute(
                "SELECT * FROM notification_rules WHERE id = ?", (rule_id,)
            ).fetchone()
            result = dict(row)
        finally:
            close_db(conn)

        return result

    # ------------------------------------------------------------------
    # DELETE /api/notifications/rules/<id> — delete a rule
    # ------------------------------------------------------------------
    @app.delete("/api/notifications/rules/<rule_id:int>")
    def delete_rule(rule_id):
        conn = get_db()
        try:
            conn.execute(
                "DELETE FROM notification_rules WHERE id = ?", (rule_id,)
            )
            conn.commit()
        finally:
            close_db(conn)
        return {"ok": True}

    # ------------------------------------------------------------------
    # POST /api/notifications/test — send a test notification
    # ------------------------------------------------------------------
    @app.post("/api/notifications/test")
    def test_notification():
        data = request.json or {}
        method = (data.get("method") or "discord").strip().lower()

        if method == "discord":
            webhook_url = (data.get("webhook_url") or "").strip() or None
            ok, err = send_test_discord(webhook_url)
            if ok:
                return {"ok": True, "message": "Test message sent to Discord"}
            else:
                response.status = 502
                return {"ok": False, "error": err}

        elif method == "email":
            email = (data.get("email") or "").strip()
            if not email:
                response.status = 400
                return {"error": "email is required"}

            subject = "[NOTICE] Test Notification"
            body_html = (
                "<html><body>"
                "<h2 style='color:#2980b9;'>NOTICE Test Email</h2>"
                "<p>This is a test notification from the NOTICE platform.</p>"
                "<p>If you received this message, your SMTP configuration is working correctly.</p>"
                "<p style='color:#7f8c8d;font-size:12px;'>Sent at {}</p>"
                "</body></html>"
            ).format(datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))

            ok = send_email(email, subject, body_html)
            if ok:
                return {"ok": True, "message": "Test email sent to {}".format(email)}
            else:
                response.status = 502
                return {"ok": False, "error": "Failed — check SMTP config in .env"}

        else:
            response.status = 400
            return {"error": "Unknown method: {}".format(method)}

    # ------------------------------------------------------------------
    # GET /api/notifications/log — recent notification log (last 50)
    # ------------------------------------------------------------------
    @app.get("/api/notifications/log")
    def notification_log():
        limit = int(request.query.get("limit", "50") or "50")
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT * FROM notification_log ORDER BY sent_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            entries = [dict(r) for r in rows]
        finally:
            close_db(conn)
        return {"log": entries}

    # ------------------------------------------------------------------
    # GET /api/notifications/stats — notification stats (last 24h)
    # ------------------------------------------------------------------
    @app.get("/api/notifications/stats")
    def notification_stats():
        return get_notification_stats()
