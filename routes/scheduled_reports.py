"""
Scheduled reports API routes — CRUD + immediate run trigger.
"""

import json
from datetime import datetime

import bottle
from bottle import request, response
from db import get_db, close_db
from analyzers.scheduler import compute_next_run


def register(app):

    # ------------------------------------------------------------------
    # GET /api/scheduled-reports — list all scheduled reports
    # ------------------------------------------------------------------
    @app.get("/api/scheduled-reports")
    def list_reports():
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT * FROM scheduled_reports ORDER BY id DESC"
            ).fetchall()
            reports = [dict(r) for r in rows]
        finally:
            close_db(conn)
        return {"reports": reports}

    # ------------------------------------------------------------------
    # POST /api/scheduled-reports — create a scheduled report
    # ------------------------------------------------------------------
    @app.post("/api/scheduled-reports")
    def create_report():
        data = request.json or {}
        name = (data.get("name") or "").strip()
        report_type = (data.get("report_type") or "executive").strip()
        schedule = (data.get("schedule") or "daily").strip()
        time_of_day = (data.get("time_of_day") or "08:00").strip()
        recipients = (data.get("recipients") or "").strip()
        day_of_week = int(data.get("day_of_week", 1) or 1)
        day_of_month = int(data.get("day_of_month", 1) or 1)

        if not name:
            response.status = 400
            return {"error": "name is required"}
        if not recipients:
            response.status = 400
            return {"error": "recipients is required"}
        if schedule not in ("daily", "weekly", "monthly"):
            response.status = 400
            return {"error": "schedule must be daily, weekly, or monthly"}

        next_run = compute_next_run(schedule, time_of_day, day_of_week, day_of_month)

        conn = get_db()
        try:
            cur = conn.execute(
                "INSERT INTO scheduled_reports "
                "(name, report_type, schedule, time_of_day, day_of_week, day_of_month, "
                "recipients, next_run) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (name, report_type, schedule, time_of_day, day_of_week, day_of_month,
                 recipients, next_run),
            )
            conn.commit()
            report_id = cur.lastrowid
            row = conn.execute(
                "SELECT * FROM scheduled_reports WHERE id = ?", (report_id,)
            ).fetchone()
            result = dict(row)
        finally:
            close_db(conn)

        response.status = 201
        return result

    # ------------------------------------------------------------------
    # PUT /api/scheduled-reports/<id> — update a scheduled report
    # ------------------------------------------------------------------
    @app.put("/api/scheduled-reports/<report_id:int>")
    def update_report(report_id):
        data = request.json or {}
        conn = get_db()
        try:
            existing = conn.execute(
                "SELECT * FROM scheduled_reports WHERE id = ?", (report_id,)
            ).fetchone()
            if not existing:
                response.status = 404
                return {"error": "Scheduled report not found"}

            allowed = {
                "name", "report_type", "schedule", "time_of_day",
                "day_of_week", "day_of_month", "recipients", "enabled", "include_pdf",
            }
            sets = []
            params = []
            for key, val in data.items():
                if key in allowed:
                    sets.append("{} = ?".format(key))
                    params.append(val)

            # Recompute next_run if schedule-related fields changed
            schedule = data.get("schedule", existing["schedule"])
            time_of_day = data.get("time_of_day", existing["time_of_day"])
            day_of_week = int(data.get("day_of_week", existing["day_of_week"]) or 1)
            day_of_month = int(data.get("day_of_month", existing["day_of_month"]) or 1)

            if any(k in data for k in ("schedule", "time_of_day", "day_of_week", "day_of_month")):
                next_run = compute_next_run(schedule, time_of_day, day_of_week, day_of_month)
                sets.append("next_run = ?")
                params.append(next_run)

            if not sets:
                response.status = 400
                return {"error": "No valid fields to update"}

            params.append(report_id)
            conn.execute(
                "UPDATE scheduled_reports SET {} WHERE id = ?".format(", ".join(sets)),
                params,
            )
            conn.commit()

            row = conn.execute(
                "SELECT * FROM scheduled_reports WHERE id = ?", (report_id,)
            ).fetchone()
            result = dict(row)
        finally:
            close_db(conn)

        return result

    # ------------------------------------------------------------------
    # DELETE /api/scheduled-reports/<id> — delete a scheduled report
    # ------------------------------------------------------------------
    @app.delete("/api/scheduled-reports/<report_id:int>")
    def delete_report(report_id):
        conn = get_db()
        try:
            conn.execute(
                "DELETE FROM scheduled_reports WHERE id = ?", (report_id,)
            )
            conn.commit()
        finally:
            close_db(conn)
        return {"ok": True}

    # ------------------------------------------------------------------
    # POST /api/scheduled-reports/<id>/run-now — trigger immediate generation
    # ------------------------------------------------------------------
    @app.post("/api/scheduled-reports/<report_id:int>/run-now")
    def run_now(report_id):
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT * FROM scheduled_reports WHERE id = ?", (report_id,)
            ).fetchone()
            if not row:
                response.status = 404
                return {"error": "Scheduled report not found"}
            report = dict(row)
        finally:
            close_db(conn)

        # Generate and email the report
        from analyzers.scheduler import run_single_report
        success, detail = run_single_report(report)

        if success:
            return {"ok": True, "message": "Report generated and emailed", "detail": detail}
        else:
            response.status = 500
            return {"ok": False, "error": "Report generation failed", "detail": detail}
