"""
Enhanced case/incident management — evidence handling, timeline, assignment,
phase changes, export, and SLA status.

Extends the core incidents module with forensic evidence upload/download,
a unified timeline view, and operational SLA tracking.
"""

import hashlib
import json
import os
from datetime import datetime, timedelta

import bottle
from bottle import request, response

from db import get_db, close_db

# Evidence files live here, organised by incident ID
EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evidence")

# 50 MB upload cap
MAX_EVIDENCE_SIZE = 50 * 1024 * 1024

# SLA thresholds by severity (hours)
SLA_THRESHOLDS = {
    "critical": 4,
    "high": 8,
    "medium": 24,
    "low": 72,
}

PHASES = ["triage", "investigate", "contain", "eradicate", "recover", "closed"]


def _ensure_evidence_dir(incident_id):
    """Create the per-incident evidence directory if it does not exist."""
    path = os.path.join(EVIDENCE_DIR, str(incident_id))
    os.makedirs(path, exist_ok=True)
    return path


def _sha256(filepath):
    """Compute SHA-256 hash of a file on disk."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def register(app):

    # ─── EVIDENCE UPLOAD ────────────────────────────────────────────────

    @app.post("/api/incidents/<incident_id:int>/evidence")
    def upload_evidence(incident_id):
        conn = get_db()
        try:
            inc = conn.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if not inc:
                response.status = 404
                return {"error": "Incident not found"}

            upload = request.files.get("file")
            if not upload:
                response.status = 400
                return {"error": "No file uploaded. Use multipart form field 'file'."}

            description = request.forms.get("description", "")
            uploaded_by = request.forms.get("uploaded_by", "analyst")

            # Read file data into memory to check size before writing
            file_data = upload.file.read()
            if len(file_data) > MAX_EVIDENCE_SIZE:
                response.status = 413
                return {"error": f"File exceeds maximum size of {MAX_EVIDENCE_SIZE // (1024*1024)}MB"}

            filename = os.path.basename(upload.filename)
            if not filename:
                response.status = 400
                return {"error": "Invalid filename"}
            content_type = upload.content_type or "application/octet-stream"

            # Save to disk
            dest_dir = _ensure_evidence_dir(incident_id)
            # Avoid overwriting: append a counter if the filename already exists
            save_name = filename
            save_path = os.path.join(dest_dir, save_name)
            counter = 1
            while os.path.exists(save_path):
                name, ext = os.path.splitext(filename)
                save_name = f"{name}_{counter}{ext}"
                save_path = os.path.join(dest_dir, save_name)
                counter += 1

            with open(save_path, "wb") as f:
                f.write(file_data)

            file_hash = _sha256(save_path)
            file_size = len(file_data)

            cur = conn.execute(
                """INSERT INTO evidence
                   (incident_id, filename, filepath, file_size, content_type,
                    description, hash_sha256, uploaded_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (incident_id, save_name, save_path, file_size, content_type,
                 description, file_hash, uploaded_by),
            )
            evidence_id = cur.lastrowid
            conn.execute(
                "UPDATE incidents SET updated_at = datetime('now','localtime') WHERE id = ?",
                (incident_id,),
            )
            conn.commit()

            row = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
            response.status = 201
            return dict(row)
        finally:
            close_db(conn)

    # ─── LIST EVIDENCE ──────────────────────────────────────────────────

    @app.get("/api/incidents/<incident_id:int>/evidence")
    def list_evidence(incident_id):
        conn = get_db()
        try:
            inc = conn.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if not inc:
                response.status = 404
                return {"error": "Incident not found"}

            rows = conn.execute(
                "SELECT * FROM evidence WHERE incident_id = ? ORDER BY uploaded_at DESC",
                (incident_id,),
            ).fetchall()
            return {"evidence": [dict(r) for r in rows]}
        finally:
            close_db(conn)

    # ─── DOWNLOAD EVIDENCE ──────────────────────────────────────────────

    @app.get("/api/incidents/<incident_id:int>/evidence/<eid:int>/download")
    def download_evidence(incident_id, eid):
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT * FROM evidence WHERE id = ? AND incident_id = ?",
                (eid, incident_id),
            ).fetchone()
            if not row:
                response.status = 404
                return {"error": "Evidence not found"}

            filepath = row["filepath"]
            if not os.path.isfile(filepath):
                response.status = 404
                return {"error": "Evidence file missing from disk"}

            directory = os.path.dirname(filepath)
            filename = os.path.basename(filepath)
            return bottle.static_file(filename, root=directory, download=row["filename"])
        finally:
            close_db(conn)

    # ─── DELETE EVIDENCE ────────────────────────────────────────────────

    @app.delete("/api/incidents/<incident_id:int>/evidence/<eid:int>")
    def delete_evidence(incident_id, eid):
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT * FROM evidence WHERE id = ? AND incident_id = ?",
                (eid, incident_id),
            ).fetchone()
            if not row:
                response.status = 404
                return {"error": "Evidence not found"}

            # Remove file from disk (best-effort)
            filepath = row["filepath"]
            if os.path.isfile(filepath):
                try:
                    os.remove(filepath)
                except OSError:
                    pass

            conn.execute("DELETE FROM evidence WHERE id = ?", (eid,))
            conn.execute(
                "UPDATE incidents SET updated_at = datetime('now','localtime') WHERE id = ?",
                (incident_id,),
            )
            conn.commit()
            return {"ok": True}
        finally:
            close_db(conn)

    # ─── TIMELINE ───────────────────────────────────────────────────────

    @app.get("/api/incidents/<incident_id:int>/timeline")
    def incident_timeline(incident_id):
        """Unified timeline: notes + events + phase changes + evidence, sorted by time."""
        conn = get_db()
        try:
            inc = conn.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if not inc:
                response.status = 404
                return {"error": "Incident not found"}

            timeline = []

            # Events
            events = conn.execute(
                "SELECT * FROM incident_events WHERE incident_id = ? ORDER BY timestamp",
                (incident_id,),
            ).fetchall()
            for ev in events:
                e = dict(ev)
                ts = e.get("timestamp") or e.get("added_at") or ""
                timeline.append({
                    "type": "event",
                    "timestamp": ts,
                    "id": e["id"],
                    "summary": e.get("event_summary", ""),
                    "event_type": e.get("event_type", ""),
                    "src_ip": e.get("src_ip", ""),
                    "dest_ip": e.get("dest_ip", ""),
                    "data": e,
                })

            # Notes
            notes = conn.execute(
                "SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at",
                (incident_id,),
            ).fetchall()
            for n in notes:
                nd = dict(n)
                timeline.append({
                    "type": "note",
                    "timestamp": nd.get("created_at", ""),
                    "id": nd["id"],
                    "summary": nd.get("content", ""),
                    "data": nd,
                })

            # Phase changes
            phases = conn.execute(
                "SELECT * FROM incident_phase_log WHERE incident_id = ? ORDER BY started_at",
                (incident_id,),
            ).fetchall()
            for p in phases:
                pd = dict(p)
                timeline.append({
                    "type": "phase_change",
                    "timestamp": pd.get("started_at", ""),
                    "id": pd["id"],
                    "summary": f"Phase changed to '{pd.get('phase', '')}'",
                    "phase": pd.get("phase", ""),
                    "completed_by": pd.get("completed_by", ""),
                    "notes": pd.get("notes", ""),
                    "data": pd,
                })

            # Evidence uploads
            evidence = conn.execute(
                "SELECT * FROM evidence WHERE incident_id = ? ORDER BY uploaded_at",
                (incident_id,),
            ).fetchall()
            for ev in evidence:
                ed = dict(ev)
                timeline.append({
                    "type": "evidence",
                    "timestamp": ed.get("uploaded_at", ""),
                    "id": ed["id"],
                    "summary": f"Evidence uploaded: {ed.get('filename', '')}",
                    "filename": ed.get("filename", ""),
                    "uploaded_by": ed.get("uploaded_by", ""),
                    "data": ed,
                })

            # Sort by timestamp
            timeline.sort(key=lambda x: x.get("timestamp") or "")

            return {"timeline": timeline, "total": len(timeline)}
        finally:
            close_db(conn)

    # ─── ASSIGN ANALYST ─────────────────────────────────────────────────

    @app.put("/api/incidents/<incident_id:int>/assign")
    def assign_analyst(incident_id):
        data = request.json or {}
        assigned_to = (data.get("assigned_to") or "").strip()
        if not assigned_to:
            response.status = 400
            return {"error": "assigned_to is required"}

        conn = get_db()
        try:
            inc = conn.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if not inc:
                response.status = 404
                return {"error": "Incident not found"}

            conn.execute(
                "UPDATE incidents SET assigned_to = ?, updated_at = datetime('now','localtime') WHERE id = ?",
                (assigned_to, incident_id),
            )
            conn.commit()
            result = dict(conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone())
            return result
        finally:
            close_db(conn)

    # ─── CHANGE PHASE ───────────────────────────────────────────────────

    @app.put("/api/incidents/<incident_id:int>/phase")
    def change_phase(incident_id):
        data = request.json or {}
        new_phase = (data.get("phase") or "").strip().lower()
        if new_phase not in PHASES:
            response.status = 400
            return {"error": f"Invalid phase. Must be one of: {PHASES}"}

        conn = get_db()
        try:
            inc = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if not inc:
                response.status = 404
                return {"error": "Incident not found"}

            notes = (data.get("notes") or "").strip()
            changed_by = (data.get("changed_by") or "analyst").strip()

            # Close the currently active phase log entry
            active_phase = conn.execute(
                "SELECT id FROM incident_phase_log WHERE incident_id = ? AND completed_at IS NULL "
                "ORDER BY started_at DESC LIMIT 1",
                (incident_id,),
            ).fetchone()
            if active_phase:
                conn.execute(
                    "UPDATE incident_phase_log SET completed_at = datetime('now','localtime'), "
                    "completed_by = ?, notes = ? WHERE id = ?",
                    (changed_by, notes, active_phase["id"]),
                )

            # Open new phase log entry
            conn.execute(
                "INSERT INTO incident_phase_log (incident_id, phase, started_at, completed_by) "
                "VALUES (?, ?, datetime('now','localtime'), ?)",
                (incident_id, new_phase, changed_by),
            )

            # Update incident record
            new_status = "closed" if new_phase == "closed" else (
                "investigating" if new_phase in ("investigate", "contain", "eradicate", "recover") else "open"
            )
            resolved_clause = ", resolved_at = datetime('now','localtime')" if new_phase == "closed" else ""
            conn.execute(
                f"UPDATE incidents SET phase = ?, phase_started_at = datetime('now','localtime'), "
                f"status = ?, updated_at = datetime('now','localtime'){resolved_clause} WHERE id = ?",
                (new_phase, new_status, incident_id),
            )
            conn.commit()

            result = dict(conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone())
            return {"ok": True, "phase": new_phase, "status": new_status, "incident": result}
        finally:
            close_db(conn)

    # ─── EXPORT INCIDENT ────────────────────────────────────────────────

    @app.get("/api/incidents/<incident_id:int>/export")
    def export_incident(incident_id):
        conn = get_db()
        try:
            inc = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if not inc:
                response.status = 404
                return {"error": "Incident not found"}

            events = [dict(r) for r in conn.execute(
                "SELECT * FROM incident_events WHERE incident_id = ? ORDER BY timestamp",
                (incident_id,),
            ).fetchall()]

            notes = [dict(r) for r in conn.execute(
                "SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at",
                (incident_id,),
            ).fetchall()]

            evidence = [dict(r) for r in conn.execute(
                "SELECT id, incident_id, filename, file_size, content_type, description, "
                "hash_sha256, uploaded_by, uploaded_at FROM evidence WHERE incident_id = ? "
                "ORDER BY uploaded_at",
                (incident_id,),
            ).fetchall()]

            iocs = [dict(r) for r in conn.execute(
                "SELECT * FROM incident_iocs WHERE incident_id = ? ORDER BY created_at",
                (incident_id,),
            ).fetchall()]

            phase_log = [dict(r) for r in conn.execute(
                "SELECT * FROM incident_phase_log WHERE incident_id = ? ORDER BY started_at",
                (incident_id,),
            ).fetchall()]

            export_data = {
                "exported_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "incident": dict(inc),
                "events": events,
                "notes": notes,
                "evidence": evidence,
                "iocs": iocs,
                "phase_log": phase_log,
            }

            response.content_type = "application/json"
            response.headers["Content-Disposition"] = (
                f'attachment; filename="incident_{incident_id}_export.json"'
            )
            return json.dumps(export_data, indent=2, default=str)
        finally:
            close_db(conn)

    # ─── SLA STATUS ─────────────────────────────────────────────────────

    @app.get("/api/incidents/sla-status")
    def sla_status():
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE status NOT IN ('closed', 'resolved') "
                "ORDER BY created_at ASC"
            ).fetchall()

            now = datetime.now()
            results = []
            for r in rows:
                inc = dict(r)
                severity = inc.get("severity", "medium")
                sla_hours = SLA_THRESHOLDS.get(severity, 24)

                created_str = inc.get("created_at", "")
                try:
                    created_at = datetime.strptime(created_str, "%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError):
                    try:
                        created_at = datetime.fromisoformat(created_str)
                    except (ValueError, TypeError):
                        created_at = now

                elapsed = now - created_at
                elapsed_hours = elapsed.total_seconds() / 3600.0
                sla_deadline = created_at + timedelta(hours=sla_hours)
                remaining_hours = (sla_deadline - now).total_seconds() / 3600.0

                breached = elapsed_hours > sla_hours

                results.append({
                    "incident_id": inc["id"],
                    "title": inc.get("title", ""),
                    "severity": severity,
                    "status": inc.get("status", ""),
                    "phase": inc.get("phase", ""),
                    "assigned_to": inc.get("assigned_to", ""),
                    "created_at": created_str,
                    "sla_hours": sla_hours,
                    "elapsed_hours": round(elapsed_hours, 2),
                    "remaining_hours": round(remaining_hours, 2),
                    "sla_deadline": sla_deadline.strftime("%Y-%m-%d %H:%M:%S"),
                    "breached": breached,
                })

            breached_count = sum(1 for r in results if r["breached"])
            return {
                "sla_status": results,
                "total_open": len(results),
                "breached": breached_count,
                "within_sla": len(results) - breached_count,
            }
        finally:
            close_db(conn)
