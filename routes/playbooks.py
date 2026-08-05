"""Playbooks API — predefined incident response workflows."""

import json
from bottle import request, response
from db import get_db, now_ist_str
from validation import sanitize_string as sanitize


def register(app):

    @app.get("/api/playbooks")
    def api_list_playbooks():
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM playbooks ORDER BY created_at DESC"
        ).fetchall()
        result = []
        for r in rows:
            steps = conn.execute(
                "SELECT * FROM playbook_steps WHERE playbook_id=? ORDER BY step_order",
                (r["id"],)
            ).fetchall()
            result.append({
                **dict(r),
                "steps": [dict(s) for s in steps],
            })
        conn.close()
        return {"playbooks": result}

    @app.get("/api/playbooks/<pid:int>")
    def api_get_playbook(pid):
        conn = get_db()
        row = conn.execute("SELECT * FROM playbooks WHERE id=?", (pid,)).fetchone()
        if not row:
            conn.close()
            response.status = 404
            return {"error": "Not found"}
        steps = conn.execute(
            "SELECT * FROM playbook_steps WHERE playbook_id=? ORDER BY step_order",
            (pid,)
        ).fetchall()
        executions = conn.execute(
            "SELECT * FROM playbook_executions WHERE playbook_id=? ORDER BY started_at DESC LIMIT 20",
            (pid,)
        ).fetchall()
        conn.close()
        return {
            **dict(row),
            "steps": [dict(s) for s in steps],
            "executions": [dict(e) for e in executions],
        }

    @app.post("/api/playbooks")
    def api_create_playbook():
        data = request.json or {}
        name = sanitize(data.get("name", ""))
        description = sanitize(data.get("description", ""))
        category = sanitize(data.get("category", "general"))
        severity = sanitize(data.get("severity", "medium"))
        trigger = sanitize(data.get("trigger", "manual"))
        steps = data.get("steps", [])

        if not name:
            response.status = 400
            return {"error": "Name required"}

        conn = get_db()
        now = now_ist_str()
        cur = conn.execute(
            """INSERT INTO playbooks (name, description, category, severity, trigger_type, created_at, updated_at, status)
               VALUES (?,?,?,?,?,?,?,?)""",
            (name, description, category, severity, trigger, now, now, "active")
        )
        pid = cur.lastrowid
        for i, step in enumerate(steps):
            conn.execute(
                """INSERT INTO playbook_steps (playbook_id, step_order, title, description, action_type, auto_action)
                   VALUES (?,?,?,?,?,?)""",
                (pid, i + 1,
                 sanitize(step.get("title", f"Step {i+1}")),
                 sanitize(step.get("description", "")),
                 sanitize(step.get("action_type", "manual")),
                 sanitize(step.get("auto_action", "")))
            )
        conn.commit()
        conn.close()
        return {"id": pid, "status": "created"}

    @app.put("/api/playbooks/<pid:int>")
    def api_update_playbook(pid):
        data = request.json or {}
        conn = get_db()
        row = conn.execute("SELECT id FROM playbooks WHERE id=?", (pid,)).fetchone()
        if not row:
            conn.close()
            response.status = 404
            return {"error": "Not found"}
        now = now_ist_str()
        conn.execute(
            """UPDATE playbooks SET name=?, description=?, category=?, severity=?,
               trigger_type=?, updated_at=?, status=? WHERE id=?""",
            (sanitize(data.get("name", "")), sanitize(data.get("description", "")),
             sanitize(data.get("category", "general")), sanitize(data.get("severity", "medium")),
             sanitize(data.get("trigger", "manual")), now,
             sanitize(data.get("status", "active")), pid)
        )
        steps = data.get("steps", [])
        if steps:
            conn.execute("DELETE FROM playbook_steps WHERE playbook_id=?", (pid,))
            for i, step in enumerate(steps):
                conn.execute(
                    """INSERT INTO playbook_steps (playbook_id, step_order, title, description, action_type, auto_action)
                       VALUES (?,?,?,?,?,?)""",
                    (pid, i + 1,
                     sanitize(step.get("title", f"Step {i+1}")),
                     sanitize(step.get("description", "")),
                     sanitize(step.get("action_type", "manual")),
                     sanitize(step.get("auto_action", "")))
                )
        conn.commit()
        conn.close()
        return {"status": "updated"}

    @app.delete("/api/playbooks/<pid:int>")
    def api_delete_playbook(pid):
        conn = get_db()
        conn.execute("DELETE FROM playbook_steps WHERE playbook_id=?", (pid,))
        conn.execute("DELETE FROM playbook_executions WHERE playbook_id=?", (pid,))
        conn.execute("DELETE FROM playbooks WHERE id=?", (pid,))
        conn.commit()
        conn.close()
        return {"status": "deleted"}

    @app.post("/api/playbooks/<pid:int>/execute")
    def api_execute_playbook(pid):
        data = request.json or {}
        conn = get_db()
        row = conn.execute("SELECT * FROM playbooks WHERE id=?", (pid,)).fetchone()
        if not row:
            conn.close()
            response.status = 404
            return {"error": "Not found"}
        now = now_ist_str()
        user = getattr(request, "user", {})
        username = user.get("username", "system") if isinstance(user, dict) else "system"
        incident_id = data.get("incident_id")
        cur = conn.execute(
            """INSERT INTO playbook_executions
               (playbook_id, incident_id, started_at, status, executed_by, step_statuses)
               VALUES (?,?,?,?,?,?)""",
            (pid, incident_id, now, "in_progress", username, "[]")
        )
        exec_id = cur.lastrowid
        conn.commit()
        conn.close()
        return {"execution_id": exec_id, "status": "started"}

    @app.put("/api/playbooks/executions/<eid:int>")
    def api_update_execution(eid):
        data = request.json or {}
        conn = get_db()
        row = conn.execute("SELECT id FROM playbook_executions WHERE id=?", (eid,)).fetchone()
        if not row:
            conn.close()
            response.status = 404
            return {"error": "Not found"}
        updates = []
        params = []
        if "status" in data:
            updates.append("status=?")
            params.append(sanitize(data["status"]))
        if "step_statuses" in data:
            updates.append("step_statuses=?")
            params.append(json.dumps(data["step_statuses"]))
        if data.get("status") in ("completed", "failed"):
            updates.append("completed_at=?")
            params.append(now_ist_str())
        if updates:
            params.append(eid)
            conn.execute(f"UPDATE playbook_executions SET {','.join(updates)} WHERE id=?", params)
            conn.commit()
        conn.close()
        return {"status": "updated"}
