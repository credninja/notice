"""
Policy rules and violations API.
"""

import json
from bottle import request, response
from db import get_db, safe_update, cache_get, cache_set
from analyzers.policy import evaluate_policies


def register(app):

    @app.get("/api/policies")
    def list_policies():
        conn = get_db()
        rows = conn.execute("SELECT * FROM policy_rules ORDER BY id").fetchall()
        conn.close()
        policies = []
        for r in rows:
            p = dict(r)
            p["config"] = json.loads(p["config"]) if p["config"] else {}
            policies.append(p)
        return {"policies": policies}

    @app.post("/api/policies")
    def create_policy():
        data = request.json or {}
        name = data.get("name", "").strip()
        if not name:
            response.status = 400
            return {"error": "Name is required"}

        config = data.get("config", {})
        if isinstance(config, dict):
            config = json.dumps(config)

        conn = get_db()
        cur = conn.execute(
            "INSERT INTO policy_rules (name, description, rule_type, config, severity) VALUES (?, ?, ?, ?, ?)",
            (name, data.get("description", ""), data.get("rule_type", "custom"),
             config, data.get("severity", "medium")),
        )
        policy_id = cur.lastrowid
        conn.commit()
        result = dict(conn.execute("SELECT * FROM policy_rules WHERE id = ?", (policy_id,)).fetchone())
        result["config"] = json.loads(result["config"]) if result["config"] else {}
        conn.close()
        response.status = 201
        return result

    @app.put("/api/policies/<policy_id:int>")
    def update_policy(policy_id):
        data = request.json or {}
        conn = get_db()
        row = conn.execute("SELECT * FROM policy_rules WHERE id = ?", (policy_id,)).fetchone()
        if not row:
            conn.close()
            response.status = 404
            return {"error": "Policy not found"}

        # Normalize special fields before safe_update
        safe_data = {}
        for field in ("name", "description", "severity", "rule_type"):
            if field in data:
                safe_data[field] = data[field]
        if "enabled" in data:
            safe_data["enabled"] = 1 if data["enabled"] else 0
        if "config" in data:
            config = data["config"]
            safe_data["config"] = json.dumps(config) if isinstance(config, dict) else config

        _POLICY_FIELDS = frozenset({"name", "description", "severity", "rule_type", "enabled", "config"})
        safe_update("policy_rules", _POLICY_FIELDS, safe_data, "WHERE id = ?", [policy_id])

        result = dict(conn.execute("SELECT * FROM policy_rules WHERE id = ?", (policy_id,)).fetchone())
        result["config"] = json.loads(result["config"]) if result["config"] else {}
        conn.close()
        return result

    @app.delete("/api/policies/<policy_id:int>")
    def delete_policy(policy_id):
        conn = get_db()
        conn.execute("DELETE FROM policy_rules WHERE id = ?", (policy_id,))
        conn.commit()
        conn.close()
        return {"ok": True}

    @app.get("/api/policies/scan")
    def scan_policies():
        minutes = int(request.query.get("minutes", 60)) or 60
        cache_key = f"policy_scan_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached

        conn = get_db()
        rows = conn.execute("SELECT * FROM policy_rules WHERE enabled = 1").fetchall()
        rules = [dict(r) for r in rows]
        conn.close()

        violations = evaluate_policies(rules, minutes=minutes)

        # Store violations in DB
        conn = get_db()
        conn.execute("DELETE FROM policy_violations WHERE acknowledged = 0")
        for v in violations:
            conn.execute(
                """INSERT INTO policy_violations
                   (rule_id, rule_name, src_ip, dest_ip, event_type, detail, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (v["rule_id"], v["rule_name"], v["src_ip"], v["dest_ip"],
                 v["event_type"], v["detail"], v.get("last_seen", "")),
            )
        conn.commit()
        conn.close()

        # Summary by rule
        by_rule = {}
        for v in violations:
            rn = v["rule_name"]
            if rn not in by_rule:
                by_rule[rn] = {"count": 0, "severity": v["severity"]}
            by_rule[rn]["count"] += 1

        result = {
            "violations": violations,
            "total": len(violations),
            "by_rule": by_rule,
        }
        cache_set(cache_key, result, ttl=120)
        return result

    @app.post("/api/violations/<violation_id:int>/ack")
    def ack_violation(violation_id):
        conn = get_db()
        conn.execute("UPDATE policy_violations SET acknowledged = 1 WHERE id = ?", (violation_id,))
        conn.commit()
        conn.close()
        return {"ok": True}

    @app.get("/api/violations")
    def list_violations():
        conn = get_db()
        ack = request.query.get("acknowledged", "")
        query = "SELECT * FROM policy_violations"
        params = []
        if ack != "":
            query += " WHERE acknowledged = ?"
            params.append(int(ack))
        query += " ORDER BY detected_at DESC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return {"violations": [dict(r) for r in rows]}
