"""
Sigma rule management routes — import, list, edit, convert, deploy.

Provides a REST API for managing Sigma rules: import YAML, view conversion
status, re-attempt conversions, enable/disable, and deploy converted rules
to the Suricata sigma.rules file.
"""

import re

import bottle
from bottle import request, response

from db import get_db, close_db
from analyzers.sigma import (
    parse_sigma_yaml,
    convert_to_suricata,
    import_sigma_file,
    deploy_sigma_rules,
)


def register(app):

    # ─── LIST ALL SIGMA RULES ───────────────────────────────────────────

    @app.get("/api/sigma/rules")
    def list_sigma_rules():
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT * FROM sigma_rules ORDER BY imported_at DESC"
            ).fetchall()

            rules = []
            for r in rows:
                rd = dict(r)
                rd["converted"] = bool(rd.get("suricata_rule"))
                rules.append(rd)

            return {"rules": rules, "total": len(rules)}
        finally:
            close_db(conn)

    # ─── IMPORT SIGMA YAML ──────────────────────────────────────────────

    @app.post("/api/sigma/import")
    def import_sigma():
        """Import a Sigma rule from YAML.

        Accepts either:
          - JSON body: {"yaml_content": "..."}
          - Multipart file upload: field name "file"
        """
        yaml_content = None

        # Try multipart file upload first
        upload = request.files.get("file")
        if upload:
            try:
                yaml_content = upload.file.read().decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                response.status = 400
                return {"error": "Could not read uploaded file as UTF-8 text"}
        else:
            # Try JSON body
            data = request.json or {}
            yaml_content = data.get("yaml_content", "").strip()

        if not yaml_content:
            response.status = 400
            return {"error": "No YAML content provided. Use JSON body {yaml_content} or upload a file."}

        try:
            result = import_sigma_file(yaml_content)
            response.status = 201
            return result
        except ValueError as exc:
            response.status = 400
            return {"error": str(exc)}
        except Exception as exc:
            response.status = 500
            return {"error": f"Import failed: {exc}"}

    # ─── RE-ATTEMPT CONVERSION ──────────────────────────────────────────

    @app.post("/api/sigma/rules/<rule_id:int>/reconvert")
    def reconvert_sigma(rule_id):
        """Re-attempt conversion of a Sigma rule to Suricata format."""
        conn = get_db()
        try:
            row = conn.execute("SELECT * FROM sigma_rules WHERE id = ?", (rule_id,)).fetchone()
            if not row:
                response.status = 404
                return {"error": "Sigma rule not found"}

            yaml_content = row["yaml_content"]
            try:
                sigma_dict = parse_sigma_yaml(yaml_content)
            except ValueError as exc:
                response.status = 400
                return {"error": f"YAML parse error: {exc}"}

            try:
                suricata_rule, conversion_log = convert_to_suricata(sigma_dict, conn=conn)
            except Exception as exc:
                conversion_log = f"ERROR: Conversion failed: {exc}"
                suricata_rule = ""

            sid_assigned = row["sid_assigned"]
            if suricata_rule:
                sid_match = re.search(r"sid:(\d+);", suricata_rule)
                if sid_match:
                    sid_assigned = int(sid_match.group(1))

            conn.execute(
                "UPDATE sigma_rules SET suricata_rule = ?, conversion_log = ?, "
                "sid_assigned = ?, updated_at = datetime('now','localtime') WHERE id = ?",
                (suricata_rule, conversion_log, sid_assigned, rule_id),
            )
            conn.commit()

            updated = dict(conn.execute("SELECT * FROM sigma_rules WHERE id = ?", (rule_id,)).fetchone())
            updated["converted"] = bool(updated.get("suricata_rule"))
            return updated
        finally:
            close_db(conn)

    # ─── UPDATE SIGMA RULE ──────────────────────────────────────────────

    @app.put("/api/sigma/rules/<rule_id:int>")
    def update_sigma(rule_id):
        """Update a Sigma rule — enable/disable, edit YAML.

        Body (all optional):
            enabled      — 0 or 1
            yaml_content — updated YAML (triggers re-conversion)
        """
        data = request.json or {}
        conn = get_db()
        try:
            row = conn.execute("SELECT * FROM sigma_rules WHERE id = ?", (rule_id,)).fetchone()
            if not row:
                response.status = 404
                return {"error": "Sigma rule not found"}

            # Toggle enabled
            if "enabled" in data:
                enabled = 1 if data["enabled"] else 0
                conn.execute(
                    "UPDATE sigma_rules SET enabled = ?, updated_at = datetime('now','localtime') WHERE id = ?",
                    (enabled, rule_id),
                )

            # Update YAML content and re-convert
            if "yaml_content" in data and data["yaml_content"].strip():
                yaml_content = data["yaml_content"].strip()

                try:
                    sigma_dict = parse_sigma_yaml(yaml_content)
                except ValueError as exc:
                    response.status = 400
                    return {"error": f"YAML parse error: {exc}"}

                title = sigma_dict.get("title", row["title"])
                sigma_id = sigma_dict.get("id", row["sigma_id"])
                description = sigma_dict.get("description", row["description"])
                level = sigma_dict.get("level", row["level"])
                status = sigma_dict.get("status", row["status"])
                author = sigma_dict.get("author", row["author"])

                import yaml as _yaml
                logsource = _yaml.dump(sigma_dict.get("logsource", {})) if sigma_dict.get("logsource") else ""

                # Re-attempt conversion
                suricata_rule = ""
                conversion_log = ""
                sid_assigned = row["sid_assigned"]
                try:
                    suricata_rule, conversion_log = convert_to_suricata(sigma_dict, conn=conn)
                    if suricata_rule:
                        sid_match = re.search(r"sid:(\d+);", suricata_rule)
                        if sid_match:
                            sid_assigned = int(sid_match.group(1))
                except Exception as exc:
                    conversion_log = f"ERROR: Conversion failed: {exc}"

                conn.execute(
                    """UPDATE sigma_rules SET
                       title = ?, sigma_id = ?, description = ?, level = ?,
                       status = ?, author = ?, logsource = ?, yaml_content = ?,
                       suricata_rule = ?, conversion_log = ?, sid_assigned = ?,
                       updated_at = datetime('now','localtime')
                       WHERE id = ?""",
                    (title, sigma_id, description, level, status, author, logsource,
                     yaml_content, suricata_rule, conversion_log, sid_assigned, rule_id),
                )

            conn.commit()
            updated = dict(conn.execute("SELECT * FROM sigma_rules WHERE id = ?", (rule_id,)).fetchone())
            updated["converted"] = bool(updated.get("suricata_rule"))
            return updated
        finally:
            close_db(conn)

    # ─── DELETE SIGMA RULE ──────────────────────────────────────────────

    @app.delete("/api/sigma/rules/<rule_id:int>")
    def delete_sigma(rule_id):
        conn = get_db()
        try:
            row = conn.execute("SELECT id FROM sigma_rules WHERE id = ?", (rule_id,)).fetchone()
            if not row:
                response.status = 404
                return {"error": "Sigma rule not found"}

            conn.execute("DELETE FROM sigma_rules WHERE id = ?", (rule_id,))
            conn.commit()
            return {"ok": True}
        finally:
            close_db(conn)

    # ─── DEPLOY SIGMA RULES ────────────────────────────────────────────

    @app.post("/api/sigma/deploy")
    def deploy():
        """Write all enabled converted rules to the sigma.rules file."""
        try:
            result = deploy_sigma_rules()
            return result
        except OSError as exc:
            response.status = 500
            return {"error": f"Failed to write rules file: {exc}"}
        except Exception as exc:
            response.status = 500
            return {"error": f"Deployment failed: {exc}"}

    # ─── SIGMA STATS ───────────────────────────────────────────────────

    @app.get("/api/sigma/stats")
    def sigma_stats():
        conn = get_db()
        try:
            total = conn.execute("SELECT COUNT(*) FROM sigma_rules").fetchone()[0]
            converted = conn.execute(
                "SELECT COUNT(*) FROM sigma_rules WHERE suricata_rule != ''"
            ).fetchone()[0]
            failed = conn.execute(
                "SELECT COUNT(*) FROM sigma_rules WHERE suricata_rule = '' OR suricata_rule IS NULL"
            ).fetchone()[0]
            enabled = conn.execute(
                "SELECT COUNT(*) FROM sigma_rules WHERE enabled = 1"
            ).fetchone()[0]
            enabled_converted = conn.execute(
                "SELECT COUNT(*) FROM sigma_rules WHERE enabled = 1 AND suricata_rule != ''"
            ).fetchone()[0]

            # Level breakdown
            levels = {}
            for row in conn.execute(
                "SELECT level, COUNT(*) as cnt FROM sigma_rules GROUP BY level"
            ).fetchall():
                levels[row["level"]] = row["cnt"]

            return {
                "total": total,
                "converted": converted,
                "failed": failed,
                "enabled": enabled,
                "enabled_converted": enabled_converted,
                "by_level": levels,
            }
        finally:
            close_db(conn)
