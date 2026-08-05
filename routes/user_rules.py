"""
User-defined detection rules — CRUD + apply.

Storage:
  - SQLite table `user_rules` is the source of truth for everything created
    through the UI. Fields can be combined into a compiled rule line, OR
    the user may supply a complete `raw_rule` for advanced use.
  - On Apply, all enabled rules are written to `notice-user.rules`
    (path overridable via NOTICE_USER_RULES env). Operators add a single
    `include` line to their detection-engine config to pick this up.

SID range:
  - User rules use 5,000,000+ to keep clear of:
      * 1,000,000–1,999,999 — local rule_generator output (BASE_SID=1000300)
      * 2,000,000–2,999,999 — ETOpen
      * 3,000,000–4,999,999 — reserved for community feeds
"""

import os
from datetime import datetime

from bottle import request, response

from db import get_db


USER_RULES_FILE = os.environ.get(
    "NOTICE_USER_RULES",
    "/var/lib/suricata/rules/notice-user.rules",
)
USER_SID_BASE = 5_000_000


# ── helpers ───────────────────────────────────────────────────────────────

def _next_sid(conn):
    row = conn.execute("SELECT MAX(sid) AS m FROM user_rules").fetchone()
    cur = row["m"] if row and row["m"] else None
    return max(USER_SID_BASE, (cur or USER_SID_BASE - 1) + 1)


def _validate(payload, partial=False):
    """Return (cleaned_dict, error_string_or_None)."""
    if "raw_rule" in payload and payload["raw_rule"]:
        # Advanced mode — one-shot: msg + sid extracted by user. Still require msg.
        if not (payload.get("msg") or "").strip():
            return None, "msg is required"
        return payload, None

    # msg is the only hard requirement; everything else has a sensible default
    if not partial and not (payload.get("msg") or "").strip():
        return None, "msg is required"

    action = (payload.get("action") or "alert").lower()
    if action not in {"alert", "drop", "reject", "pass"}:
        return None, "action must be one of alert/drop/reject/pass"

    proto = (payload.get("protocol") or "tcp").lower()
    if proto not in {"tcp", "udp", "icmp", "ip", "http", "tls", "dns", "ssh", "smb", "ftp"}:
        return None, "protocol not recognised"

    direction = (payload.get("direction") or "->").strip()
    if direction not in {"->", "<>"}:
        return None, "direction must be '->' or '<>'"

    sev = payload.get("severity", 2)
    try:
        sev = int(sev)
    except (TypeError, ValueError):
        sev = 2
    sev = max(1, min(4, sev))

    cleaned = {
        "msg": (payload.get("msg") or "").strip(),
        "action": action,
        "protocol": proto,
        "src_ip": (payload.get("src_ip") or "any").strip() or "any",
        "src_port": (payload.get("src_port") or "any").strip() or "any",
        "direction": direction,
        "dst_ip": (payload.get("dst_ip") or "any").strip() or "any",
        "dst_port": (payload.get("dst_port") or "any").strip() or "any",
        "content": (payload.get("content") or "").strip() or None,
        "classtype": (payload.get("classtype") or "attempted-recon").strip(),
        "severity": sev,
        "asset_ip": (payload.get("asset_ip") or "").strip() or None,
        "raw_rule": (payload.get("raw_rule") or "").strip() or None,
        "enabled": 1 if payload.get("enabled", True) else 0,
    }
    return cleaned, None


def _compile_rule(row):
    """Render a DB row (dict-like) into a single IDS rule line."""
    if row.get("raw_rule"):
        # Force the configured sid into the user-supplied rule body
        line = row["raw_rule"]
        if "sid:" not in line:
            line = line.rstrip(";)") + f"; sid:{row['sid']}; rev:1;)"
        return line

    msg = (row["msg"] or "").replace('"', "'")
    parts = [
        row["action"], row["protocol"], row["src_ip"], row["src_port"],
        row["direction"], row["dst_ip"], row["dst_port"],
    ]
    body = " ".join(str(p) for p in parts)
    opts = [f'msg:"USER: {msg}"']
    if row.get("content"):
        c = row["content"].replace('"', "'")
        opts.append(f'content:"{c}"')
    opts.append(f'classtype:{row["classtype"] or "attempted-recon"}')
    opts.append(f'priority:{row["severity"]}')
    opts.append(f'sid:{row["sid"]}')
    opts.append("rev:1")
    return f"{body} ({'; '.join(opts)};)"


def _row_to_dict(row):
    d = dict(row)
    d["compiled"] = _compile_rule(d)
    d["enabled"] = bool(d.get("enabled", 1))
    return d


# ── routes ────────────────────────────────────────────────────────────────

EXT2INT_PACK_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "rules", "ext2int.rules",
)
EXT2INT_DEPLOY_PATH = os.environ.get(
    "NOTICE_EXT2INT_RULES",
    "/var/lib/suricata/rules/notice-ext2int.rules",
)

ASSET_ID_PACK_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "rules", "asset_identify.rules",
)
ASSET_ID_DEPLOY_PATH = os.environ.get(
    "NOTICE_ASSET_ID_RULES",
    "/var/lib/suricata/rules/notice-asset-identify.rules",
)


def _pack_status(pack_file, deploy_path):
    try:
        with open(pack_file, "r") as f:
            src = f.read()
    except FileNotFoundError:
        return None
    rule_count = sum(1 for ln in src.splitlines()
                     if ln.strip().startswith(("alert ", "drop ", "reject ", "pass ")))
    deployed = os.path.exists(deploy_path)
    deployed_count = 0
    if deployed:
        try:
            with open(deploy_path, "r") as f:
                deployed_count = sum(1 for ln in f if ln.strip().startswith(
                    ("alert ", "drop ", "reject ", "pass ")))
        except (IOError, PermissionError):
            pass
    return {
        "pack_file": pack_file,
        "deploy_path": deploy_path,
        "pack_rule_count": rule_count,
        "deployed": deployed,
        "deployed_rule_count": deployed_count,
        "match": rule_count == deployed_count,
    }


def _pack_deploy(pack_file, deploy_path, hint_label="rule pack"):
    try:
        with open(pack_file, "r") as f:
            content = f.read()
    except FileNotFoundError:
        return None, f"{pack_file} not found in install"
    try:
        os.makedirs(os.path.dirname(deploy_path), exist_ok=True)
        tmp = deploy_path + ".tmp"
        with open(tmp, "w") as f:
            f.write(content)
        os.replace(tmp, deploy_path)
    except (OSError, PermissionError) as e:
        return None, (f"write failed: {e} | "
                      f"Try: sudo chown $(whoami) {os.path.dirname(deploy_path)} "
                      f"or set the NOTICE_*_RULES env var to a writable path.")
    return content, None


def register(app):

    @app.get("/api/rules/ext2int/status")
    def ext2int_status():
        """Inspect the bundled ext→int rule pack: how many rules, deployed?"""
        s = _pack_status(EXT2INT_PACK_FILE, EXT2INT_DEPLOY_PATH)
        if not s:
            response.status = 404
            return {"error": "rules/ext2int.rules not found in install"}
        return s

    @app.post("/api/rules/ext2int/deploy")
    def ext2int_deploy():
        """Copy the bundled ext→int rule pack to the IDS rules directory."""
        content, err = _pack_deploy(EXT2INT_PACK_FILE, EXT2INT_DEPLOY_PATH)
        if err:
            response.status = 500
            return {"error": err}
        return {
            "ok": True,
            "deploy_path": EXT2INT_DEPLOY_PATH,
            "rules_written": sum(1 for ln in content.splitlines()
                                 if ln.strip().startswith(("alert ", "drop ", "reject ", "pass "))),
            "reload_hint": f"Add `include {EXT2INT_DEPLOY_PATH}` to your suricata.yaml rule-files block, then reload: `sudo kill -USR2 $(pgrep -f suricata)`.",
        }

    @app.get("/api/rules/asset-id/status")
    def asset_id_status():
        """Inspect the asset-identification rule pack."""
        s = _pack_status(ASSET_ID_PACK_FILE, ASSET_ID_DEPLOY_PATH)
        if not s:
            response.status = 404
            return {"error": "rules/asset_identify.rules not found in install"}
        return s

    @app.post("/api/rules/asset-id/deploy")
    def asset_id_deploy():
        """Copy the asset-identification rule pack into the IDS rules dir."""
        content, err = _pack_deploy(ASSET_ID_PACK_FILE, ASSET_ID_DEPLOY_PATH)
        if err:
            response.status = 500
            return {"error": err}
        return {
            "ok": True,
            "deploy_path": ASSET_ID_DEPLOY_PATH,
            "rules_written": sum(1 for ln in content.splitlines()
                                 if ln.strip().startswith(("alert ", "drop ", "reject ", "pass "))),
            "reload_hint": f"Add `include {ASSET_ID_DEPLOY_PATH}` to your suricata.yaml rule-files block, then reload: `sudo kill -USR2 $(pgrep -f suricata)`.",
        }

    @app.get("/api/rules/by-sid/<sid:int>")
    def rule_by_sid(sid):
        """Return the rule (parsed dict + raw line) that matches `sid`,
        or 404 if not found in any source (suricata.rules / local.rules / user_rules)."""
        from analyzers.suricata_rules import get_rule_by_sid
        rule = get_rule_by_sid(sid)
        if not rule:
            response.status = 404
            return {"error": f"No rule with sid={sid} found"}
        return rule

    @app.get("/api/rules/user")
    def list_user_rules():
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM user_rules ORDER BY sid"
        ).fetchall()
        conn.close()
        rules = [_row_to_dict(r) for r in rows]
        return {
            "rules": rules,
            "total": len(rules),
            "enabled": sum(1 for r in rules if r["enabled"]),
            "next_sid": (rules[-1]["sid"] + 1) if rules else USER_SID_BASE,
            "rules_file": USER_RULES_FILE,
        }

    @app.post("/api/rules/user")
    def create_user_rule():
        payload = request.json or {}
        cleaned, err = _validate(payload)
        if err:
            response.status = 400
            return {"error": err}
        conn = get_db()
        sid = _next_sid(conn)
        conn.execute(
            """INSERT INTO user_rules
               (sid, msg, action, protocol, src_ip, src_port, direction,
                dst_ip, dst_port, content, classtype, severity, asset_ip,
                raw_rule, enabled)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (sid, cleaned["msg"], cleaned["action"], cleaned["protocol"],
             cleaned["src_ip"], cleaned["src_port"], cleaned["direction"],
             cleaned["dst_ip"], cleaned["dst_port"], cleaned["content"],
             cleaned["classtype"], cleaned["severity"], cleaned["asset_ip"],
             cleaned["raw_rule"], cleaned["enabled"]),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM user_rules WHERE sid=?", (sid,)).fetchone()
        conn.close()
        response.status = 201
        return _row_to_dict(row)

    @app.put("/api/rules/user/<sid:int>")
    def update_user_rule(sid):
        payload = request.json or {}
        cleaned, err = _validate(payload)
        if err:
            response.status = 400
            return {"error": err}
        conn = get_db()
        row = conn.execute("SELECT sid FROM user_rules WHERE sid=?", (sid,)).fetchone()
        if not row:
            conn.close()
            response.status = 404
            return {"error": f"no rule with sid {sid}"}
        conn.execute(
            """UPDATE user_rules SET
                 msg=?, action=?, protocol=?, src_ip=?, src_port=?,
                 direction=?, dst_ip=?, dst_port=?, content=?, classtype=?,
                 severity=?, asset_ip=?, raw_rule=?, enabled=?,
                 updated_at=datetime('now','localtime')
               WHERE sid=?""",
            (cleaned["msg"], cleaned["action"], cleaned["protocol"],
             cleaned["src_ip"], cleaned["src_port"], cleaned["direction"],
             cleaned["dst_ip"], cleaned["dst_port"], cleaned["content"],
             cleaned["classtype"], cleaned["severity"], cleaned["asset_ip"],
             cleaned["raw_rule"], cleaned["enabled"], sid),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM user_rules WHERE sid=?", (sid,)).fetchone()
        conn.close()
        return _row_to_dict(row)

    @app.delete("/api/rules/user/<sid:int>")
    def delete_user_rule(sid):
        conn = get_db()
        cur = conn.execute("DELETE FROM user_rules WHERE sid=?", (sid,))
        conn.commit()
        conn.close()
        if cur.rowcount == 0:
            response.status = 404
            return {"error": f"no rule with sid {sid}"}
        return {"ok": True, "deleted": sid}

    @app.post("/api/rules/user/preview")
    def preview_user_rule():
        """Return the compiled rule line for a draft (no DB write)."""
        payload = request.json or {}
        cleaned, err = _validate(payload)
        if err:
            response.status = 400
            return {"error": err}
        # Use a placeholder sid for preview if none supplied
        cleaned["sid"] = payload.get("sid") or USER_SID_BASE
        return {"compiled": _compile_rule(cleaned)}

    @app.post("/api/rules/user/apply")
    def apply_user_rules():
        """Write all enabled user_rules to the rules file."""
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM user_rules WHERE enabled=1 ORDER BY sid"
        ).fetchall()
        conn.close()
        rules = [_row_to_dict(r) for r in rows]

        header = (
            f"# === NOTICE user-defined rules ===\n"
            f"# Generated: {datetime.now().isoformat()}\n"
            f"# DO NOT EDIT MANUALLY — managed via Monitoring → Rule Manager\n"
            f"# Total enabled: {len(rules)}\n\n"
        )
        body = "\n".join(r["compiled"] for r in rules) + ("\n" if rules else "")

        try:
            os.makedirs(os.path.dirname(USER_RULES_FILE), exist_ok=True)
            tmp = USER_RULES_FILE + ".tmp"
            with open(tmp, "w") as f:
                f.write(header)
                f.write(body)
            os.replace(tmp, USER_RULES_FILE)
            ok, write_err = True, None
        except (OSError, PermissionError) as e:
            ok, write_err = False, str(e)

        return {
            "ok": ok,
            "rules_file": USER_RULES_FILE,
            "rules_written": len(rules) if ok else 0,
            "error": write_err,
            "reload_hint": (
                "Reload the detection engine to pick up the new rules: "
                "`sudo kill -USR2 $(pgrep -f 'detection-engine')` "
                "or restart the engine service."
            ),
        }
