"""
Authentication & user-management routes for NOTICE.

Provides login/logout, user CRUD (admin only), password change, and
audit-log retrieval.  All endpoints live under ``/api/auth/``.
"""

import hashlib
import json
import time as _time

import bottle
from bottle import request, response

from db import get_db, close_db
from auth import (
    hash_password,
    verify_password,
    create_session,
    get_current_user,
    require_auth,
    require_role,
    audit,
    create_api_key,
    list_api_keys,
    revoke_api_key,
)


# ---------------------------------------------------------------------------
# Brute-force rate limiting (in-memory)
# ---------------------------------------------------------------------------
_login_failures = {}  # ip -> [timestamp, timestamp, ...]
_MAX_FAILURES = 5
_LOCKOUT_SECONDS = 900  # 15 minutes


def _check_rate_limit(ip):
    """Returns (blocked: bool, retry_after_seconds: int)"""
    now = _time.time()
    attempts = _login_failures.get(ip, [])
    # Prune old attempts
    attempts = [t for t in attempts if now - t < _LOCKOUT_SECONDS]
    _login_failures[ip] = attempts
    if len(attempts) >= _MAX_FAILURES:
        oldest = attempts[0]
        retry_after = int(_LOCKOUT_SECONDS - (now - oldest))
        return True, max(retry_after, 1)
    return False, 0


def _record_failure(ip):
    now = _time.time()
    if ip not in _login_failures:
        _login_failures[ip] = []
    _login_failures[ip].append(now)


def _clear_failures(ip):
    _login_failures.pop(ip, None)


def _json_response(data, status=200):
    """Helper: set status + content-type and return serialised JSON."""
    response.status = status
    response.content_type = "application/json"
    return json.dumps(data)


def _get_client_ip():
    return request.environ.get("REMOTE_ADDR", "")


def register(app):
    """Mount all /api/auth/* routes onto *app*."""

    # ------------------------------------------------------------------
    # POST /api/auth/login
    # ------------------------------------------------------------------
    @app.post("/api/auth/login")
    def login():
        ip = _get_client_ip()

        # Brute-force rate limiting
        blocked, retry_after = _check_rate_limit(ip)
        if blocked:
            return _json_response(
                {"error": f"Too many login attempts. Try again in {retry_after // 60 + 1} minutes."},
                429,
            )

        try:
            body = request.json or {}
        except Exception:
            return _json_response({"error": "Invalid JSON body"}, 400)

        username = (body.get("username") or "").strip()
        password = body.get("password") or ""

        if not username or not password:
            return _json_response({"error": "Username and password are required"}, 400)

        conn = get_db()
        try:
            row = conn.execute(
                "SELECT id, username, password_hash, salt, email, full_name, role, active "
                "FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        finally:
            close_db(conn)

        if row is None:
            _record_failure(ip)
            return _json_response({"error": "Invalid username or password"}, 401)

        user = dict(row)

        if not user.get("active", 1):
            _record_failure(ip)
            return _json_response({"error": "Account is deactivated"}, 403)

        if not verify_password(password, user["password_hash"], user["salt"]):
            _record_failure(ip)
            return _json_response({"error": "Invalid username or password"}, 401)

        # Successful login — clear failure tracking
        _clear_failures(ip)

        # Create session
        token = create_session(user["id"], request)

        # Update last_login
        conn = get_db()
        try:
            conn.execute(
                "UPDATE users SET last_login = datetime('now','localtime') WHERE id = ?",
                (user["id"],),
            )
            conn.commit()
        finally:
            close_db(conn)

        # Set cookie — only mark Secure when the request arrived over HTTPS
        _is_https = request.urlparts.scheme == "https"
        response.set_cookie(
            "notice_session",
            token,
            path="/",
            httponly=True,
            secure=_is_https,
            max_age=86400,
            samesite="Lax",
        )

        audit(
            {"id": user["id"], "username": user["username"]},
            "login",
            target_type="session",
            detail="User logged in",
            ip=ip,
        )

        return _json_response({
            "ok": True,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "full_name": user["full_name"],
                "role": user["role"],
            },
        })

    # ------------------------------------------------------------------
    # POST /api/auth/logout
    # ------------------------------------------------------------------
    @app.post("/api/auth/logout")
    def logout():
        token = request.get_cookie("notice_session")
        if token:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            conn = get_db()
            try:
                conn.execute("DELETE FROM sessions WHERE token = ?", (token_hash,))
                conn.commit()
            finally:
                close_db(conn)

        response.delete_cookie("notice_session", path="/")
        return _json_response({"ok": True})

    # ------------------------------------------------------------------
    # GET /api/auth/me
    # ------------------------------------------------------------------
    @app.get("/api/auth/me")
    @require_auth
    def me():
        user = request.user
        return _json_response({
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
        })

    # ------------------------------------------------------------------
    # GET /api/auth/users  (admin only)
    # ------------------------------------------------------------------
    @app.get("/api/auth/users")
    @require_auth
    @require_role("admin")
    def list_users():
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT id, username, email, full_name, role, active, last_login, created_at "
                "FROM users ORDER BY id"
            ).fetchall()
        finally:
            close_db(conn)

        users = [dict(r) for r in rows]
        return _json_response({"users": users})

    # ------------------------------------------------------------------
    # GET /api/auth/users/assignable  (all authenticated users)
    # Returns just username + full_name + role for the incident-assignee
    # dropdown. Viewers are excluded (can't handle incidents).
    # ------------------------------------------------------------------
    @app.get("/api/auth/users/assignable")
    @require_auth
    def list_assignable_users():
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT username, full_name, role FROM users "
                "WHERE active = 1 AND role IN ('admin','analyst') "
                "ORDER BY role DESC, username"
            ).fetchall()
        finally:
            close_db(conn)
        return _json_response({"users": [dict(r) for r in rows]})

    # ------------------------------------------------------------------
    # POST /api/auth/users  (admin only)
    # ------------------------------------------------------------------
    @app.post("/api/auth/users")
    @require_auth
    @require_role("admin")
    def create_user():
        try:
            body = request.json or {}
        except Exception:
            return _json_response({"error": "Invalid JSON body"}, 400)

        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        email = (body.get("email") or "").strip()
        full_name = (body.get("full_name") or "").strip()
        role = (body.get("role") or "analyst").strip()

        if not username:
            return _json_response({"error": "Username is required"}, 400)
        if not password:
            return _json_response({"error": "Password is required"}, 400)
        if len(password) < 4:
            return _json_response({"error": "Password must be at least 4 characters"}, 400)
        if role not in ("admin", "analyst", "viewer"):
            return _json_response({"error": "Role must be admin, analyst, or viewer"}, 400)

        pw_hash, salt = hash_password(password)

        conn = get_db()
        try:
            # Check uniqueness
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if existing:
                return _json_response({"error": "Username already exists"}, 409)

            conn.execute(
                "INSERT INTO users (username, password_hash, salt, email, full_name, role) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (username, pw_hash, salt, email, full_name, role),
            )
            conn.commit()
            new_id = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()["id"]
        finally:
            close_db(conn)

        admin_user = request.user
        audit(
            admin_user,
            "create_user",
            target_type="user",
            target_id=str(new_id),
            detail=f"Created user '{username}' with role '{role}'",
            ip=_get_client_ip(),
        )

        return _json_response({
            "ok": True,
            "user": {
                "id": new_id,
                "username": username,
                "email": email,
                "full_name": full_name,
                "role": role,
            },
        }, 201)

    # ------------------------------------------------------------------
    # PUT /api/auth/users/<user_id>  (admin only)
    # ------------------------------------------------------------------
    @app.put("/api/auth/users/<user_id:int>")
    @require_auth
    @require_role("admin")
    def update_user(user_id):
        try:
            body = request.json or {}
        except Exception:
            return _json_response({"error": "Invalid JSON body"}, 400)

        conn = get_db()
        try:
            row = conn.execute(
                "SELECT id, username FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if row is None:
                return _json_response({"error": "User not found"}, 404)

            allowed = {"email", "full_name", "role", "active"}
            updates = []
            params = []

            for field in allowed:
                if field in body:
                    value = body[field]
                    if field == "role" and value not in ("admin", "analyst", "viewer"):
                        return _json_response(
                            {"error": "Role must be admin, analyst, or viewer"}, 400
                        )
                    if field == "active" and value not in (0, 1, True, False):
                        return _json_response(
                            {"error": "Active must be 0 or 1"}, 400
                        )
                    if field == "active":
                        value = 1 if value else 0
                    updates.append(f"{field} = ?")
                    params.append(value)

            # Allow password reset by admin
            if "password" in body:
                new_pw = body["password"]
                if not new_pw or len(new_pw) < 4:
                    return _json_response(
                        {"error": "Password must be at least 4 characters"}, 400
                    )
                pw_hash, salt = hash_password(new_pw)
                updates.append("password_hash = ?")
                params.append(pw_hash)
                updates.append("salt = ?")
                params.append(salt)

            if not updates:
                return _json_response({"error": "No valid fields to update"}, 400)

            updates.append("updated_at = datetime('now','localtime')")
            params.append(user_id)
            conn.execute(
                f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
                params,
            )

            # If password was reset by admin, invalidate all sessions for that user
            if "password" in body:
                conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

            conn.commit()

            updated = conn.execute(
                "SELECT id, username, email, full_name, role, active, last_login, created_at "
                "FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        finally:
            close_db(conn)

        admin_user = request.user
        audit(
            admin_user,
            "update_user",
            target_type="user",
            target_id=str(user_id),
            detail=f"Updated fields: {', '.join(body.keys())}",
            ip=_get_client_ip(),
        )

        return _json_response({"ok": True, "user": dict(updated)})

    # ------------------------------------------------------------------
    # DELETE /api/auth/users/<user_id>  (admin only — soft-delete)
    # ------------------------------------------------------------------
    @app.delete("/api/auth/users/<user_id:int>")
    @require_auth
    @require_role("admin")
    def deactivate_user(user_id):
        admin_user = request.user

        # Prevent self-deactivation
        if admin_user["id"] == user_id:
            return _json_response({"error": "Cannot deactivate your own account"}, 400)

        conn = get_db()
        try:
            row = conn.execute(
                "SELECT id, username FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if row is None:
                return _json_response({"error": "User not found"}, 404)

            conn.execute(
                "UPDATE users SET active = 0, updated_at = datetime('now','localtime') WHERE id = ?",
                (user_id,),
            )
            # Invalidate all sessions for this user
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            conn.commit()
        finally:
            close_db(conn)

        audit(
            admin_user,
            "deactivate_user",
            target_type="user",
            target_id=str(user_id),
            detail=f"Deactivated user '{dict(row)['username']}'",
            ip=_get_client_ip(),
        )

        return _json_response({"ok": True})

    # ------------------------------------------------------------------
    # PUT /api/auth/password  (change own password)
    # ------------------------------------------------------------------
    @app.put("/api/auth/password")
    @require_auth
    def change_password():
        try:
            body = request.json or {}
        except Exception:
            return _json_response({"error": "Invalid JSON body"}, 400)

        old_password = body.get("old_password") or ""
        new_password = body.get("new_password") or ""

        if not old_password or not new_password:
            return _json_response(
                {"error": "old_password and new_password are required"}, 400
            )
        if len(new_password) < 4:
            return _json_response(
                {"error": "New password must be at least 4 characters"}, 400
            )

        user = request.user
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT password_hash, salt FROM users WHERE id = ?",
                (user["id"],),
            ).fetchone()

            if not verify_password(old_password, row["password_hash"], row["salt"]):
                return _json_response({"error": "Current password is incorrect"}, 401)

            pw_hash, salt = hash_password(new_password)
            conn.execute(
                "UPDATE users SET password_hash = ?, salt = ?, updated_at = datetime('now','localtime') "
                "WHERE id = ?",
                (pw_hash, salt, user["id"]),
            )

            conn.execute(
                "DELETE FROM sessions WHERE user_id = ?",
                (user["id"],),
            )

            conn.commit()
        finally:
            close_db(conn)

        audit(
            user,
            "change_password",
            target_type="user",
            target_id=str(user["id"]),
            detail="Password changed",
            ip=_get_client_ip(),
        )

        return _json_response({"ok": True})

    # ------------------------------------------------------------------
    # GET /api/auth/audit  (admin only)
    # ------------------------------------------------------------------
    @app.get("/api/auth/audit")
    @require_auth
    @require_role("admin")
    def audit_log():
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT id, user_id, username, action, target_type, target_id, "
                "detail, ip_address, created_at "
                "FROM audit_log ORDER BY id DESC LIMIT 100"
            ).fetchall()
        finally:
            close_db(conn)

        entries = [dict(r) for r in rows]
        return _json_response({"entries": entries})

    # -------------------------------------------------------------------
    # API Key Management
    # -------------------------------------------------------------------

    @app.post("/api/auth/api-keys")
    def create_key():
        """Create a new API key. Admin can create for any user, others only for themselves."""
        user = get_current_user(request)
        if not user:
            return _json_response({"error": "Authentication required"}, 401)
        body = request.json or {}
        name = body.get("name", "").strip()
        if not name:
            return _json_response({"error": "Key name is required"}, 400)
        expires_days = body.get("expires_days")
        target_user = int(body.get("user_id", user["id"]))
        if target_user != user["id"] and user["role"] != "admin":
            return _json_response({"error": "Only admins can create keys for other users"}, 403)

        raw_key = create_api_key(target_user, name, expires_days=expires_days)
        return _json_response({"ok": True, "key": raw_key, "name": name,
                               "message": "Save this key — it won't be shown again"})

    @app.get("/api/auth/api-keys")
    def get_keys():
        """List API keys. Admin sees all, others see only their own."""
        user = get_current_user(request)
        if not user:
            return _json_response({"error": "Authentication required"}, 401)
        if user["role"] == "admin":
            keys = list_api_keys()
        else:
            keys = list_api_keys(user_id=user["id"])
        return _json_response({"keys": keys})

    @app.delete("/api/auth/api-keys/<key_id:int>")
    def delete_key(key_id):
        """Revoke an API key."""
        user = get_current_user(request)
        if not user:
            return _json_response({"error": "Authentication required"}, 401)
        if user["role"] != "admin":
            return _json_response({"error": "Admin only"}, 403)
        revoke_api_key(key_id)
        return _json_response({"ok": True})
