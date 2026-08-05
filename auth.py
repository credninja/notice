"""
Authentication middleware and helpers for NOTICE.

Provides password hashing (pbkdf2_hmac), session management, decorators
for route protection, and audit logging.
"""

import hashlib
import secrets
import functools
import json
from datetime import datetime, timedelta

import bottle

from db import get_db, close_db


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(password, salt=None):
    """Hash a password with PBKDF2-HMAC-SHA256.

    Args:
        password: plaintext password string
        salt: hex-encoded salt string, or None to generate a new one

    Returns:
        (hash_hex, salt_hex) tuple
    """
    if salt is None:
        salt = secrets.token_hex(32)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 310000
    ).hex()
    return pw_hash, salt


def verify_password(password, stored_hash, salt):
    """Verify a plaintext password against a stored hash + salt.

    Returns True if the password matches, False otherwise.
    """
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 310000
    ).hex()
    return secrets.compare_digest(candidate, stored_hash)


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

def create_session(user_id, request):
    """Create a new session for the given user.

    Stores a SHA-256 hash of the token in the ``sessions`` table (so a DB
    leak does not directly expose valid session credentials) with a 24-hour
    expiry and returns the raw opaque token string to the caller.
    """
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    ip_address = request.environ.get("REMOTE_ADDR", "")
    user_agent = request.environ.get("HTTP_USER_AGENT", "")
    expires_at = (datetime.now() + timedelta(hours=24)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO sessions (token, user_id, ip_address, user_agent, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (token_hash, user_id, ip_address, user_agent, expires_at),
        )
        conn.commit()
    finally:
        close_db(conn)

    return token


def get_current_user(request):
    """Return the authenticated user dict or None.

    Checks (in order):
      1. X-API-Key header — for programmatic/API access
      2. notice_session cookie — for browser sessions
    """
    # 1. API key authentication
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return _authenticate_api_key(api_key)

    # 2. Session cookie authentication
    token = request.get_cookie("notice_session")
    if not token:
        return None

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT u.id, u.username, u.email, u.full_name, u.role, u.active "
            "FROM sessions s JOIN users u ON s.user_id = u.id "
            "WHERE s.token = ? AND s.expires_at > ?",
            (token_hash, now),
        ).fetchone()
    finally:
        close_db(conn)

    if row is None:
        return None

    user = dict(row)
    if not user.get("active", 1):
        return None

    return user


def _authenticate_api_key(key):
    """Validate an API key and return the associated user or None."""
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT ak.id as key_id, ak.user_id, ak.expires_at, "
            "u.id, u.username, u.email, u.full_name, u.role, u.active "
            "FROM api_keys ak JOIN users u ON ak.user_id = u.id "
            "WHERE ak.key_hash = ? AND ak.revoked = 0",
            (key_hash,),
        ).fetchone()
    except Exception:
        close_db(conn)
        return None
    finally:
        close_db(conn)

    if row is None:
        return None

    user = dict(row)
    if not user.get("active", 1):
        return None

    # Check expiry (NULL means never expires)
    expires = user.get("expires_at")
    if expires and expires < now:
        return None

    # Update last_used
    conn = get_db()
    try:
        conn.execute("UPDATE api_keys SET last_used = ? WHERE id = ?",
                     (now, user.get("key_id")))
        conn.commit()
    except Exception:
        pass
    finally:
        close_db(conn)

    return {"id": user["user_id"], "username": user["username"],
            "email": user.get("email", ""), "full_name": user.get("full_name", ""),
            "role": user["role"]}


# ---------------------------------------------------------------------------
# API Key management
# ---------------------------------------------------------------------------

def _ensure_api_keys_table():
    conn = get_db()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                name TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                key_prefix TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                expires_at TEXT,
                last_used TEXT,
                revoked INTEGER DEFAULT 0
            )
        """)
        conn.commit()
    finally:
        close_db(conn)


def create_api_key(user_id, name, expires_days=None):
    """Generate a new API key for a user. Returns the raw key (shown only once)."""
    _ensure_api_keys_table()
    raw_key = "ntc_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:8]
    expires_at = None
    if expires_days:
        expires_at = (datetime.now() + timedelta(days=expires_days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO api_keys (user_id, name, key_hash, key_prefix, expires_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, name, key_hash, key_prefix, expires_at),
        )
        conn.commit()
    finally:
        close_db(conn)

    return raw_key


def list_api_keys(user_id=None):
    """List API keys (without the actual key hash)."""
    _ensure_api_keys_table()
    conn = get_db()
    try:
        q = """SELECT ak.id, ak.name, ak.key_prefix, ak.created_at, ak.expires_at,
                      ak.last_used, ak.revoked, u.username
               FROM api_keys ak JOIN users u ON ak.user_id = u.id"""
        params = []
        if user_id:
            q += " WHERE ak.user_id = ?"
            params.append(user_id)
        q += " ORDER BY ak.created_at DESC"
        rows = conn.execute(q, params).fetchall()
    finally:
        close_db(conn)
    return [dict(r) for r in rows]


def revoke_api_key(key_id):
    """Revoke an API key by ID."""
    _ensure_api_keys_table()
    conn = get_db()
    try:
        conn.execute("UPDATE api_keys SET revoked = 1 WHERE id = ?", (key_id,))
        conn.commit()
    finally:
        close_db(conn)


def cleanup_expired_sessions():
    """Delete all sessions whose expires_at is in the past."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    try:
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        conn.commit()
    finally:
        close_db(conn)


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def require_auth(fn):
    """Decorator that enforces a valid session.

    Returns 401 JSON if no valid session is found; otherwise injects the
    user dict as ``request.user`` and calls the wrapped function.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        user = getattr(bottle.request, "user", None)
        if user is None:
            user = get_current_user(bottle.request)
            if user is None:
                bottle.response.status = 401
                bottle.response.content_type = "application/json"
                return json.dumps({"error": "Authentication required"})
            bottle.request.user = user
        return fn(*args, **kwargs)
    return wrapper


def require_role(*roles):
    """Decorator factory that checks user role after authentication.

    Usage::

        @require_auth
        @require_role("admin")
        def admin_only_route():
            ...

    Returns 403 JSON if the authenticated user's role is not in *roles*.
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            user = getattr(bottle.request, "user", None)
            if user is None:
                # require_auth should have run first
                bottle.response.status = 401
                bottle.response.content_type = "application/json"
                return json.dumps({"error": "Authentication required"})
            if user.get("role") not in roles:
                bottle.response.status = 403
                bottle.response.content_type = "application/json"
                return json.dumps({"error": "Insufficient permissions"})
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def audit(user, action, target_type="", target_id="", detail="", ip=""):
    """Write a row to the audit_log table.

    Args:
        user: user dict (must contain 'id' and 'username'), or None
        action: short verb, e.g. "login", "create_user"
        target_type: entity type, e.g. "user", "session"
        target_id: entity id as string
        detail: freeform detail text
        ip: client IP address
    """
    user_id = user["id"] if user else None
    username = user["username"] if user else ""

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO audit_log (user_id, username, action, target_type, target_id, detail, ip_address) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, username, action, str(target_type), str(target_id), str(detail), str(ip)),
        )
        conn.commit()
    finally:
        close_db(conn)
