"""Session Analytics API — connection graph, protocol analytics, top talkers, file tracking."""

import os
from bottle import request, response, static_file
from db import cache_get, cache_set
from eve_reader import iter_events, is_internal
from analyzers.session_analytics import (
    get_connection_graph, get_protocol_analytics, get_session_timeline,
    get_top_talkers, get_file_transfers, get_extended_protocols,
)


def register(app):

    @app.get("/api/sessions/graph")
    def sessions_graph():
        minutes = int(request.query.get("minutes", 60))
        cache_key = f"session_graph_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = get_connection_graph(minutes=minutes)
        cache_set(cache_key, result, ttl=60)
        return result

    @app.get("/api/sessions/protocols")
    def sessions_protocols():
        minutes = int(request.query.get("minutes", 60))
        cache_key = f"session_proto_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = get_protocol_analytics(minutes=minutes)
        cache_set(cache_key, result, ttl=60)
        return result

    @app.get("/api/sessions/timeline")
    def sessions_timeline():
        minutes = int(request.query.get("minutes", 60))
        cache_key = f"session_timeline_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = get_session_timeline(minutes=minutes)
        cache_set(cache_key, result, ttl=60)
        return result

    @app.get("/api/sessions/talkers")
    def sessions_talkers():
        minutes = int(request.query.get("minutes", 60))
        cache_key = f"session_talkers_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = get_top_talkers(minutes=minutes)
        cache_set(cache_key, result, ttl=60)
        return result

    @app.get("/api/sessions/files")
    def sessions_files():
        minutes = int(request.query.get("minutes", 60))
        cache_key = f"session_files_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = get_file_transfers(minutes=minutes)
        cache_set(cache_key, result, ttl=60)
        return result

    @app.get("/api/sessions/extended")
    def sessions_extended():
        minutes = int(request.query.get("minutes", 60))
        cache_key = f"session_ext_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = get_extended_protocols(minutes=minutes)
        cache_set(cache_key, result, ttl=60)
        return result

    @app.get("/api/sessions/plaintext")
    def sessions_plaintext():
        """Return plaintext HTTP traffic with URLs, headers, and bodies."""
        minutes = int(request.query.get("minutes", 60))
        sensitive_only = request.query.get("sensitive", "0") == "1"
        cache_key = f"session_plain_{minutes}_{int(sensitive_only)}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = _get_plaintext_traffic(minutes, sensitive_only=sensitive_only)
        cache_set(cache_key, result, ttl=60)
        return result

    @app.get("/api/sessions/file-content/<sha256>")
    def file_content(sha256):
        """Serve extracted file from Suricata file-store."""
        if not sha256 or len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
            response.status = 400
            return {"error": "Invalid SHA256"}
        fstore = "/var/log/suricata/filestore"
        fpath = os.path.join(fstore, sha256[:2], sha256)
        if not os.path.isfile(fpath):
            response.status = 404
            return {"error": "File not in store"}
        size = os.path.getsize(fpath)
        if size > 2 * 1024 * 1024:
            response.status = 413
            return {"error": "File too large to display (>2MB)"}
        try:
            with open(fpath, "rb") as f:
                raw = f.read()
            try:
                text = raw.decode("utf-8", errors="replace")
                is_text = sum(1 for c in text[:500] if c.isprintable() or c in "\n\r\t") > len(text[:500]) * 0.8
            except Exception:
                is_text = False
            if is_text:
                return {"sha256": sha256, "size": size, "type": "text", "content": text[:50000]}
            else:
                import base64
                return {"sha256": sha256, "size": size, "type": "binary", "content_b64": base64.b64encode(raw[:50000]).decode()}
        except PermissionError:
            response.status = 403
            return {"error": "Cannot read file (permission denied)"}


_SENSITIVE_HEADER_NAMES = frozenset({
    "authorization", "proxy-authorization",
})

_SENSITIVE_URL_PATTERNS = (
    "login", "signin", "sign-in", "password", "passwd",
)

_SENSITIVE_BODY_PATTERNS = (
    "password", "passwd", "pass=", "pwd=",
    "username", "user=", "email=",
)


def _decode_basic_auth(value):
    """Decode Basic auth header, return 'user:pass' or None."""
    import base64 as _b64
    try:
        token = value.strip()
        if token.lower().startswith("basic "):
            token = token[6:].strip()
        decoded = _b64.b64decode(token).decode("utf-8", errors="replace")
        if ":" in decoded:
            return decoded
    except Exception:
        pass
    return None


def _extract_body_credentials(body):
    """Extract actual username/password values from request body (form or JSON)."""
    import json as _json, urllib.parse as _up
    creds = {}
    if not body:
        return creds
    # Try JSON first
    try:
        obj = _json.loads(body)
        if isinstance(obj, dict):
            for k, v in obj.items():
                kl = k.lower()
                if kl in ("password", "passwd", "pass", "pwd"):
                    creds["password"] = str(v)
                elif kl in ("username", "user", "email", "login", "user_name"):
                    creds["username"] = str(v)
            return creds
    except Exception:
        pass
    # Try URL-encoded form data
    try:
        pairs = _up.parse_qs(body, keep_blank_values=True)
        for k, vals in pairs.items():
            kl = k.lower()
            if kl in ("password", "passwd", "pass", "pwd"):
                creds["password"] = vals[0] if vals else ""
            elif kl in ("username", "user", "email", "login", "user_name"):
                creds["username"] = vals[0] if vals else ""
    except Exception:
        pass
    return creds


def _extract_query_credentials(url):
    """Extract username/password from query string parameters."""
    import urllib.parse as _up
    creds = {}
    try:
        qs = url.split("?", 1)[1] if "?" in url else ""
        if not qs:
            return creds
        pairs = _up.parse_qs(qs, keep_blank_values=True)
        for k, vals in pairs.items():
            kl = k.lower()
            if kl in ("password", "passwd", "pass", "pwd"):
                creds["password"] = vals[0] if vals else ""
            elif kl in ("username", "user", "email", "login", "user_name"):
                creds["username"] = vals[0] if vals else ""
    except Exception:
        pass
    return creds


def _detect_sensitive(entry, req_headers, resp_headers, req_body, resp_body):
    """Detect actual plaintext credentials only: Basic Auth, POST body creds, query string creds."""
    findings = []

    # 1. HTTP Basic Auth headers only (skip Bearer / other schemes)
    for hdr in (req_headers or []):
        name_lower = hdr.get("name", "").lower()
        if name_lower in _SENSITIVE_HEADER_NAMES:
            value = hdr.get("value", "")
            if name_lower in ("authorization", "proxy-authorization"):
                if value.strip().lower().startswith("basic "):
                    decoded = _decode_basic_auth(value)
                    if decoded:
                        parts = decoded.split(":", 1)
                        findings.append({
                            "type": "basic_auth",
                            "header": hdr["name"],
                            "detail": f"{hdr['name']}: Basic ***",
                            "decoded": decoded,
                            "username": parts[0],
                            "password": parts[1] if len(parts) > 1 else "",
                        })

    # 2. Credential fields in POST request body (form data or JSON)
    body_creds = _extract_body_credentials(req_body)
    if body_creds.get("password") or body_creds.get("username"):
        detail_parts = []
        if body_creds.get("username"):
            detail_parts.append(f"username={body_creds['username']}")
        if body_creds.get("password"):
            detail_parts.append(f"password={body_creds['password']}")
        findings.append({
            "type": "body_credentials",
            "detail": f"POST body contains: {', '.join(detail_parts)}",
            "username": body_creds.get("username", ""),
            "password": body_creds.get("password", ""),
        })

    # 3. Credential fields in query string
    url = entry.get("url", "")
    query_creds = _extract_query_credentials(url)
    if query_creds.get("password") or query_creds.get("username"):
        detail_parts = []
        if query_creds.get("username"):
            detail_parts.append(f"username={query_creds['username']}")
        if query_creds.get("password"):
            detail_parts.append(f"password={query_creds['password']}")
        findings.append({
            "type": "query_credentials",
            "detail": f"Query string contains: {', '.join(detail_parts)}",
            "username": query_creds.get("username", ""),
            "password": query_creds.get("password", ""),
        })

    return findings


def _get_plaintext_traffic(minutes, sensitive_only=False):
    """Extract HTTP plaintext traffic — URLs, headers, request/response bodies."""
    all_requests = []
    scan_limit = 2000000 if sensitive_only else None
    for ev in iter_events(event_types={"http"}, minutes=minutes, max_lines=scan_limit):
        http = ev.get("http", {})
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        ts = ev.get("timestamp", "")

        method = http.get("http_method", "")
        hostname = http.get("hostname", "")
        url = http.get("url", "")
        status = http.get("status", 0)
        ua = http.get("http_user_agent", "")
        ct = http.get("http_content_type", "")
        length = http.get("length", 0)
        referer = http.get("http_refer", "")
        req_headers = http.get("request_headers", [])
        resp_headers = http.get("response_headers", [])
        req_body = http.get("http_request_body_printable", "")
        resp_body = http.get("http_response_body_printable", "")

        entry = {
            "timestamp": ts[:19].replace("T", " ") if ts else "",
            "src_ip": src,
            "dest_ip": dst,
            "src_internal": is_internal(src) if src else False,
            "method": method,
            "hostname": hostname,
            "url": url[:300],
            "status": status,
            "user_agent": ua[:150] if ua else "",
            "content_type": ct,
            "length": length,
            "referer": referer[:200] if referer else "",
        }
        if req_headers:
            entry["request_headers"] = req_headers[:20]
        if resp_headers:
            entry["response_headers"] = resp_headers[:20]
        if req_body:
            entry["request_body"] = req_body[:5000]
        if resp_body:
            entry["response_body"] = resp_body[:5000]

        findings = _detect_sensitive(entry, req_headers, resp_headers, req_body, resp_body)
        if findings:
            entry["sensitive"] = findings

        if sensitive_only and not findings:
            continue

        all_requests.append(entry)
        if len(all_requests) >= 500:
            break

    from collections import Counter
    hosts = Counter()
    methods = Counter()
    sensitive_count = 0
    for r in all_requests:
        hosts[r["hostname"]] += 1
        methods[r["method"]] += 1
        if r.get("sensitive"):
            sensitive_count += 1

    return {
        "requests": all_requests,
        "total": len(all_requests),
        "sensitive_count": sensitive_count,
        "by_host": dict(hosts.most_common(20)),
        "by_method": dict(methods.most_common()),
    }
