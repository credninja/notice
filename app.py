#!/usr/bin/env python3
"""
NOTICE - Network Observation & Threat Intelligence Correlation Engine
Entry point: creates Bottle app, mounts routes, starts server.
"""

import os
import ssl
import sys
import threading
from socketserver import ThreadingMixIn
from wsgiref.simple_server import make_server, WSGIRequestHandler, WSGIServer
import bottle
from db import init_db, cache_gc


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Thread-per-request WSGI server — required so long-lived SSE streams
    (/api/events/stream) don't block other requests."""
    daemon_threads = True
    allow_reuse_address = True

# Load .env file if present
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())
from eve_reader import SUBNET, EVE_LOG
from auth import get_current_user, cleanup_expired_sessions
from routes import (
    graph, security, plaintext, investigate, anomalies, incidents, policies, assets,
    network_map, dashboard, drilldown, intel, asset_inventory, executive,
    monitoring, tor_intel, events_stream, user_rules, containment,
    threat_intel_api, auto_promote_api, insight_api,
)
from routes import (
    auth as auth_routes, notifications,
    case_mgmt, pcap, sigma as sigma_routes,
    dns_analytics, file_hash, attack_map, osint_feeds,
    session_analytics, knowledge_graph,
)

app = bottle.Bottle()

# Register all route modules
graph.register(app)
security.register(app)
plaintext.register(app)
investigate.register(app)
anomalies.register(app)
incidents.register(app)
policies.register(app)
assets.register(app)
network_map.register(app)
dashboard.register(app)
drilldown.register(app)
intel.register(app)
asset_inventory.register(app)
executive.register(app)
monitoring.register(app)
tor_intel.register(app)
events_stream.register(app)
user_rules.register(app)
containment.register(app)
threat_intel_api.register(app)
auto_promote_api.register(app)
insight_api.register(app)

# NOTICE v2 modules
auth_routes.register(app)
notifications.register(app)
case_mgmt.register(app)
pcap.register(app)
sigma_routes.register(app)
dns_analytics.register(app)
file_hash.register(app)
attack_map.register(app)
osint_feeds.register(app)
session_analytics.register(app)
knowledge_graph.register(app)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

AUTH_ENABLED = os.environ.get("AUTH_ENABLED", "true").lower() in ("true", "1", "yes")

PUBLIC_PATHS = frozenset([
    "/api/auth/login",
])
PUBLIC_PREFIXES = ("/static/",)

# ---------------------------------------------------------------------------
# RBAC — path/method-based role enforcement
# ---------------------------------------------------------------------------
# Writes on these prefixes are admin-only. Reads (GET) are still allowed for
# analysts (so they can view rules/policies etc.).
ADMIN_WRITE_PREFIXES = (
    "/api/auth/users",           # user management
    "/api/auth/audit",           # audit log
    "/api/policies",             # policy rules
    "/api/user-rules",           # detection rule mgmt
    "/api/auto-promote-rules",   # auto-promote rule mgmt
    "/api/notifications/rules",  # notification rules
    "/api/sigma",                # Sigma rule mgmt
    "/api/scheduled-reports",    # scheduled reports
    "/api/playbooks",            # playbook definitions (execution allowed via other paths)
    "/api/osint-feeds",          # OSINT feed config
)

# Everyone (viewer/analyst/admin) can hit these writes — self-service actions.
SELF_SERVICE_WRITES = frozenset([
    "/api/auth/logout",
    "/api/auth/password",       # change own password
    "/api/auth/api-keys",       # each user manages their own API keys
])


def _rbac_check(user, method, path):
    """Return (allowed, error_message).

    Rules:
      - admin  : full access
      - analyst: all reads; writes on non-admin prefixes; read-only for admin prefixes
      - viewer : reads only; writes only on self-service paths (logout/password/own api-keys)
    """
    role = (user or {}).get("role", "viewer")
    if role == "admin":
        return True, None
    if method == "GET":
        return True, None  # everyone can read

    # Non-GET (write) below

    # Self-service writes allowed for everyone
    for p in SELF_SERVICE_WRITES:
        if path == p or path.startswith(p + "/"):
            return True, None

    if role == "viewer":
        return False, "Viewer role is read-only"

    if role == "analyst":
        for prefix in ADMIN_WRITE_PREFIXES:
            if path.startswith(prefix):
                return False, f"Admin role required to modify {prefix}"
        return True, None

    return False, f"Unknown role: {role}"


@app.hook("before_request")
def auth_check():
    """Global auth middleware — blocks unauthenticated requests unless on a public path."""
    if not AUTH_ENABLED:
        return
    path = bottle.request.path
    if path == "/" or path in PUBLIC_PATHS:
        return
    for prefix in PUBLIC_PREFIXES:
        if path.startswith(prefix):
            return
    user = get_current_user(bottle.request)
    if not user:
        bottle.response.status = 401
        bottle.response.content_type = "application/json"
        bottle.abort(401, "Authentication required")
    bottle.request.user = user

    # CSRF protection: require custom header on state-changing requests
    # Skip CSRF check for API key authenticated requests (non-browser clients)
    if bottle.request.method in ("POST", "PUT", "DELETE"):
        if not bottle.request.headers.get("X-Requested-With") and not bottle.request.headers.get("X-API-Key"):
            bottle.response.status = 403
            bottle.response.content_type = "application/json"
            bottle.abort(403, "Missing X-Requested-With header")

    # RBAC enforcement (skip for the /api/auth/me lookup itself)
    if path != "/api/auth/me":
        allowed, reason = _rbac_check(user, bottle.request.method, path)
        if not allowed:
            bottle.response.status = 403
            bottle.response.content_type = "application/json"
            bottle.abort(403, reason or "Forbidden")


@app.hook("after_request")
def security_headers():
    bottle.response.headers["X-Content-Type-Options"] = "nosniff"
    bottle.response.headers["X-Frame-Options"] = "DENY"
    bottle.response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    bottle.response.headers["X-XSS-Protection"] = "1; mode=block"
    bottle.response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if AUTH_ENABLED:
        bottle.response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"


@app.route("/")
def index():
    return bottle.static_file("index.html", root=STATIC_DIR)


@app.route("/static/<filepath:path>")
def static_files(filepath):
    return bottle.static_file(filepath, root=STATIC_DIR)


@app.route("/api/pipeline/stats")
def pipeline_stats():
    from pipeline import get_pipeline_stats
    bottle.response.content_type = "application/json"
    import json
    return json.dumps(get_pipeline_stats())


HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 8080))
CERT_FILE = os.path.join(BASE_DIR, "certs", "cert.pem")
KEY_FILE = os.path.join(BASE_DIR, "certs", "key.pem")


class QuietHandler(WSGIRequestHandler):
    def log_request(self, code="-", size="-"):
        print(f"[{self.log_date_time_string()}] {self.requestline} {code}")


def _start_cache_gc_timer():
    """Run cache garbage collection every 5 minutes in a background thread."""
    def _gc_loop():
        while True:
            try:
                cache_gc()
            except Exception:
                pass
            import time
            time.sleep(300)
    t = threading.Thread(target=_gc_loop, daemon=True)
    t.start()


def _start_tor_refresh_timer():
    """Refresh the Tor exit-node list every 15 minutes.

    The list is small (~1500 IPs) and cheap to fetch. needs_refresh() guards
    against duplicate fetches when the loop wakes early (e.g. after suspend).
    """
    from analyzers.tor_list import refresh_tor_exits, needs_refresh
    def _loop():
        import time as _t
        # Initial fetch shortly after startup so the rest of the app comes up first
        _t.sleep(15)
        while True:
            try:
                if needs_refresh():
                    refresh_tor_exits()
            except Exception:
                pass
            # Wake once a minute and re-evaluate — needs_refresh()'s 15-min TTL
            # is the actual gate, so this is just a tight enough cadence to
            # honor the schedule without burning CPU.
            _t.sleep(60)
    t = threading.Thread(target=_loop, daemon=True)
    t.start()


def _start_auto_promote_sweeper():
    """Every 5 minutes in a background thread:
      1. Bulk-enqueue indicators from recent alerts onto the TI queue
         (catches up after restart since SSE only sees future alerts)
      2. Run the auto-promote evaluator
      3. Run the reinfection check
    """
    from analyzers.auto_promote import evaluate_and_promote
    from analyzers.insight import reinfection_check
    from analyzers.ti_queue import bulk_enrich_recent_alerts
    def _loop():
        import time as _t
        _t.sleep(30)  # let the app finish booting
        while True:
            try:
                bulk_enrich_recent_alerts(minutes=30, max_events=500)
            except Exception:
                pass
            try:
                evaluate_and_promote(window_minutes=10, dry_run=False)
            except Exception:
                pass
            try:
                reinfection_check()
            except Exception:
                pass
            _t.sleep(300)
    t = threading.Thread(target=_loop, daemon=True)
    t.start()


def _start_ti_queue_worker():
    """Drain the TI lookup queue continuously, calling VirusTotal +
    AbuseIPDB through their rate-limited clients."""
    from analyzers.ti_queue import start_worker
    start_worker()


def _start_snapshot_timer():
    """Capture daily snapshot every hour in a background thread."""
    from analyzers.snapshots import capture_daily_snapshot
    def _snap_loop():
        import time
        time.sleep(10)  # Initial delay
        while True:
            try:
                capture_daily_snapshot()
            except Exception:
                pass
            time.sleep(3600)  # Every hour
    t = threading.Thread(target=_snap_loop, daemon=True)
    t.start()


def _start_pipeline():
    """Start the persistent alert ingestion pipeline."""
    from pipeline import start_pipeline
    start_pipeline()


def _start_session_cleanup():
    """Clean expired sessions every 10 minutes."""
    def _loop():
        import time as _t
        _t.sleep(60)
        while True:
            try:
                cleanup_expired_sessions()
            except Exception:
                pass
            _t.sleep(600)
    t = threading.Thread(target=_loop, daemon=True)
    t.start()


def _start_pcap_cleanup():
    """Delete PCAP files older than 24 hours. Runs every hour."""
    def _loop():
        import time as _t
        import glob
        _t.sleep(120)
        log_dir = os.environ.get("SURICATA_LOG_DIR", "/var/log/suricata/")
        max_age = 86400  # 24 hours in seconds
        while True:
            try:
                now = _t.time()
                for fp in glob.glob(os.path.join(log_dir, "*.pcap*")):
                    if os.path.isfile(fp):
                        age = now - os.path.getmtime(fp)
                        if age > max_age:
                            os.remove(fp)
            except Exception:
                pass
            _t.sleep(3600)
    t = threading.Thread(target=_loop, daemon=True)
    t.start()


def _start_osint_feeds():
    """Start OSINT threat feed background worker."""
    from analyzers.osint_feeds import start_feed_worker
    start_feed_worker()


if __name__ == "__main__":
    init_db()
    _start_cache_gc_timer()
    _start_snapshot_timer()
    _start_tor_refresh_timer()
    _start_auto_promote_sweeper()
    _start_ti_queue_worker()
    _start_pipeline()
    _start_session_cleanup()
    _start_pcap_cleanup()
    _start_osint_feeds()
    use_https = os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)
    no_ssl = "--no-ssl" in sys.argv
    if no_ssl:
        use_https = False

    protocol = "https" if use_https else "http"
    print(f"NOTICE - Network Security Monitor")
    print(f"Monitoring subnet: {SUBNET}")
    print(f"Reading logs from: {EVE_LOG}")
    print(f"Starting server on {protocol}://{HOST}:{PORT}")
    if use_https:
        print(f"TLS cert: {CERT_FILE}")

    server = make_server(HOST, PORT, app, server_class=ThreadingWSGIServer, handler_class=QuietHandler)

    if use_https:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!DSS:!RC4")
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()
