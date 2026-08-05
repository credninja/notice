"""
Database layer for NOTICE — supports SQLite (default) and PostgreSQL.

Set DATABASE_URL in .env to switch backends:
  DATABASE_URL=postgresql://user:pass@localhost:5432/notice
  (leave unset or empty for SQLite)
"""

import sqlite3
import json
import time
import os
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))

def now_ist():
    """Return current time in IST as a datetime object."""
    return datetime.now(IST)

def now_ist_str(fmt="%Y-%m-%d %H:%M:%S"):
    """Return current IST time as a formatted string."""
    return now_ist().strftime(fmt)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "notice.db")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_POSTGRES = DATABASE_URL.startswith("postgresql://")

_pg_pool = None

def _get_pg_connection():
    """Get a PostgreSQL connection (lazy-init connection pool)."""
    global _pg_pool
    import psycopg2
    import psycopg2.extras
    if _pg_pool is None:
        from psycopg2.pool import ThreadedConnectionPool
        _pg_pool = ThreadedConnectionPool(1, 10, DATABASE_URL)
    conn = _pg_pool.getconn()
    conn.autocommit = False
    return conn

def return_pg_connection(conn):
    if _pg_pool:
        _pg_pool.putconn(conn)


class PgRowFactory:
    """Make psycopg2 rows behave like sqlite3.Row (dict-like access)."""
    def __init__(self, cursor):
        self.cols = [d[0] for d in cursor.description] if cursor.description else []
    def __call__(self, cursor, row):
        return dict(zip(self.cols, row))

SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    value TEXT,
    created_at REAL,
    ttl_seconds INTEGER DEFAULT 300
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity TEXT CHECK(severity IN ('critical','high','medium','low')) DEFAULT 'medium',
    status TEXT CHECK(status IN ('open','investigating','resolved','closed')) DEFAULT 'open',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    resolved_at TEXT,
    assigned_to TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS incident_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    event_type TEXT,
    event_summary TEXT,
    event_data TEXT,
    src_ip TEXT,
    dest_ip TEXT,
    timestamp TEXT,
    added_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS incident_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS policy_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    rule_type TEXT NOT NULL,
    config TEXT DEFAULT '{}',
    severity TEXT DEFAULT 'medium',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS policy_violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER REFERENCES policy_rules(id) ON DELETE CASCADE,
    rule_name TEXT,
    src_ip TEXT,
    dest_ip TEXT,
    event_type TEXT,
    detail TEXT,
    timestamp TEXT,
    detected_at TEXT DEFAULT (datetime('now','localtime')),
    acknowledged INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    hostname TEXT DEFAULT '',
    owner TEXT DEFAULT '',
    department TEXT DEFAULT '',
    asset_type TEXT DEFAULT 'workstation',
    scope TEXT CHECK(scope IN ('internal','external')) DEFAULT 'internal',
    os TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    purdue_level TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS action_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    assigned_to TEXT DEFAULT '',
    assigned_role TEXT CHECK(assigned_role IN ('asset_custodian','network_admin','soc_analyst','management')) DEFAULT 'network_admin',
    priority TEXT CHECK(priority IN ('critical','high','medium','low')) DEFAULT 'medium',
    status TEXT CHECK(status IN ('open','in_progress','completed','overdue','cancelled')) DEFAULT 'open',
    source_type TEXT DEFAULT '',
    source_ip TEXT DEFAULT '',
    incident_id INTEGER,
    sla_hours INTEGER DEFAULT 24,
    due_at TEXT,
    completed_at TEXT,
    sla_breached INTEGER DEFAULT 0,
    breach_reason TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS geo_cache (
    ip TEXT PRIMARY KEY,
    country TEXT DEFAULT '',
    country_code TEXT DEFAULT '',
    city TEXT DEFAULT '',
    isp TEXT DEFAULT '',
    org TEXT DEFAULT '',
    looked_up_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS alert_verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    signature_id INTEGER,
    signature TEXT,
    src_ip TEXT,
    dest_ip TEXT,
    verdict TEXT CHECK(verdict IN ('true_positive','false_positive','false_negative','investigating')) DEFAULT 'investigating',
    analyst_notes TEXT DEFAULT '',
    marked_at TEXT DEFAULT (datetime('now','localtime')),
    UNIQUE(signature_id, src_ip, dest_ip)
);

CREATE TABLE IF NOT EXISTS missed_detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_ip TEXT NOT NULL,
    attacker_ip TEXT DEFAULT '',
    description TEXT NOT NULL,
    discovered_at TEXT DEFAULT (datetime('now','localtime')),
    severity TEXT CHECK(severity IN ('critical','high','medium','low')) DEFAULT 'high',
    incident_id INTEGER,
    notes TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_missed_detections_asset ON missed_detections(asset_ip);

CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_action_items_status ON action_items(status);
CREATE INDEX IF NOT EXISTS idx_action_items_due ON action_items(due_at);
CREATE INDEX IF NOT EXISTS idx_violations_rule ON policy_violations(rule_id);
CREATE INDEX IF NOT EXISTS idx_violations_src ON policy_violations(src_ip);
CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events(incident_id);
CREATE INDEX IF NOT EXISTS idx_alert_verdicts_sig ON alert_verdicts(signature_id);

CREATE TABLE IF NOT EXISTS daily_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_date TEXT NOT NULL UNIQUE,
    total_alerts INTEGER DEFAULT 0,
    critical_alerts INTEGER DEFAULT 0,
    high_alerts INTEGER DEFAULT 0,
    medium_alerts INTEGER DEFAULT 0,
    low_alerts INTEGER DEFAULT 0,
    total_flows INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    unique_internal_ips INTEGER DEFAULT 0,
    unique_external_ips INTEGER DEFAULT 0,
    policy_violations INTEGER DEFAULT 0,
    incidents_opened INTEGER DEFAULT 0,
    incidents_resolved INTEGER DEFAULT 0,
    tp_verdicts INTEGER DEFAULT 0,
    fp_verdicts INTEGER DEFAULT 0,
    health_score INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_snapshots_date ON daily_snapshots(snapshot_date);

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip TEXT PRIMARY KEY,
    abuse_score INTEGER DEFAULT 0,
    total_reports INTEGER DEFAULT 0,
    country_code TEXT DEFAULT '',
    isp TEXT DEFAULT '',
    domain TEXT DEFAULT '',
    is_tor INTEGER DEFAULT 0,
    last_reported TEXT DEFAULT '',
    checked_at TEXT DEFAULT (datetime('now','localtime'))
);

-- Tracks the first time each adversary IP was ever observed attacking us.
-- Populated incrementally by /api/monitoring/overview on each scan.
-- Used to classify adversaries as "new" (never seen before) vs returning.
-- Daily-refreshed snapshot of the official Tor exit-node list from
-- https://check.torproject.org/torbulkexitlist. Used by the Threat Insights
-- tab to count flows/alerts that touch Tor and surface a "Tor traffic" metric.
CREATE TABLE IF NOT EXISTS tor_exits (
    ip TEXT PRIMARY KEY,
    refreshed_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_tor_exits_refreshed ON tor_exits(refreshed_at);

CREATE TABLE IF NOT EXISTS adversary_seen (
    ip TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    total_attacks INTEGER DEFAULT 1,
    target_count INTEGER DEFAULT 0,
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_adversary_seen_first ON adversary_seen(first_seen);

CREATE TABLE IF NOT EXISTS user_rules (
    sid INTEGER PRIMARY KEY,
    msg TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'alert',
    protocol TEXT NOT NULL DEFAULT 'tcp',
    src_ip TEXT DEFAULT 'any',
    src_port TEXT DEFAULT 'any',
    direction TEXT DEFAULT '->',
    dst_ip TEXT DEFAULT 'any',
    dst_port TEXT DEFAULT 'any',
    content TEXT,
    classtype TEXT DEFAULT 'attempted-recon',
    severity INTEGER DEFAULT 2,
    asset_ip TEXT,
    raw_rule TEXT,
    enabled INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_user_rules_asset ON user_rules(asset_ip);

-- Incident response containment + workflow tables
CREATE TABLE IF NOT EXISTS blocklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    reason TEXT DEFAULT '',
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    created_by TEXT DEFAULT 'analyst',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    expires_at TEXT,
    active INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_blocklist_ip ON blocklist(ip);
CREATE INDEX IF NOT EXISTS idx_blocklist_active ON blocklist(active);

CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_ip TEXT NOT NULL,
    reason TEXT DEFAULT '',
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    created_by TEXT DEFAULT 'analyst',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    released_at TEXT,
    active INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_quarantine_ip ON quarantine(asset_ip);
CREATE INDEX IF NOT EXISTS idx_quarantine_active ON quarantine(active);

CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_value TEXT NOT NULL,
    ioc_type TEXT NOT NULL DEFAULT 'ip',          -- ip / signature_id / domain
    note TEXT DEFAULT '',
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    created_by TEXT DEFAULT 'analyst',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    expires_at TEXT,
    hits INTEGER DEFAULT 0,
    last_hit_at TEXT,
    active INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_watchlist_value ON watchlist(ioc_value);
CREATE INDEX IF NOT EXISTS idx_watchlist_active ON watchlist(active);

CREATE TABLE IF NOT EXISTS incident_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    ioc_type TEXT NOT NULL,                       -- src_ip / dest_ip / signature_id / signature / asset_ip
    ioc_value TEXT NOT NULL,
    is_primary INTEGER DEFAULT 0,                 -- 1 for seed IOCs (attacker, victim, sig); 0 for auxiliary
    frequency INTEGER DEFAULT 1,                  -- how many cluster events touched this IOC (used to rank auxiliary)
    created_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_incident_iocs_incident ON incident_iocs(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_iocs_value ON incident_iocs(ioc_value);

CREATE TABLE IF NOT EXISTS incident_phase_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    phase TEXT NOT NULL,                          -- triage/investigate/contain/eradicate/recover/closed
    started_at TEXT DEFAULT (datetime('now','localtime')),
    completed_at TEXT,
    completed_by TEXT,
    notes TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_incident_phase_log_incident ON incident_phase_log(incident_id);

-- Threat intelligence: domain + URL reputation (VirusTotal)
CREATE TABLE IF NOT EXISTS domain_reputation (
    domain TEXT PRIMARY KEY,
    vt_score INTEGER DEFAULT 0,                -- 0-100 (malicious_count / total_engines * 100)
    vt_malicious INTEGER DEFAULT 0,            -- raw count of engines marking malicious
    vt_suspicious INTEGER DEFAULT 0,
    vt_total_engines INTEGER DEFAULT 0,
    vt_categories TEXT DEFAULT '',             -- comma-joined category list
    classification TEXT DEFAULT 'unknown',     -- malicious / suspicious / benign / unknown
    last_checked TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS url_reputation (
    url TEXT PRIMARY KEY,
    vt_score INTEGER DEFAULT 0,
    vt_malicious INTEGER DEFAULT 0,
    vt_suspicious INTEGER DEFAULT 0,
    vt_total_engines INTEGER DEFAULT 0,
    classification TEXT DEFAULT 'unknown',
    last_checked TEXT DEFAULT (datetime('now','localtime'))
);

-- Auto-promote engine: declarative rules + decision audit trail
CREATE TABLE IF NOT EXISTS auto_promote_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    criterion TEXT NOT NULL,                   -- ti_malicious / alert_burst / killchain_phase / ti_burst
    threshold REAL DEFAULT 0,                  -- numeric threshold for the criterion
    window_minutes INTEGER DEFAULT 10,         -- evaluation window for burst-style rules
    severity_floor TEXT DEFAULT 'medium',      -- minimum severity to trigger
    enabled INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS auto_promote_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER REFERENCES auto_promote_rules(id) ON DELETE SET NULL,
    rule_name TEXT,
    signature_id INTEGER,
    src_ip TEXT,
    dest_ip TEXT,
    decision TEXT NOT NULL,                    -- promoted / skipped / failed
    reason TEXT,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_apd_created ON auto_promote_decisions(created_at);

-- Per-asset compromise state (drives the post-compromise tracker UI)
CREATE TABLE IF NOT EXISTS asset_compromise_state (
    asset_ip TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'active',     -- active / contained / resolved / reinfected / suspected
    since TEXT DEFAULT (datetime('now','localtime')),
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    last_indicator TEXT DEFAULT '',
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_acs_status ON asset_compromise_state(status);

-- TI lookup queue: every alert's flagged IPs/domains/URLs go in here so a
-- background worker can enrich them via VirusTotal + AbuseIPDB at a rate
-- that respects each provider's quota. UNIQUE(indicator_type, indicator_value)
-- means re-queueing the same IOC just bumps priority; we don't waste lookups.
CREATE TABLE IF NOT EXISTS ti_lookup_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_type TEXT NOT NULL,             -- ip / domain / url
    indicator_value TEXT NOT NULL,
    priority INTEGER DEFAULT 5,               -- lower = processed sooner (1..10)
    status TEXT NOT NULL DEFAULT 'pending',   -- pending / done / failed
    source TEXT DEFAULT 'alert',              -- alert / sse / manual / sweeper
    queued_at TEXT DEFAULT (datetime('now','localtime')),
    last_attempt_at TEXT,
    attempts INTEGER DEFAULT 0,
    last_error TEXT DEFAULT '',
    UNIQUE(indicator_type, indicator_value)
);
CREATE INDEX IF NOT EXISTS idx_tilq_status_prio ON ti_lookup_queue(status, priority, queued_at);
CREATE INDEX IF NOT EXISTS idx_tilq_value ON ti_lookup_queue(indicator_value);

-- =====================================================================
-- NOTICE v2 Tables — Auth, Pipeline, Alerting, Case Mgmt, PCAP, Sigma
-- =====================================================================

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    email TEXT DEFAULT '',
    full_name TEXT DEFAULT '',
    role TEXT CHECK(role IN ('admin','analyst','viewer')) DEFAULT 'analyst',
    active INTEGER DEFAULT 1,
    last_login TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    ip_address TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    target_type TEXT DEFAULT '',
    target_id TEXT DEFAULT '',
    detail TEXT DEFAULT '',
    ip_address TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

CREATE TABLE IF NOT EXISTS pipeline_state (
    source TEXT PRIMARY KEY,
    byte_offset INTEGER DEFAULT 0,
    inode INTEGER DEFAULT 0,
    last_event_time TEXT,
    events_processed INTEGER DEFAULT 0,
    alerts_ingested INTEGER DEFAULT 0,
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS ingested_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    signature_id INTEGER,
    signature TEXT,
    severity INTEGER,
    category TEXT DEFAULT '',
    src_ip TEXT,
    src_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    proto TEXT DEFAULT '',
    app_proto TEXT DEFAULT '',
    payload_printable TEXT DEFAULT '',
    pcap_filename TEXT DEFAULT '',
    event_json TEXT,
    notified INTEGER DEFAULT 0,
    ingested_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_ialerts_ts ON ingested_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_ialerts_sig ON ingested_alerts(signature_id);
CREATE INDEX IF NOT EXISTS idx_ialerts_src ON ingested_alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_ialerts_dst ON ingested_alerts(dest_ip);
CREATE INDEX IF NOT EXISTS idx_ialerts_sev ON ingested_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_ialerts_notified ON ingested_alerts(notified);

CREATE TABLE IF NOT EXISTS notification_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    condition_type TEXT NOT NULL,
    condition_value TEXT DEFAULT '',
    recipients TEXT NOT NULL,
    cooldown_minutes INTEGER DEFAULT 30,
    last_fired_at TEXT,
    enabled INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS notification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER REFERENCES notification_rules(id) ON DELETE SET NULL,
    rule_name TEXT DEFAULT '',
    recipient TEXT NOT NULL,
    subject TEXT NOT NULL,
    body_preview TEXT DEFAULT '',
    status TEXT CHECK(status IN ('sent','failed','queued')) DEFAULT 'queued',
    error_message TEXT DEFAULT '',
    sent_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_notlog_rule ON notification_log(rule_id);
CREATE INDEX IF NOT EXISTS idx_notlog_status ON notification_log(status);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,
    file_size INTEGER DEFAULT 0,
    content_type TEXT DEFAULT '',
    description TEXT DEFAULT '',
    hash_sha256 TEXT DEFAULT '',
    uploaded_by TEXT DEFAULT '',
    uploaded_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id);

CREATE TABLE IF NOT EXISTS incident_auto_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    priority INTEGER DEFAULT 100,
    match_signature TEXT DEFAULT '',
    match_sid TEXT DEFAULT '',
    match_severity TEXT DEFAULT '',
    match_src_subnet TEXT DEFAULT '',
    match_dst_subnet TEXT DEFAULT '',
    match_title_pattern TEXT DEFAULT '',
    action TEXT NOT NULL DEFAULT 'close_fp',
    auto_classification TEXT DEFAULT '',
    auto_certin_category TEXT DEFAULT '',
    auto_impact TEXT DEFAULT '',
    auto_mitre_tactic TEXT DEFAULT '',
    auto_mitre_technique TEXT DEFAULT '',
    auto_summary TEXT DEFAULT '',
    created_by TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS sigma_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    sigma_id TEXT DEFAULT '',
    description TEXT DEFAULT '',
    level TEXT DEFAULT 'medium',
    status TEXT DEFAULT 'active',
    author TEXT DEFAULT '',
    logsource TEXT DEFAULT '',
    yaml_content TEXT NOT NULL,
    suricata_rule TEXT DEFAULT '',
    conversion_log TEXT DEFAULT '',
    sid_assigned INTEGER,
    enabled INTEGER DEFAULT 1,
    imported_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_sigma_level ON sigma_rules(level);
CREATE INDEX IF NOT EXISTS idx_sigma_enabled ON sigma_rules(enabled);

-- In-app notifications (assignment, mentions, escalations, etc.)
CREATE TABLE IF NOT EXISTS user_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'assignment',
    incident_id INTEGER,
    title TEXT DEFAULT '',
    message TEXT DEFAULT '',
    is_read INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    read_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_notif_user_read ON user_notifications(username, is_read, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notif_incident ON user_notifications(incident_id);

CREATE TABLE IF NOT EXISTS pcap_index (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,
    file_size INTEGER DEFAULT 0,
    start_time TEXT,
    end_time TEXT,
    packet_count INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 0,
    indexed_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_pcap_time ON pcap_index(start_time, end_time);
CREATE INDEX IF NOT EXISTS idx_pcap_file ON pcap_index(filename);

CREATE TABLE IF NOT EXISTS playbooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    category TEXT DEFAULT 'general',
    severity TEXT DEFAULT 'medium',
    trigger_type TEXT DEFAULT 'manual',
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS playbook_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id INTEGER NOT NULL,
    step_order INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    action_type TEXT DEFAULT 'manual',
    auto_action TEXT DEFAULT '',
    FOREIGN KEY (playbook_id) REFERENCES playbooks(id)
);

CREATE TABLE IF NOT EXISTS playbook_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id INTEGER NOT NULL,
    incident_id INTEGER,
    started_at TEXT DEFAULT (datetime('now','localtime')),
    completed_at TEXT,
    status TEXT DEFAULT 'pending',
    executed_by TEXT DEFAULT 'system',
    step_statuses TEXT DEFAULT '[]',
    FOREIGN KEY (playbook_id) REFERENCES playbooks(id)
);
CREATE INDEX IF NOT EXISTS idx_pb_exec_playbook ON playbook_executions(playbook_id);
"""

# Placeholder examples. Users should replace these with their own network's assets
# from the Admin → Assets UI. IPs kept in RFC1918 private range.
DEFAULT_ASSETS = [
    {"ip": "10.0.0.10", "owner": "Analyst-1", "asset_type": "workstation", "notes": "Sample workstation"},
    {"ip": "10.0.0.11", "owner": "Analyst-2", "asset_type": "workstation", "notes": "Sample workstation"},
    {"ip": "10.0.0.12", "owner": "Server-EDR", "asset_type": "server", "notes": "Sample EDR/security server"},
]

DEFAULT_EXTERNAL_ASSETS = [
    {"ip": "185.125.190.101", "hostname": "Ubuntu Connectivity Check", "asset_type": "service", "notes": "connectivity-check.ubuntu.com"},
]

DEFAULT_POLICIES = [
    {
        "name": "No Plaintext HTTP",
        "description": "Flag HTTP traffic on port 80 (unencrypted)",
        "rule_type": "plaintext_protocol",
        "config": json.dumps({"event_types": ["http"], "ports": [80]}),
        "severity": "high",
    },
    {
        "name": "No FTP",
        "description": "Flag FTP traffic (credentials transmitted in plaintext)",
        "rule_type": "plaintext_protocol",
        "config": json.dumps({"event_types": ["ftp"]}),
        "severity": "critical",
    },
    {
        "name": "No Plaintext SMTP",
        "description": "Flag unencrypted SMTP traffic",
        "rule_type": "plaintext_protocol",
        "config": json.dumps({"event_types": ["smtp"]}),
        "severity": "high",
    },
    {
        "name": "Weak SNMP Community",
        "description": "Flag SNMP with weak/default community strings",
        "rule_type": "weak_snmp",
        "config": json.dumps({"blocked_communities": ["public", "private", "iiit123"]}),
        "severity": "high",
    },
    {
        "name": "No BitTorrent",
        "description": "Flag BitTorrent DHT traffic (unauthorized P2P)",
        "rule_type": "unauthorized_service",
        "config": json.dumps({"event_types": ["bittorrent_dht"]}),
        "severity": "medium",
    },
    {
        "name": "No Deprecated TLS",
        "description": "Flag TLS v1.0 and v1.1 (deprecated, insecure)",
        "rule_type": "deprecated_tls",
        "config": json.dumps({"blocked_versions": ["TLSv1", "TLS 1.0", "TLS 1.1"]}),
        "severity": "medium",
    },
]


def get_db():
    """Return a DB connection — SQLite by default, PostgreSQL if DATABASE_URL is set."""
    if USE_POSTGRES:
        conn = _get_pg_connection()
        return conn
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def close_db(conn):
    """Close/return a DB connection."""
    if USE_POSTGRES:
        return_pg_connection(conn)
    else:
        conn.close()


def safe_update(table, allowed_fields, data, where_clause, where_params, extra_sets=None):
    """
    Build and execute a safe UPDATE statement.

    Args:
        table: Table name (must be a known constant, not user input)
        allowed_fields: frozenset of column names that may be updated
        data: dict of field -> value from user input
        where_clause: SQL WHERE clause, e.g. "WHERE id = ?"
        where_params: list of params for the WHERE clause
        extra_sets: list of raw SQL SET fragments (e.g. ["updated_at = datetime('now','localtime')"])

    Returns:
        True if any update was made, False otherwise
    """
    updates = []
    params = []
    for field, value in data.items():
        if field in allowed_fields:
            updates.append(f"{field} = ?")
            params.append(value)
    if extra_sets:
        updates.extend(extra_sets)
    if not updates:
        return False
    params.extend(where_params)
    conn = get_db()
    conn.execute(f"UPDATE {table} SET {', '.join(updates)} {where_clause}", params)
    conn.commit()
    return True


def cache_gc():
    """Delete expired cache entries."""
    conn = get_db()
    conn.execute("DELETE FROM cache WHERE (? - created_at) > ttl_seconds", (time.time(),))
    conn.commit()


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    # Migrations for existing DBs
    asset_cols = [r[1] for r in conn.execute("PRAGMA table_info(assets)").fetchall()]
    if "scope" not in asset_cols:
        conn.execute("ALTER TABLE assets ADD COLUMN scope TEXT DEFAULT 'internal'")
    if "business_critical" not in asset_cols:
        conn.execute("ALTER TABLE assets ADD COLUMN business_critical INTEGER DEFAULT 0")
    if "purdue_level" not in asset_cols:
        conn.execute("ALTER TABLE assets ADD COLUMN purdue_level TEXT DEFAULT ''")
    inc_cols = [r[1] for r in conn.execute("PRAGMA table_info(incidents)").fetchall()]
    if "verdict" not in inc_cols:
        conn.execute("ALTER TABLE incidents ADD COLUMN verdict TEXT DEFAULT 'investigating'")
    # IR-lifecycle columns — added together so older DBs migrate cleanly
    _ir_columns = [
        ("phase",              "TEXT DEFAULT 'triage'"),
        ("phase_started_at",   "TEXT"),
        ("attacker_ip",        "TEXT"),
        ("victim_ip",          "TEXT"),
        ("signature_id",       "INTEGER"),
        ("signature",          "TEXT"),
        ("rca_root_cause",     "TEXT DEFAULT ''"),
        ("rca_lessons_learned","TEXT DEFAULT ''"),
        ("rca_actions_taken",  "TEXT DEFAULT ''"),
    ]
    for col, decl in _ir_columns:
        if col not in inc_cols:
            conn.execute(f"ALTER TABLE incidents ADD COLUMN {col} {decl}")
    _closure_columns = [
        ("closure_classification", "TEXT DEFAULT ''"),
        ("closure_certin_category", "TEXT DEFAULT ''"),
        ("closure_impact",         "TEXT DEFAULT ''"),
        ("closure_mitre_tactic",   "TEXT DEFAULT ''"),
        ("closure_mitre_technique","TEXT DEFAULT ''"),
        ("closure_summary",        "TEXT DEFAULT ''"),
        ("closed_by",             "TEXT DEFAULT ''"),
    ]
    for col, decl in _closure_columns:
        if col not in inc_cols:
            conn.execute(f"ALTER TABLE incidents ADD COLUMN {col} {decl}")
    # Migration for incident_iocs: add is_primary + frequency columns if missing
    try:
        ioc_cols = [r[1] for r in conn.execute("PRAGMA table_info(incident_iocs)").fetchall()]
        if ioc_cols:
            if "is_primary" not in ioc_cols:
                conn.execute("ALTER TABLE incident_iocs ADD COLUMN is_primary INTEGER DEFAULT 0")
            if "frequency" not in ioc_cols:
                conn.execute("ALTER TABLE incident_iocs ADD COLUMN frequency INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass
    # Migration for incident_events: add sid column so we don't have to parse it
    # out of event_summary every time we need to look up the firing rule.
    try:
        ev_cols = [r[1] for r in conn.execute("PRAGMA table_info(incident_events)").fetchall()]
        if ev_cols and "sid" not in ev_cols:
            conn.execute("ALTER TABLE incident_events ADD COLUMN sid INTEGER")
    except sqlite3.OperationalError:
        pass
    # Migration for ip_reputation: add VirusTotal columns alongside AbuseIPDB
    try:
        ipr_cols = [r[1] for r in conn.execute("PRAGMA table_info(ip_reputation)").fetchall()]
        for col, decl in [
            ("vt_score", "INTEGER DEFAULT 0"),
            ("vt_malicious", "INTEGER DEFAULT 0"),
            ("vt_suspicious", "INTEGER DEFAULT 0"),
            ("vt_total_engines", "INTEGER DEFAULT 0"),
            ("vt_categories", "TEXT DEFAULT ''"),
            ("classification", "TEXT DEFAULT 'unknown'"),
        ]:
            if col not in ipr_cols:
                conn.execute(f"ALTER TABLE ip_reputation ADD COLUMN {col} {decl}")
    except sqlite3.OperationalError:
        pass
    # Seed auto-promote rules if empty (default criteria — analyst can edit later)
    try:
        n = conn.execute("SELECT COUNT(*) FROM auto_promote_rules").fetchone()[0]
        if n == 0:
            for name, criterion, threshold, win, sev in [
                ("TI Malicious",       "ti_malicious",     80,   10, "medium"),
                ("Alert Burst",        "alert_burst",       5,   10, "medium"),
                ("Kill-Chain Deep",    "killchain_phase",   4,   60, "medium"),
                ("Critical Asset Hit", "critical_asset",    1,   10, "high"),
            ]:
                conn.execute(
                    "INSERT INTO auto_promote_rules (name, criterion, threshold, window_minutes, severity_floor) "
                    "VALUES (?,?,?,?,?)",
                    (name, criterion, threshold, win, sev),
                )
    except sqlite3.OperationalError:
        pass
    # Persist all migrations + seeds before the alert_verdicts probe below —
    # that block uses BEGIN/ROLLBACK which would otherwise discard our work.
    conn.commit()
    # Migrate alert_verdicts to allow 'false_negative' (SQLite CHECK constraint requires table rebuild)
    try:
        # Check if the new verdict value is supported by attempting a transient insert
        conn.execute("BEGIN")
        conn.execute("INSERT INTO alert_verdicts (signature_id, src_ip, dest_ip, verdict) VALUES (-99999999, 'test', 'test', 'false_negative')")
        conn.execute("ROLLBACK")
    except sqlite3.IntegrityError:
        # Old schema doesn't allow false_negative - rebuild the table
        conn.execute("ROLLBACK")
        try:
            conn.execute("ALTER TABLE alert_verdicts RENAME TO alert_verdicts_old")
            conn.execute("""
                CREATE TABLE alert_verdicts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    signature_id INTEGER,
                    signature TEXT,
                    src_ip TEXT,
                    dest_ip TEXT,
                    verdict TEXT CHECK(verdict IN ('true_positive','false_positive','false_negative','investigating')) DEFAULT 'investigating',
                    analyst_notes TEXT DEFAULT '',
                    marked_at TEXT DEFAULT (datetime('now','localtime')),
                    UNIQUE(signature_id, src_ip, dest_ip)
                )
            """)
            conn.execute("INSERT INTO alert_verdicts SELECT * FROM alert_verdicts_old")
            conn.execute("DROP TABLE alert_verdicts_old")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_verdicts_sig ON alert_verdicts(signature_id)")
        except sqlite3.OperationalError:
            pass
    except sqlite3.OperationalError:
        # Table doesn't exist yet, schema will create it
        try: conn.execute("ROLLBACK")
        except: pass
    # Seed default policies if table is empty
    count = conn.execute("SELECT COUNT(*) FROM policy_rules").fetchone()[0]
    if count == 0:
        for p in DEFAULT_POLICIES:
            conn.execute(
                "INSERT INTO policy_rules (name, description, rule_type, config, severity) VALUES (?, ?, ?, ?, ?)",
                (p["name"], p["description"], p["rule_type"], p["config"], p["severity"]),
            )
    # Seed default assets if table is empty
    asset_count = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    if asset_count == 0:
        for a in DEFAULT_ASSETS:
            conn.execute(
                "INSERT INTO assets (ip, owner, asset_type, scope, notes) VALUES (?, ?, ?, 'internal', ?)",
                (a["ip"], a.get("owner", ""), a.get("asset_type", "workstation"), a.get("notes", "")),
            )
        for a in DEFAULT_EXTERNAL_ASSETS:
            conn.execute(
                "INSERT INTO assets (ip, hostname, asset_type, scope, notes) VALUES (?, ?, ?, 'external', ?)",
                (a["ip"], a.get("hostname", ""), a.get("asset_type", "server"), a.get("notes", "")),
            )
    # Seed default admin user if users table is empty
    user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if user_count == 0:
        import hashlib, secrets as _sec
        _salt = _sec.token_hex(32)
        _hash = hashlib.pbkdf2_hmac("sha256", b"admin", _salt.encode(), 310000).hex()
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, email, full_name, role) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("admin", _hash, _salt, "", "Administrator", "admin"),
        )
    # Seed default playbooks if empty
    try:
        pb_count = conn.execute("SELECT COUNT(*) FROM playbooks").fetchone()[0]
        if pb_count == 0:
            _now = now_ist_str()
            _playbooks = [
                ("Malware Detected", "Response workflow for malware alerts", "malware", "critical", "alert_trigger",
                 [("Isolate Host", "Quarantine the affected system from the network", "manual", ""),
                  ("Collect Evidence", "Capture memory dump, disk image, and relevant logs", "manual", ""),
                  ("Identify Malware", "Analyze file hash, check VT/sandbox results", "manual", ""),
                  ("Eradicate Threat", "Remove malware artifacts and persistence mechanisms", "manual", ""),
                  ("Restore System", "Rebuild or restore from clean backup", "manual", ""),
                  ("Notify Stakeholders", "Send incident report to management and affected users", "manual", "")]),
                ("Phishing Reported", "Response for reported phishing emails", "phishing", "high", "manual",
                 [("Verify Report", "Confirm the email is malicious — check headers, links, attachments", "manual", ""),
                  ("Block Indicators", "Add sender, domains, and URLs to blocklist", "manual", ""),
                  ("Search for Recipients", "Identify all users who received the phishing email", "manual", ""),
                  ("Notify Affected Users", "Alert recipients not to interact with the email", "manual", ""),
                  ("Remove Emails", "Delete phishing emails from all mailboxes", "manual", ""),
                  ("Document & Close", "Record findings and close the case", "manual", "")]),
                ("Unauthorized Access", "Response for unauthorized access attempts", "access", "high", "alert_trigger",
                 [("Verify Alert", "Confirm the access attempt is unauthorized, not a false positive", "manual", ""),
                  ("Block Attacker", "Block source IP at firewall/WAF", "manual", ""),
                  ("Assess Impact", "Determine if the attacker gained access — check logs for success", "manual", ""),
                  ("Reset Credentials", "Force password reset for targeted accounts", "manual", ""),
                  ("Harden Defenses", "Update rules, patch vulnerabilities exploited", "manual", ""),
                  ("Post-Incident Review", "Document timeline, root cause, and lessons learned", "manual", "")]),
                ("Data Exfiltration", "Response for suspected data exfiltration", "exfiltration", "critical", "alert_trigger",
                 [("Confirm Exfiltration", "Verify data is actually leaving the network abnormally", "manual", ""),
                  ("Block Channel", "Cut off the exfiltration path (DNS tunnel, C2, HTTP upload)", "manual", ""),
                  ("Identify Data Scope", "Determine what data was or could have been exfiltrated", "manual", ""),
                  ("Preserve Evidence", "Capture network captures, logs, and forensic images", "manual", ""),
                  ("Legal & Compliance", "Notify legal team if PII/sensitive data involved", "manual", ""),
                  ("Remediate & Report", "Patch the vector, document timeline, file incident report", "manual", "")]),
            ]
            for name, desc, cat, sev, trig, steps in _playbooks:
                cur = conn.execute(
                    "INSERT INTO playbooks (name, description, category, severity, trigger_type, created_at, updated_at, status) VALUES (?,?,?,?,?,?,?,?)",
                    (name, desc, cat, sev, trig, _now, _now, "active"))
                pid = cur.lastrowid
                for i, (st, sd, at, aa) in enumerate(steps):
                    conn.execute(
                        "INSERT INTO playbook_steps (playbook_id, step_order, title, description, action_type, auto_action) VALUES (?,?,?,?,?,?)",
                        (pid, i+1, st, sd, at, aa))
    except Exception:
        pass
    conn.commit()
    conn.close()


def cache_get(key):
    conn = get_db()
    row = conn.execute("SELECT value, created_at, ttl_seconds FROM cache WHERE key = ?", (key,)).fetchone()
    conn.close()
    if row and (time.time() - row["created_at"]) < row["ttl_seconds"]:
        return json.loads(row["value"])
    return None


def cache_set(key, value, ttl=300):
    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO cache (key, value, created_at, ttl_seconds) VALUES (?, ?, ?, ?)",
        (key, json.dumps(value), time.time(), ttl),
    )
    conn.commit()
    conn.close()
