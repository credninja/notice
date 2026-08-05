"""
OSINT Threat Intelligence Feed aggregator — fetches free IOC feeds from
Abuse.ch (Feodo Tracker, URLhaus, ThreatFox, SSLBL) and correlates
them against live alerts from the detection engine.

All feeds are free, no API key required, updated frequently.
Uses only stdlib (urllib, csv, json, ssl, gzip).
"""

import csv
import gzip
import io
import json
import os
import re
import ssl
import threading
import time
import urllib.request
from datetime import datetime, timezone, timedelta

from db import get_db, now_ist_str

IST = timezone(timedelta(hours=5, minutes=30))

FEEDS = {
    "feodo": {
        "name": "Feodo Tracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv",
        "description": "Botnet C2 server IPs (Dridex, Emotet, TrickBot, QakBot)",
        "ioc_type": "ip",
        "refresh_minutes": 60,
        "source": "abuse.ch",
    },
    "sslbl": {
        "name": "SSL Blacklist",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "description": "IPs associated with malicious SSL certificates",
        "ioc_type": "ip",
        "refresh_minutes": 60,
        "source": "abuse.ch",
    },
    "urlhaus": {
        "name": "URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "description": "Recently reported malware distribution URLs",
        "ioc_type": "url",
        "refresh_minutes": 120,
        "source": "abuse.ch",
    },
    "threatfox": {
        "name": "ThreatFox IOCs",
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "description": "Recent IOCs (IPs, domains, URLs, hashes) from ThreatFox",
        "ioc_type": "mixed",
        "refresh_minutes": 120,
        "source": "abuse.ch",
    },
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS osint_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    threat_type TEXT DEFAULT '',
    malware TEXT DEFAULT '',
    confidence INTEGER DEFAULT 75,
    tags TEXT DEFAULT '',
    reference TEXT DEFAULT '',
    first_seen TEXT DEFAULT '',
    last_seen TEXT DEFAULT '',
    fetched_at TEXT NOT NULL,
    UNIQUE(feed, ioc_type, ioc_value)
);
CREATE INDEX IF NOT EXISTS idx_osint_ioc_value ON osint_iocs(ioc_value);
CREATE INDEX IF NOT EXISTS idx_osint_ioc_type ON osint_iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_osint_feed ON osint_iocs(feed);

CREATE TABLE IF NOT EXISTS osint_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id INTEGER,
    feed TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    matched_field TEXT NOT NULL,
    src_ip TEXT DEFAULT '',
    dest_ip TEXT DEFAULT '',
    alert_signature TEXT DEFAULT '',
    alert_sid INTEGER DEFAULT 0,
    event_type TEXT DEFAULT '',
    event_timestamp TEXT DEFAULT '',
    malware TEXT DEFAULT '',
    threat_type TEXT DEFAULT '',
    matched_at TEXT NOT NULL,
    UNIQUE(ioc_value, matched_field, src_ip, dest_ip, event_timestamp)
);
CREATE INDEX IF NOT EXISTS idx_osint_match_time ON osint_matches(matched_at);

CREATE TABLE IF NOT EXISTS osint_feed_status (
    feed TEXT PRIMARY KEY,
    last_fetch TEXT,
    ioc_count INTEGER DEFAULT 0,
    fetch_status TEXT DEFAULT 'pending',
    error_message TEXT DEFAULT '',
    fetch_duration_ms INTEGER DEFAULT 0
);
"""

_initialized = False
_lock = threading.Lock()


def _ensure_tables():
    global _initialized
    if _initialized:
        return
    with _lock:
        if _initialized:
            return
        conn = get_db()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()
        _initialized = True


def _http_get(url, timeout=30):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={
        "User-Agent": "NOTICE-ThreatIntel/1.0",
        "Accept-Encoding": "gzip",
    })
    resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
    data = resp.read()
    if resp.headers.get("Content-Encoding") == "gzip":
        data = gzip.decompress(data)
    return data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Feed parsers — each returns list of dicts with standard keys
# ---------------------------------------------------------------------------

def _parse_feodo(raw):
    iocs = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 4:
            continue
        first_seen = parts[0].strip('"').strip()
        ip = parts[1].strip('"').strip()
        port = parts[2].strip('"').strip()
        malware = parts[3].strip('"').strip()
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            continue
        iocs.append({
            "ioc_type": "ip",
            "ioc_value": ip,
            "threat_type": "botnet_c2",
            "malware": malware,
            "confidence": 90,
            "tags": f"c2,port:{port}",
            "first_seen": first_seen,
            "reference": f"https://feodotracker.abuse.ch/browse/host/{ip}/",
        })
    return iocs


def _parse_sslbl(raw):
    iocs = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        first_seen = parts[0].strip('"').strip()
        ip = parts[1].strip('"').strip()
        port = parts[2].strip('"').strip()
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            continue
        reason = parts[3].strip('"').strip() if len(parts) > 3 else ""
        iocs.append({
            "ioc_type": "ip",
            "ioc_value": ip,
            "threat_type": "malicious_ssl",
            "malware": reason,
            "confidence": 85,
            "tags": f"ssl,port:{port}",
            "first_seen": first_seen,
            "reference": f"https://sslbl.abuse.ch/intel/{ip}",
        })
    return iocs


def _parse_urlhaus(raw):
    iocs = []
    reader = csv.reader(io.StringIO(raw))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if len(row) < 8:
            continue
        url_id = row[0].strip('"')
        date_added = row[1].strip('"')
        url = row[2].strip('"')
        status = row[3].strip('"')
        threat = row[5].strip('"') if len(row) > 5 else ""
        tags = row[6].strip('"') if len(row) > 6 else ""

        domain = ""
        m = re.match(r"https?://([^/:]+)", url)
        if m:
            domain = m.group(1)

        malware_tag = ""
        if tags:
            for t in tags.split(","):
                t = t.strip()
                if t and t.lower() != "none":
                    malware_tag = t
                    break

        iocs.append({
            "ioc_type": "url",
            "ioc_value": url[:500],
            "threat_type": threat or "malware_distribution",
            "malware": malware_tag,
            "confidence": 80 if status == "online" else 60,
            "tags": tags,
            "first_seen": date_added,
            "reference": f"https://urlhaus.abuse.ch/url/{url_id}/",
        })
        if domain and re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            iocs.append({
                "ioc_type": "ip",
                "ioc_value": domain,
                "threat_type": "malware_hosting",
                "malware": malware_tag,
                "confidence": 75,
                "tags": "urlhaus," + tags,
                "first_seen": date_added,
                "reference": f"https://urlhaus.abuse.ch/url/{url_id}/",
            })
        elif domain:
            iocs.append({
                "ioc_type": "domain",
                "ioc_value": domain,
                "threat_type": "malware_hosting",
                "malware": malware_tag,
                "confidence": 75,
                "tags": "urlhaus," + tags,
                "first_seen": date_added,
                "reference": f"https://urlhaus.abuse.ch/url/{url_id}/",
            })
    return iocs


def _parse_threatfox(raw):
    """ThreatFox CSV columns:
    first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type,
    fk_malware, malware_alias, malware_printable, last_seen_utc,
    confidence_level, is_compromised, reference, tags, anonymous, reporter
    """
    iocs = []
    reader = csv.reader(io.StringIO(raw))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if len(row) < 10:
            continue
        first_seen = row[0].strip()
        ioc_value = row[2].strip()
        ioc_type_raw = row[3].strip()
        threat = row[4].strip()
        malware = row[7].strip()  # malware_printable
        confidence = row[9].strip()
        reference = row[11].strip() if len(row) > 11 else ""
        tags = row[12].strip() if len(row) > 12 else ""
        if reference == "None":
            reference = ""

        def _mk(itype, val, conf_str):
            c = int(conf_str) if conf_str.isdigit() else 75
            return {"ioc_type": itype, "ioc_value": val, "threat_type": threat,
                    "malware": malware, "confidence": c, "tags": tags,
                    "first_seen": first_seen, "reference": reference}

        if "ip:" in ioc_type_raw.lower():
            ip = ioc_value.split(":")[0] if ":" in ioc_value else ioc_value
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                continue
            iocs.append(_mk("ip", ip, confidence))
        elif "domain" in ioc_type_raw.lower():
            iocs.append(_mk("domain", ioc_value.lower(), confidence))
        elif "url" in ioc_type_raw.lower():
            iocs.append(_mk("url", ioc_value[:500], confidence))
            m = re.match(r"https?://([^/:]+)", ioc_value)
            if m:
                d = m.group(1)
                t = "ip" if re.match(r"^\d+\.\d+\.\d+\.\d+$", d) else "domain"
                iocs.append(_mk(t, d.lower() if t == "domain" else d, confidence))
        elif "hash" in ioc_type_raw.lower() or "sha256" in ioc_type_raw.lower() or "md5" in ioc_type_raw.lower():
            h_type = "hash_sha256" if len(ioc_value) == 64 else "hash_md5" if len(ioc_value) == 32 else "hash"
            iocs.append(_mk(h_type, ioc_value.lower(), confidence))
    return iocs


_PARSERS = {
    "feodo": _parse_feodo,
    "sslbl": _parse_sslbl,
    "urlhaus": _parse_urlhaus,
    "threatfox": _parse_threatfox,
}


# ---------------------------------------------------------------------------
# Feed fetch + store
# ---------------------------------------------------------------------------

def fetch_feed(feed_id):
    _ensure_tables()
    if feed_id not in FEEDS:
        return {"error": f"Unknown feed: {feed_id}"}

    feed = FEEDS[feed_id]
    conn = get_db()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO osint_feed_status (feed, fetch_status, last_fetch) VALUES (?, 'fetching', ?)",
            (feed_id, now_ist_str()),
        )
        conn.commit()
    except Exception:
        pass

    start = time.time()
    try:
        raw = _http_get(feed["url"], timeout=45)
        parser = _PARSERS.get(feed_id)
        if not parser:
            raise ValueError(f"No parser for {feed_id}")
        iocs = parser(raw)

        now = now_ist_str()
        inserted = 0
        for ioc in iocs:
            try:
                conn.execute(
                    """INSERT INTO osint_iocs (feed, ioc_type, ioc_value, threat_type,
                       malware, confidence, tags, reference, first_seen, last_seen, fetched_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(feed, ioc_type, ioc_value) DO UPDATE SET
                       threat_type=excluded.threat_type, malware=excluded.malware,
                       confidence=excluded.confidence, tags=excluded.tags,
                       last_seen=excluded.fetched_at, fetched_at=excluded.fetched_at""",
                    (feed_id, ioc["ioc_type"], ioc["ioc_value"], ioc.get("threat_type", ""),
                     ioc.get("malware", ""), ioc.get("confidence", 75),
                     ioc.get("tags", ""), ioc.get("reference", ""),
                     ioc.get("first_seen", ""), now, now),
                )
                inserted += 1
            except Exception:
                continue
        conn.commit()

        elapsed = int((time.time() - start) * 1000)
        total = conn.execute("SELECT COUNT(*) FROM osint_iocs WHERE feed=?", (feed_id,)).fetchone()[0]
        conn.execute(
            "INSERT OR REPLACE INTO osint_feed_status (feed, last_fetch, ioc_count, fetch_status, error_message, fetch_duration_ms) VALUES (?, ?, ?, 'ok', '', ?)",
            (feed_id, now, total, elapsed),
        )
        conn.commit()
        return {"ok": True, "feed": feed_id, "inserted": inserted, "total": total, "duration_ms": elapsed}

    except Exception as e:
        elapsed = int((time.time() - start) * 1000)
        conn.execute(
            "INSERT OR REPLACE INTO osint_feed_status (feed, last_fetch, fetch_status, error_message, fetch_duration_ms) VALUES (?, ?, 'error', ?, ?)",
            (feed_id, now_ist_str(), str(e)[:200], elapsed),
        )
        conn.commit()
        return {"error": str(e), "feed": feed_id}
    finally:
        conn.close()


def fetch_all_feeds():
    results = {}
    for fid in FEEDS:
        results[fid] = fetch_feed(fid)
    return results


# ---------------------------------------------------------------------------
# Correlation engine — match IOCs against recent alerts
# ---------------------------------------------------------------------------

def correlate(minutes=60):
    """Scan recent events and match against IOC database."""
    _ensure_tables()
    from eve_reader import iter_events, is_internal

    conn = get_db()
    try:
        ip_iocs = {}
        for row in conn.execute("SELECT id, feed, ioc_value, malware, threat_type FROM osint_iocs WHERE ioc_type='ip'"):
            ip_iocs[row["ioc_value"]] = dict(row)

        domain_iocs = {}
        for row in conn.execute("SELECT id, feed, ioc_value, malware, threat_type FROM osint_iocs WHERE ioc_type='domain'"):
            domain_iocs[row["ioc_value"]] = dict(row)
    except Exception:
        conn.close()
        return {"error": "Failed to load IOCs"}

    if not ip_iocs and not domain_iocs:
        conn.close()
        return {"matches": 0, "message": "No IOCs loaded — fetch feeds first"}

    now = now_ist_str()
    new_matches = 0

    for ev in iter_events(event_types={"alert", "dns", "tls", "http"}, minutes=minutes):
        etype = ev.get("event_type", "")
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        ts = ev.get("timestamp", "")
        alert = ev.get("alert", {})
        sig = alert.get("signature", "")
        sid = alert.get("signature_id", 0)

        matches_to_insert = []

        if src in ip_iocs and not is_internal(src):
            ioc = ip_iocs[src]
            matches_to_insert.append((ioc["id"], ioc["feed"], "ip", src, "src_ip",
                                      src, dst, sig, sid, etype, ts, ioc["malware"], ioc["threat_type"], now))

        if dst in ip_iocs and not is_internal(dst):
            ioc = ip_iocs[dst]
            matches_to_insert.append((ioc["id"], ioc["feed"], "ip", dst, "dest_ip",
                                      src, dst, sig, sid, etype, ts, ioc["malware"], ioc["threat_type"], now))

        if etype == "dns" and domain_iocs:
            query = ev.get("dns", {}).get("rrname", "").lower().rstrip(".")
            if query in domain_iocs:
                ioc = domain_iocs[query]
                matches_to_insert.append((ioc["id"], ioc["feed"], "domain", query, "dns_query",
                                          src, dst, "", 0, "dns", ts, ioc["malware"], ioc["threat_type"], now))

        if etype == "tls" and domain_iocs:
            sni = ev.get("tls", {}).get("sni", "").lower()
            if sni in domain_iocs:
                ioc = domain_iocs[sni]
                matches_to_insert.append((ioc["id"], ioc["feed"], "domain", sni, "tls_sni",
                                          src, dst, "", 0, "tls", ts, ioc["malware"], ioc["threat_type"], now))

        if etype == "http" and domain_iocs:
            host = ev.get("http", {}).get("hostname", "").lower()
            if host in domain_iocs:
                ioc = domain_iocs[host]
                matches_to_insert.append((ioc["id"], ioc["feed"], "domain", host, "http_host",
                                          src, dst, "", 0, "http", ts, ioc["malware"], ioc["threat_type"], now))

        for m in matches_to_insert:
            try:
                conn.execute(
                    """INSERT INTO osint_matches (ioc_id, feed, ioc_type, ioc_value, matched_field,
                       src_ip, dest_ip, alert_signature, alert_sid, event_type, event_timestamp,
                       malware, threat_type, matched_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(ioc_value, matched_field, src_ip, dest_ip, event_timestamp) DO NOTHING""",
                    m,
                )
                new_matches += 1
            except Exception:
                continue

    conn.commit()
    total_matches = conn.execute("SELECT COUNT(*) FROM osint_matches").fetchone()[0]
    conn.close()
    return {"new_matches": new_matches, "total_matches": total_matches}


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_feed_status():
    _ensure_tables()
    conn = get_db()
    result = {}
    for fid, fmeta in FEEDS.items():
        row = conn.execute("SELECT * FROM osint_feed_status WHERE feed=?", (fid,)).fetchone()
        result[fid] = {
            "name": fmeta["name"],
            "description": fmeta["description"],
            "source": fmeta["source"],
            "refresh_minutes": fmeta["refresh_minutes"],
            "status": dict(row) if row else {"feed": fid, "fetch_status": "pending", "ioc_count": 0},
        }
    conn.close()
    return result


def get_ioc_summary():
    _ensure_tables()
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM osint_iocs").fetchone()[0]
    by_type = {}
    for row in conn.execute("SELECT ioc_type, COUNT(*) as c FROM osint_iocs GROUP BY ioc_type"):
        by_type[row["ioc_type"]] = row["c"]
    by_feed = {}
    for row in conn.execute("SELECT feed, COUNT(*) as c FROM osint_iocs GROUP BY feed"):
        by_feed[row["feed"]] = row["c"]
    by_threat = {}
    for row in conn.execute("SELECT threat_type, COUNT(*) as c FROM osint_iocs GROUP BY threat_type ORDER BY c DESC LIMIT 10"):
        by_threat[row["threat_type"]] = row["c"]
    conn.close()
    return {"total": total, "by_type": by_type, "by_feed": by_feed, "by_threat": by_threat}


def get_matches(limit=200):
    _ensure_tables()
    conn = get_db()
    rows = conn.execute(
        """SELECT m.*, i.confidence, i.reference, i.tags
           FROM osint_matches m
           LEFT JOIN osint_iocs i ON m.ioc_id = i.id
           ORDER BY m.matched_at DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_match_stats():
    _ensure_tables()
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM osint_matches").fetchone()[0]
    by_feed = {}
    for row in conn.execute("SELECT feed, COUNT(*) as c FROM osint_matches GROUP BY feed"):
        by_feed[row["feed"]] = row["c"]
    by_type = {}
    for row in conn.execute("SELECT ioc_type, COUNT(*) as c FROM osint_matches GROUP BY ioc_type"):
        by_type[row["ioc_type"]] = row["c"]
    by_field = {}
    for row in conn.execute("SELECT matched_field, COUNT(*) as c FROM osint_matches GROUP BY matched_field"):
        by_field[row["matched_field"]] = row["c"]
    unique_ips = conn.execute(
        "SELECT COUNT(DISTINCT ioc_value) FROM osint_matches WHERE ioc_type='ip'"
    ).fetchone()[0]
    unique_domains = conn.execute(
        "SELECT COUNT(DISTINCT ioc_value) FROM osint_matches WHERE ioc_type='domain'"
    ).fetchone()[0]
    top_malware = []
    for row in conn.execute(
        "SELECT malware, COUNT(*) as c FROM osint_matches WHERE malware!='' GROUP BY malware ORDER BY c DESC LIMIT 10"
    ):
        top_malware.append({"malware": row["malware"], "count": row["c"]})

    recent = []
    for row in conn.execute(
        """SELECT m.*, i.confidence, i.reference
           FROM osint_matches m LEFT JOIN osint_iocs i ON m.ioc_id = i.id
           ORDER BY m.matched_at DESC LIMIT 20"""
    ):
        recent.append(dict(row))

    conn.close()
    return {
        "total_matches": total,
        "by_feed": by_feed,
        "by_type": by_type,
        "by_field": by_field,
        "unique_ips": unique_ips,
        "unique_domains": unique_domains,
        "top_malware": top_malware,
        "recent": recent,
    }


def search_ioc(query):
    _ensure_tables()
    conn = get_db()
    q = f"%{query}%"
    rows = conn.execute(
        """SELECT * FROM osint_iocs WHERE ioc_value LIKE ? OR malware LIKE ? OR tags LIKE ?
           ORDER BY confidence DESC LIMIT 100""",
        (q, q, q),
    ).fetchall()
    matches = conn.execute(
        """SELECT * FROM osint_matches WHERE ioc_value LIKE ? OR malware LIKE ?
           ORDER BY matched_at DESC LIMIT 50""",
        (q, q),
    ).fetchall()
    conn.close()
    return {"iocs": [dict(r) for r in rows], "matches": [dict(r) for r in matches]}


# ---------------------------------------------------------------------------
# Background refresh timer
# ---------------------------------------------------------------------------

def _refresh_loop():
    time.sleep(20)
    while True:
        try:
            conn = get_db()
            for fid, fmeta in FEEDS.items():
                row = conn.execute("SELECT last_fetch FROM osint_feed_status WHERE feed=?", (fid,)).fetchone()
                if row and row["last_fetch"]:
                    try:
                        last = datetime.strptime(row["last_fetch"], "%Y-%m-%d %H:%M:%S")
                        age_min = (datetime.now() - last).total_seconds() / 60
                        if age_min < fmeta["refresh_minutes"]:
                            continue
                    except Exception:
                        pass
                conn.close()
                fetch_feed(fid)
                conn = get_db()
            conn.close()
            correlate(minutes=60)
        except Exception:
            pass
        time.sleep(900)


def start_feed_worker():
    t = threading.Thread(target=_refresh_loop, daemon=True)
    t.start()
