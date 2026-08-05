"""
PCAP integration routes — browse, search, download, and index pcap files
captured by Suricata.

Suricata writes pcap files to /var/log/suricata/ (configurable via
SURICATA_LOG_DIR env). This module provides a REST API for analysts to
find relevant pcap captures for alert investigation.
"""

import glob
import os
from datetime import datetime, timedelta

import bottle
from bottle import request, response

from db import get_db, close_db

SURICATA_LOG_DIR = os.environ.get("SURICATA_LOG_DIR", "/var/log/suricata/")


def _pcap_file_info(filepath):
    """Return metadata dict for a pcap file on disk."""
    try:
        stat = os.stat(filepath)
        return {
            "filename": os.path.basename(filepath),
            "filepath": filepath,
            "size": stat.st_size,
            "modified_time": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "modified_ts": stat.st_mtime,
        }
    except OSError:
        return None


def _list_pcap_files():
    """Scan the Suricata log directory for pcap files."""
    results = []
    pattern = os.path.join(SURICATA_LOG_DIR, "*.pcap*")
    for filepath in glob.glob(pattern):
        if os.path.isfile(filepath):
            info = _pcap_file_info(filepath)
            if info:
                results.append(info)
    results.sort(key=lambda x: x.get("modified_ts", 0), reverse=True)
    return results


def register(app):

    # ─── LIST PCAP FILES ────────────────────────────────────────────────

    @app.get("/api/pcap/files")
    def list_pcap_files():
        files = _list_pcap_files()

        from_str = request.query.get("from", "").strip()
        to_str = request.query.get("to", "").strip()

        if from_str or to_str:
            try:
                from_ts = datetime.fromisoformat(from_str).timestamp() if from_str else 0
            except (ValueError, TypeError):
                from_ts = 0
            try:
                to_ts = datetime.fromisoformat(to_str).timestamp() if to_str else 9999999999
            except (ValueError, TypeError):
                to_ts = 9999999999

            files = [f for f in files if from_ts <= f.get("modified_ts", 0) <= to_ts]

        cleaned = []
        for f in files:
            cleaned.append({
                "filename": f["filename"],
                "size": f["size"],
                "modified": f["modified_time"],
            })
        return {"files": cleaned, "total": len(cleaned)}

    # ─── SEARCH PCAP FILES ──────────────────────────────────────────────

    @app.get("/api/pcap/search")
    def search_pcap():
        """Search for pcap files relevant to a given alert.

        Query params:
            src_ip          — source IP of the alert
            dest_ip         — destination IP of the alert
            timestamp       — alert timestamp (ISO format or YYYY-MM-DD HH:MM:SS)
            window_seconds  — time window around the alert (default 300 = 5 min)
        """
        src_ip = request.query.get("src_ip", "").strip()
        dest_ip = request.query.get("dest_ip", "").strip()
        timestamp = request.query.get("timestamp", "").strip()
        try:
            window_seconds = int(request.query.get("window_seconds", "300"))
        except (ValueError, TypeError):
            window_seconds = 300

        conn = get_db()
        try:
            results = []

            # Try the pcap_index table first (has time-range info)
            if timestamp:
                try:
                    ts = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
                except (ValueError, TypeError):
                    try:
                        ts = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S%z")
                    except (ValueError, TypeError):
                        try:
                            ts = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                        except (ValueError, TypeError):
                            try:
                                ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                            except (ValueError, TypeError):
                                ts = None

                if ts:
                    # Remove timezone info for comparison with naive datetimes in DB
                    ts_naive = ts.replace(tzinfo=None) if ts.tzinfo else ts
                    window_start = (ts_naive - timedelta(seconds=window_seconds)).strftime("%Y-%m-%d %H:%M:%S")
                    window_end = (ts_naive + timedelta(seconds=window_seconds)).strftime("%Y-%m-%d %H:%M:%S")

                    indexed = conn.execute(
                        """SELECT * FROM pcap_index
                           WHERE (start_time <= ? AND end_time >= ?)
                              OR (start_time >= ? AND start_time <= ?)
                              OR (end_time >= ? AND end_time <= ?)
                           ORDER BY start_time DESC""",
                        (window_end, window_start,
                         window_start, window_end,
                         window_start, window_end),
                    ).fetchall()

                    for row in indexed:
                        r = dict(row)
                        results.append({
                            "filename": r.get("filename", ""),
                            "filepath": r.get("filepath", ""),
                            "size": r.get("file_size", 0),
                            "start_time": r.get("start_time", ""),
                            "end_time": r.get("end_time", ""),
                            "packet_count": r.get("packet_count", 0),
                            "source": "index",
                        })

            # Fallback: list files from disk matching by timestamp proximity
            if not results:
                pcap_files = _list_pcap_files()
                if timestamp:
                    try:
                        ts = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
                    except (ValueError, TypeError):
                        try:
                            ts = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                        except (ValueError, TypeError):
                            try:
                                ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                            except (ValueError, TypeError):
                                ts = None

                    if ts:
                        ts_epoch = ts.timestamp() if ts.tzinfo else ts.replace().timestamp()
                        for f in pcap_files:
                            mtime = f.get("modified_ts", 0)
                            # A pcap file modified within the window could contain relevant packets
                            if abs(mtime - ts_epoch) <= window_seconds + 600:
                                results.append({
                                    "filename": f["filename"],
                                    "size": f["size"],
                                    "modified_time": f["modified_time"],
                                    "source": "filesystem",
                                })
                else:
                    # No timestamp filter — return all pcap files
                    for f in pcap_files:
                        results.append({
                            "filename": f["filename"],
                            "size": f["size"],
                            "modified_time": f["modified_time"],
                            "source": "filesystem",
                        })

            return {
                "results": results,
                "total": len(results),
                "query": {
                    "src_ip": src_ip,
                    "dest_ip": dest_ip,
                    "timestamp": timestamp,
                    "window_seconds": window_seconds,
                },
            }
        finally:
            close_db(conn)

    # ─── DOWNLOAD PCAP ──────────────────────────────────────────────────

    @app.get("/api/pcap/download/<filename>")
    def download_pcap(filename):
        """Serve a pcap file for download from the Suricata log directory."""
        # Sanitise: only the basename, no directory traversal
        safe_name = os.path.basename(filename)
        filepath = os.path.join(SURICATA_LOG_DIR, safe_name)
        if not os.path.isfile(filepath):
            response.status = 404
            return {"error": "PCAP file not found"}
        return bottle.static_file(safe_name, root=SURICATA_LOG_DIR, download=safe_name)

    # ─── INDEX PCAP FILES ───────────────────────────────────────────────

    @app.post("/api/pcap/index")
    def index_pcap():
        """Scan the Suricata log directory for pcap files and store metadata
        in the pcap_index table. Does not parse packet contents — only records
        file-level metadata (name, size, mtime)."""
        pcap_files = _list_pcap_files()

        conn = get_db()
        try:
            indexed = 0
            skipped = 0
            for f in pcap_files:
                filename = f["filename"]
                filepath = os.path.join(SURICATA_LOG_DIR, filename)

                # Check if already indexed (by filename)
                existing = conn.execute(
                    "SELECT id, file_size FROM pcap_index WHERE filename = ?",
                    (filename,),
                ).fetchone()

                if existing:
                    # Update if size changed (file is still being written)
                    if existing["file_size"] != f["size"]:
                        conn.execute(
                            "UPDATE pcap_index SET file_size = ?, indexed_at = datetime('now','localtime') "
                            "WHERE id = ?",
                            (f["size"], existing["id"]),
                        )
                        indexed += 1
                    else:
                        skipped += 1
                    continue

                # Use file mtime as approximate start_time; end_time approximated too
                start_time = f["modified_time"]
                end_time = f["modified_time"]

                conn.execute(
                    """INSERT INTO pcap_index
                       (filename, filepath, file_size, start_time, end_time)
                       VALUES (?, ?, ?, ?, ?)""",
                    (filename, filepath, f["size"], start_time, end_time),
                )
                indexed += 1

            conn.commit()
            return {
                "ok": True,
                "indexed": indexed,
                "skipped": skipped,
                "total_files": len(pcap_files),
            }
        finally:
            close_db(conn)

    # ─── PCAP STORAGE STATS ─────────────────────────────────────────────

    @app.get("/api/pcap/stats")
    def pcap_stats():
        """Return pcap storage statistics: total files, total size, oldest, newest."""
        pcap_files = _list_pcap_files()

        if not pcap_files:
            return {
                "total_files": 0,
                "total_size": 0,
                "total_size_mb": 0.0,
                "oldest": None,
                "newest": None,
            }

        total_size = sum(f["size"] for f in pcap_files)
        # Files are sorted newest-first by _list_pcap_files
        newest = pcap_files[0]["modified_time"] if pcap_files else None
        oldest = pcap_files[-1]["modified_time"] if pcap_files else None

        return {
            "total_files": len(pcap_files),
            "total_size": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "oldest": oldest,
            "newest": newest,
        }
