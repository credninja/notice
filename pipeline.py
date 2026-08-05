"""
Persistent EVE JSON ingestion pipeline for NOTICE.

Continuously tails /var/log/suricata/eve.json (or EVE_LOG), parses each
line, inserts alert events into the ingested_alerts table, and maintains
a byte-offset bookmark in pipeline_state so restarts resume where they
left off.  Log rotation (inode change) is detected automatically.

Usage:
    from pipeline import start_pipeline, get_pipeline_stats
    start_pipeline()          # fire-and-forget daemon thread
    stats = get_pipeline_stats()
"""

import json
import os
import time
import threading

from db import get_db, close_db
from eve_reader import EVE_LOG

_pipeline_instance = None
_lock = threading.Lock()

SOURCE_KEY = "eve.json"


class AlertPipeline:
    """Read new EVE JSON lines from disk and ingest alerts into the DB."""

    def __init__(self, eve_path=None):
        self.eve_path = eve_path or EVE_LOG

    # ------------------------------------------------------------------
    # Bookmark helpers
    # ------------------------------------------------------------------

    def _get_bookmark(self):
        """Return (byte_offset, inode) from pipeline_state, or (0, 0)."""
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT byte_offset, inode FROM pipeline_state WHERE source = ?",
                (SOURCE_KEY,),
            ).fetchone()
            if row:
                return (row["byte_offset"], row["inode"])
            return (0, 0)
        finally:
            close_db(conn)

    def _save_bookmark(self, offset, inode, events, alerts):
        """Upsert the bookmark and cumulative counters into pipeline_state."""
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        conn = get_db()
        try:
            existing = conn.execute(
                "SELECT source FROM pipeline_state WHERE source = ?",
                (SOURCE_KEY,),
            ).fetchone()
            if existing:
                conn.execute(
                    """UPDATE pipeline_state
                          SET byte_offset      = ?,
                              inode            = ?,
                              last_event_time  = ?,
                              events_processed = events_processed + ?,
                              alerts_ingested  = alerts_ingested  + ?,
                              updated_at       = datetime('now','localtime')
                        WHERE source = ?""",
                    (offset, inode, now, events, alerts, SOURCE_KEY),
                )
            else:
                conn.execute(
                    """INSERT INTO pipeline_state
                           (source, byte_offset, inode, last_event_time,
                            events_processed, alerts_ingested, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, datetime('now','localtime'))""",
                    (SOURCE_KEY, offset, inode, now, events, alerts),
                )
            conn.commit()
        finally:
            close_db(conn)

    # ------------------------------------------------------------------
    # Rotation detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_rotation(current_inode, saved_inode):
        """Return True if the log file has been rotated (inode changed)."""
        if saved_inode == 0:
            return False
        return current_inode != saved_inode

    # ------------------------------------------------------------------
    # Line processing
    # ------------------------------------------------------------------

    def _process_line(self, line_bytes):
        """Parse one JSON line.  If it is an alert, insert it and return the
        alert dict.  For any other event type return None (but the caller
        counts it as an event processed)."""
        try:
            ev = json.loads(line_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

        if ev.get("event_type") != "alert":
            return None

        alert_block = ev.get("alert", {})
        record = {
            "timestamp":         ev.get("timestamp", ""),
            "signature_id":      alert_block.get("signature_id"),
            "signature":         alert_block.get("signature", ""),
            "severity":          alert_block.get("severity"),
            "category":          alert_block.get("category", ""),
            "src_ip":            ev.get("src_ip", ""),
            "src_port":          ev.get("src_port"),
            "dest_ip":           ev.get("dest_ip", ""),
            "dest_port":         ev.get("dest_port"),
            "proto":             ev.get("proto", ""),
            "app_proto":         ev.get("app_proto", ""),
            "payload_printable": ev.get("payload_printable", ""),
            "pcap_filename":     ev.get("pcap_filename", ""),
            "event_json":        json.dumps(ev),
        }

        conn = get_db()
        try:
            conn.execute(
                """INSERT INTO ingested_alerts
                       (timestamp, signature_id, signature, severity, category,
                        src_ip, src_port, dest_ip, dest_port, proto, app_proto,
                        payload_printable, pcap_filename, event_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record["timestamp"],
                    record["signature_id"],
                    record["signature"],
                    record["severity"],
                    record["category"],
                    record["src_ip"],
                    record["src_port"],
                    record["dest_ip"],
                    record["dest_port"],
                    record["proto"],
                    record["app_proto"],
                    record["payload_printable"],
                    record["pcap_filename"],
                    record["event_json"],
                ),
            )
            conn.commit()
        finally:
            close_db(conn)

        return record

    # ------------------------------------------------------------------
    # Core ingestion loop
    # ------------------------------------------------------------------

    def run_once(self):
        """Read from the last bookmark to current EOF, process all new lines.

        Returns:
            (events_processed, alerts_ingested)
        """
        try:
            stat = os.stat(self.eve_path)
        except FileNotFoundError:
            return (0, 0)

        current_inode = stat.st_ino
        file_size = stat.st_size

        saved_offset, saved_inode = self._get_bookmark()

        # Handle log rotation — start from the beginning of the new file.
        if self._detect_rotation(current_inode, saved_inode):
            saved_offset = 0

        # File was truncated (e.g. log rotation without inode change).
        if saved_offset > file_size:
            saved_offset = 0

        # Nothing new to read.
        if saved_offset >= file_size:
            return (0, 0)

        events_processed = 0
        alerts_ingested = 0

        try:
            with open(self.eve_path, "rb") as f:
                f.seek(saved_offset)
                data = f.read()
        except FileNotFoundError:
            return (0, 0)

        new_offset = saved_offset + len(data)

        for line in data.split(b"\n"):
            line = line.strip()
            if not line:
                continue
            events_processed += 1
            result = self._process_line(line)
            if result is not None:
                alerts_ingested += 1
                try:
                    from analyzers.alerting import check_and_notify
                    check_and_notify(result)
                except Exception:
                    pass

        self._save_bookmark(new_offset, current_inode, events_processed, alerts_ingested)
        return (events_processed, alerts_ingested)

    def run_forever(self, interval=2):
        """Loop calling run_once() every *interval* seconds.  Designed to
        run inside a daemon thread — blocks indefinitely."""
        while True:
            try:
                self.run_once()
            except Exception:
                # Swallow errors so the daemon thread never dies.  The next
                # iteration will retry.
                pass
            time.sleep(interval)


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def start_pipeline():
    """Create an AlertPipeline and start run_forever() in a daemon thread.

    Safe to call multiple times — only the first call spawns the thread.
    """
    global _pipeline_instance
    with _lock:
        if _pipeline_instance is not None:
            return
        _pipeline_instance = AlertPipeline()
        t = threading.Thread(target=_pipeline_instance.run_forever, daemon=True)
        t.start()


def get_pipeline_stats():
    """Return a dict with current pipeline statistics."""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT byte_offset, inode, last_event_time, events_processed, "
            "       alerts_ingested, updated_at "
            "FROM pipeline_state WHERE source = ?",
            (SOURCE_KEY,),
        ).fetchone()
    finally:
        close_db(conn)

    if not row:
        return {
            "events_processed": 0,
            "alerts_ingested":  0,
            "byte_offset":      0,
            "last_event_time":  None,
            "lag_bytes":        0,
        }

    byte_offset = row["byte_offset"]

    # Compute lag: how far behind EOF the bookmark is.
    try:
        file_size = os.path.getsize(EVE_LOG)
    except FileNotFoundError:
        file_size = byte_offset  # no lag if the file doesn't exist

    return {
        "events_processed": row["events_processed"],
        "alerts_ingested":  row["alerts_ingested"],
        "byte_offset":      byte_offset,
        "last_event_time":  row["last_event_time"],
        "lag_bytes":        max(0, file_size - byte_offset),
    }
