"""
Server-Sent Events stream of new alert events.

GET /api/events/stream
  - Content-Type: text/event-stream
  - Tails eve.json from end-of-file and pushes each new alert as an SSE event.
  - Sends a 'heartbeat' comment every ~15s so proxies / browsers don't
    drop the idle connection.
  - Client must be EventSource-aware (browsers handle reconnect automatically).

Backed by a per-request file-tailer thread (no shared queue), so the only
shared resource is the underlying eve.json file. Suitable for the small
number of analyst dashboards we expect (handful of concurrent viewers).
"""

import json
import os
import time

from bottle import response

from eve_reader import EVE_LOG, is_internal


_ALERT_PHASES = {
    0: "Unmapped", 1: "Reconnaissance", 2: "Weaponization", 3: "Delivery",
    4: "Exploitation", 5: "Installation", 6: "Command & Control",
    7: "Actions on Objectives",
}


def _classify_phase(signature):
    # Lazy import — analyzers.correlation imports a lot of state at module load.
    from analyzers.correlation import SIGNATURE_MAP
    sig_lower = (signature or "").lower()
    for m in SIGNATURE_MAP:
        if m["pattern"] in sig_lower:
            p = m.get("phase", 0)
            return p, m.get("phase_name", _ALERT_PHASES.get(p, "Unmapped"))
    return 0, "Unmapped"


def _tail_eve(path, idle_sleep=0.5):
    """Generator yielding new lines appended to `path`.

    Opens at end-of-file and polls. Handles log rotation (file shrinks or
    inode changes) by re-opening. Yields raw bytes-decoded strings.
    """
    while True:
        try:
            f = open(path, "r", encoding="utf-8", errors="replace")
        except FileNotFoundError:
            time.sleep(2.0)
            continue
        try:
            f.seek(0, 2)  # jump to end
            inode = os.fstat(f.fileno()).st_ino
            while True:
                line = f.readline()
                if line:
                    yield line
                    continue
                # No new data — sleep, then check for rotation
                time.sleep(idle_sleep)
                try:
                    cur_inode = os.stat(path).st_ino
                    cur_size = os.stat(path).st_size
                except FileNotFoundError:
                    break
                if cur_inode != inode or cur_size < f.tell():
                    break  # rotated/truncated — reopen
        finally:
            f.close()


def register(app):

    @app.get("/api/events/stream")
    def events_stream():
        """SSE stream of new alert events as they're written to eve.json."""
        response.content_type = "text/event-stream"
        response.set_header("Cache-Control", "no-cache, no-transform")
        # Note: don't set Connection: keep-alive — wsgiref treats it as a
        # hop-by-hop header and rejects the response. The HTTP/1.1 default
        # is already keep-alive.
        response.set_header("X-Accel-Buffering", "no")  # disable proxy buffering

        def _generate():
            # Initial hello so the client knows the stream is live
            yield "event: hello\ndata: {}\n\n"

            last_heartbeat = time.time()
            for line in _tail_eve(EVE_LOG):
                # Heartbeat at most every 15s
                now = time.time()
                if now - last_heartbeat > 15:
                    yield ": heartbeat\n\n"
                    last_heartbeat = now

                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if ev.get("event_type") != "alert":
                    continue

                alert = ev.get("alert") or {}
                signature = alert.get("signature", "")
                phase, phase_name = _classify_phase(signature)
                src = ev.get("src_ip", "")
                dst = ev.get("dest_ip", "")
                payload = {
                    "timestamp": ev.get("timestamp", ""),
                    "src_ip": src,
                    "dest_ip": dst,
                    "src_port": ev.get("src_port"),
                    "dest_port": ev.get("dest_port"),
                    "proto": ev.get("proto", ""),
                    "signature": signature,
                    "signature_id": alert.get("signature_id"),
                    "category": alert.get("category", ""),
                    "phase": phase,
                    "phase_name": phase_name,
                    "src_internal": is_internal(src),
                    "dest_internal": is_internal(dst),
                }
                # Auto-enrich: extract every flagged IP/domain/URL from the
                # alert and push onto the TI queue. The worker thread pulls
                # asynchronously so this never blocks the SSE response.
                try:
                    from analyzers.ti_queue import enrich_event
                    enrich_event(ev, source="sse")
                except Exception:
                    pass
                yield "event: alert\ndata: " + json.dumps(payload) + "\n\n"

        return _generate()
