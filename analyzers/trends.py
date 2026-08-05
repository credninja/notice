"""
Trend Analysis — Compare Current Period vs Previous Period
============================================================
Calculates delta metrics: "alerts up 15% vs yesterday", "traffic down 8% vs last week"
Uses live data for both current and previous period.
"""

from collections import Counter
from eve_reader import iter_events, is_ipv4
from db import get_db


def compute_trends(minutes=60):
    """
    Compare metrics between current period and previous period of same duration.
    e.g., if minutes=60, compares last 1 hour vs the hour before that.
    Returns: {metric: {current, previous, delta, delta_pct, trend}}
    """
    # Current period: last N minutes
    current = _collect_metrics(minutes=minutes)

    # Previous period: N to 2N minutes ago
    previous = _collect_metrics_previous(minutes=minutes)

    # Calculate deltas
    trends = {}
    for key in current:
        cur = current[key]
        prev = previous.get(key, 0)
        delta = cur - prev
        delta_pct = round((delta / prev * 100), 1) if prev > 0 else (100.0 if cur > 0 else 0.0)
        if delta > 0:
            trend = "up"
        elif delta < 0:
            trend = "down"
        else:
            trend = "stable"

        trends[key] = {
            "current": cur,
            "previous": prev,
            "delta": delta,
            "delta_pct": delta_pct,
            "trend": trend,
        }

    return {
        "period_minutes": minutes,
        "metrics": trends,
    }


def _collect_metrics(minutes):
    """Collect key metrics from current time window."""
    total_events = 0
    total_alerts = 0
    total_bytes = 0
    total_flows = 0
    alert_by_sev = Counter()
    unique_src = set()
    unique_dst = set()

    for ev in iter_events(minutes=minutes):
        total_events += 1
        etype = ev.get("event_type")
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")

        if etype == "alert":
            total_alerts += 1
            sev = ev.get("alert", {}).get("severity", 3)
            alert_by_sev[sev] += 1

        if etype == "flow":
            flow = ev.get("flow", {})
            total_bytes += flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
            total_flows += 1

        if is_ipv4(src):
            unique_src.add(src)
        if is_ipv4(dst):
            unique_dst.add(dst)

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "total_bytes": total_bytes,
        "total_flows": total_flows,
        "critical_alerts": alert_by_sev.get(1, 0),
        "high_alerts": alert_by_sev.get(2, 0),
        "medium_alerts": alert_by_sev.get(3, 0),
        "unique_sources": len(unique_src),
        "unique_destinations": len(unique_dst),
    }


def _collect_metrics_previous(minutes):
    """Collect metrics from the period BEFORE the current window."""
    # Read events from (2*minutes) ago to (minutes) ago
    total_events = 0
    total_alerts = 0
    total_bytes = 0
    total_flows = 0
    alert_by_sev = Counter()
    unique_src = set()
    unique_dst = set()

    from datetime import datetime, timedelta
    now = datetime.now().astimezone()
    cutoff_start = now - timedelta(minutes=minutes * 2)
    cutoff_end = now - timedelta(minutes=minutes)

    for ev in iter_events(minutes=minutes * 2):
        ts_str = ev.get("timestamp", "")
        if not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(ts_str)
        except (ValueError, TypeError):
            continue

        # Only include events in the PREVIOUS window
        if ts >= cutoff_end or ts < cutoff_start:
            continue

        total_events += 1
        etype = ev.get("event_type")
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")

        if etype == "alert":
            total_alerts += 1
            sev = ev.get("alert", {}).get("severity", 3)
            alert_by_sev[sev] += 1

        if etype == "flow":
            flow = ev.get("flow", {})
            total_bytes += flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
            total_flows += 1

        if is_ipv4(src):
            unique_src.add(src)
        if is_ipv4(dst):
            unique_dst.add(dst)

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "total_bytes": total_bytes,
        "total_flows": total_flows,
        "critical_alerts": alert_by_sev.get(1, 0),
        "high_alerts": alert_by_sev.get(2, 0),
        "medium_alerts": alert_by_sev.get(3, 0),
        "unique_sources": len(unique_src),
        "unique_destinations": len(unique_dst),
    }
