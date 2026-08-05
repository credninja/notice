"""
Daily snapshot collector and trend comparison engine.
Stores daily summaries in SQLite for week-over-week trend analysis.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from eve_reader import iter_events, is_internal, is_ipv4
from db import get_db


def capture_daily_snapshot():
    """Capture today's metrics and store as a snapshot. Safe to call multiple times (upserts)."""
    today = datetime.now().strftime("%Y-%m-%d")
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_alerts = 0
    total_flows = 0
    total_bytes = 0
    internal_ips = set()
    external_ips = set()

    for ev in iter_events(event_types={"flow", "alert"}, minutes=1440):
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        etype = ev["event_type"]

        if is_ipv4(src) and is_internal(src):
            internal_ips.add(src)
        if is_ipv4(dst) and is_internal(dst):
            internal_ips.add(dst)
        if is_ipv4(src) and not is_internal(src):
            external_ips.add(src)
        if is_ipv4(dst) and not is_internal(dst):
            external_ips.add(dst)

        if etype == "alert":
            total_alerts += 1
            s = ev.get("alert", {}).get("severity", 3)
            if s == 1:
                sev["critical"] += 1
            elif s == 2:
                sev["high"] += 1
            elif s == 3:
                sev["medium"] += 1
            else:
                sev["low"] += 1
        elif etype == "flow":
            total_flows += 1
            flow = ev.get("flow", {})
            total_bytes += flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)

    # Count from DB tables
    conn = get_db()
    violations = conn.execute(
        "SELECT COUNT(*) FROM policy_violations WHERE detected_at >= ?", (today,)
    ).fetchone()[0]
    inc_opened = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE created_at >= ?", (today,)
    ).fetchone()[0]
    inc_resolved = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE resolved_at >= ? AND status IN ('resolved','closed')", (today,)
    ).fetchone()[0]
    tp = conn.execute(
        "SELECT COUNT(*) FROM alert_verdicts WHERE verdict='true_positive' AND marked_at >= ?", (today,)
    ).fetchone()[0]
    fp = conn.execute(
        "SELECT COUNT(*) FROM alert_verdicts WHERE verdict='false_positive' AND marked_at >= ?", (today,)
    ).fetchone()[0]

    # Health score (0-100, higher is better)
    health = _compute_health_score(sev, total_alerts, violations, len(internal_ips))

    conn.execute("""
        INSERT OR REPLACE INTO daily_snapshots
        (snapshot_date, total_alerts, critical_alerts, high_alerts, medium_alerts, low_alerts,
         total_flows, total_bytes, unique_internal_ips, unique_external_ips,
         policy_violations, incidents_opened, incidents_resolved,
         tp_verdicts, fp_verdicts, health_score)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (today, total_alerts, sev["critical"], sev["high"], sev["medium"], sev["low"],
          total_flows, total_bytes, len(internal_ips), len(external_ips),
          violations, inc_opened, inc_resolved, tp, fp, health))
    conn.commit()
    conn.close()
    return today


def _compute_health_score(sev, total_alerts, violations, asset_count):
    """Compute 0-100 health score. 100 = perfectly healthy."""
    score = 100
    # Critical alerts heavily penalize
    score -= min(40, sev["critical"] * 10)
    # High alerts
    score -= min(25, sev["high"] * 5)
    # Medium alerts
    score -= min(15, sev["medium"] * 1)
    # Policy violations
    score -= min(10, violations * 2)
    # Bonus: if we have good asset visibility
    if asset_count > 0 and total_alerts == 0:
        score = min(100, score + 5)
    return max(0, min(100, score))


def get_trend_data(days=14):
    """Get snapshot data for the last N days for trend analysis."""
    conn = get_db()
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = conn.execute(
        "SELECT * FROM daily_snapshots WHERE snapshot_date >= ? ORDER BY snapshot_date",
        (cutoff,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_week_comparison():
    """Compare this week vs last week metrics."""
    snapshots = get_trend_data(days=14)
    if not snapshots:
        return None

    today = datetime.now().date()
    this_week = []
    last_week = []

    for s in snapshots:
        d = datetime.strptime(s["snapshot_date"], "%Y-%m-%d").date()
        age = (today - d).days
        if age < 7:
            this_week.append(s)
        else:
            last_week.append(s)

    def _sum(data, key):
        return sum(s.get(key, 0) for s in data)

    def _avg(data, key):
        if not data:
            return 0
        return sum(s.get(key, 0) for s in data) / len(data)

    def _delta(current, previous):
        if previous == 0:
            return 100 if current > 0 else 0
        return round(((current - previous) / previous) * 100, 1)

    tw_alerts = _sum(this_week, "total_alerts")
    lw_alerts = _sum(last_week, "total_alerts")
    tw_critical = _sum(this_week, "critical_alerts")
    lw_critical = _sum(last_week, "critical_alerts")
    tw_violations = _sum(this_week, "policy_violations")
    lw_violations = _sum(last_week, "policy_violations")
    tw_health = _avg(this_week, "health_score")
    lw_health = _avg(last_week, "health_score")
    tw_bytes = _sum(this_week, "total_bytes")
    lw_bytes = _sum(last_week, "total_bytes")

    return {
        "this_week": {
            "days": len(this_week),
            "total_alerts": tw_alerts,
            "critical_alerts": tw_critical,
            "policy_violations": tw_violations,
            "avg_health_score": round(tw_health),
            "total_bytes": tw_bytes,
            "incidents_opened": _sum(this_week, "incidents_opened"),
            "incidents_resolved": _sum(this_week, "incidents_resolved"),
        },
        "last_week": {
            "days": len(last_week),
            "total_alerts": lw_alerts,
            "critical_alerts": lw_critical,
            "policy_violations": lw_violations,
            "avg_health_score": round(lw_health),
            "total_bytes": lw_bytes,
            "incidents_opened": _sum(last_week, "incidents_opened"),
            "incidents_resolved": _sum(last_week, "incidents_resolved"),
        },
        "deltas": {
            "alerts": _delta(tw_alerts, lw_alerts),
            "critical": _delta(tw_critical, lw_critical),
            "violations": _delta(tw_violations, lw_violations),
            "health": round(tw_health - lw_health, 1),
            "bytes": _delta(tw_bytes, lw_bytes),
        },
        "trend": [
            {"date": s["snapshot_date"], "alerts": s["total_alerts"],
             "critical": s["critical_alerts"], "health": s["health_score"],
             "bytes": s["total_bytes"], "violations": s["policy_violations"]}
            for s in snapshots
        ],
    }
