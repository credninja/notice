"""
Executive summary, trend analysis, MITRE heatmap, and IP reputation APIs.
"""

from bottle import request, response
from db import get_db, cache_get, cache_set
from analyzers.snapshots import capture_daily_snapshot, get_trend_data, get_week_comparison
from analyzers.mitre import build_mitre_heatmap
from analyzers.reputation import lookup_reputation, get_all_cached, lookup_batch_reputation
from eve_reader import iter_events, is_internal, is_ipv4
from collections import defaultdict
from datetime import datetime, timedelta


def register(app):

    # ── Daily Snapshot (called on page load or via timer) ──
    @app.post("/api/snapshot")
    def take_snapshot():
        date = capture_daily_snapshot()
        return {"ok": True, "date": date}

    # ── Trend Data ──
    @app.get("/api/trends")
    def api_trends():
        cached = cache_get("trends_14d")
        if cached:
            return cached
        data = get_week_comparison()
        if not data:
            # No snapshots yet, capture one now
            capture_daily_snapshot()
            data = get_week_comparison()
        result = data or {"error": "No snapshot data available yet"}
        cache_set("trends_14d", result, ttl=300)
        return result

    @app.get("/api/trends/history")
    def api_trend_history():
        days = min(90, max(1, int(request.query.get("days", 14))))
        data = get_trend_data(days=days)
        return {"snapshots": data, "days": days}

    # ── Executive Summary (single page, all KPIs) ──
    @app.get("/api/executive")
    def api_executive():
        # Honor the time-range selector — without this, switching filters
        # (1h / 24h / 7d) returns the same 24h-based response every time.
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"executive_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        data = _build_executive(minutes=minutes)
        cache_set(cache_key, data, ttl=120)
        return data

    # ── MITRE ATT&CK Heatmap ──
    @app.get("/api/mitre")
    def api_mitre():
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"mitre_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        data = build_mitre_heatmap(minutes=minutes)
        cache_set(cache_key, data, ttl=120)
        return data

    # ── IP Reputation ──
    @app.get("/api/reputation/<ip>")
    def api_reputation(ip):
        result = lookup_reputation(ip)
        return result

    @app.get("/api/reputation")
    def api_reputation_cached():
        """Return all cached reputation data."""
        return {"results": get_all_cached()}

    @app.post("/api/reputation/scan")
    def api_reputation_scan():
        """Scan top external IPs for reputation."""
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"reputation_scan_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached

        # Find top external IPs by alert count
        ext_ips = defaultdict(int)
        for ev in iter_events(event_types={"alert"}, minutes=minutes):
            src = ev.get("src_ip", "")
            dst = ev.get("dest_ip", "")
            if is_ipv4(src) and not is_internal(src):
                ext_ips[src] += 1
            if is_ipv4(dst) and not is_internal(dst):
                ext_ips[dst] += 1

        top_ips = sorted(ext_ips.keys(), key=lambda ip: ext_ips[ip], reverse=True)[:20]
        results = lookup_batch_reputation(top_ips)

        enriched = []
        for ip in top_ips:
            r = results.get(ip, {})
            r["alert_count"] = ext_ips[ip]
            enriched.append(r)

        data = {"results": enriched, "total_external_ips": len(ext_ips)}
        cache_set(cache_key, data, ttl=300)
        return data

    # ── Alert Sparklines (7-day trend per metric) ──
    @app.get("/api/sparklines")
    def api_sparklines():
        cached = cache_get("sparklines")
        if cached:
            return cached
        data = get_trend_data(days=7)
        sparklines = {
            "alerts": [s.get("total_alerts", 0) for s in data],
            "critical": [s.get("critical_alerts", 0) for s in data],
            "health": [s.get("health_score", 0) for s in data],
            "bytes": [s.get("total_bytes", 0) for s in data],
            "violations": [s.get("policy_violations", 0) for s in data],
            "dates": [s.get("snapshot_date", "") for s in data],
        }
        cache_set("sparklines", sparklines, ttl=300)
        return sparklines


def _build_executive(minutes=1440):
    """Build executive summary combining all KPIs over the requested window."""
    # Get current metrics
    conn = get_db()

    # Asset stats
    total_assets = conn.execute("SELECT COUNT(*) FROM assets WHERE scope='internal'").fetchone()[0]
    critical_assets = conn.execute("SELECT COUNT(*) FROM assets WHERE business_critical=1").fetchone()[0]

    # Incident stats
    open_incidents = conn.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating')").fetchone()[0]
    resolved = conn.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('resolved','closed')").fetchone()[0]

    # Verdict stats
    tp = conn.execute("SELECT COUNT(*) FROM alert_verdicts WHERE verdict='true_positive'").fetchone()[0]
    fp = conn.execute("SELECT COUNT(*) FROM alert_verdicts WHERE verdict='false_positive'").fetchone()[0]
    pending = conn.execute("SELECT COUNT(*) FROM alert_verdicts WHERE verdict='investigating'").fetchone()[0]

    # Policy violations
    active_violations = conn.execute("SELECT COUNT(*) FROM policy_violations WHERE acknowledged=0").fetchone()[0]

    # Action items
    open_actions = conn.execute("SELECT COUNT(*) FROM action_items WHERE status IN ('open','in_progress')").fetchone()[0]
    breached_sla = conn.execute("SELECT COUNT(*) FROM action_items WHERE sla_breached=1").fetchone()[0]

    # MTTR (hours)
    mttr_row = conn.execute("""
        SELECT AVG((julianday(resolved_at) - julianday(created_at)) * 24) as mttr
        FROM incidents WHERE resolved_at IS NOT NULL
    """).fetchone()
    mttr = round(mttr_row["mttr"], 1) if mttr_row and mttr_row["mttr"] else None

    conn.close()

    # Alert counts from eve.json over the requested window
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_alerts = 0
    for ev in iter_events(event_types={"alert"}, minutes=minutes):
        total_alerts += 1
        s = ev.get("alert", {}).get("severity", 3)
        if s == 1:
            sev_counts["critical"] += 1
        elif s == 2:
            sev_counts["high"] += 1
        elif s == 3:
            sev_counts["medium"] += 1
        else:
            sev_counts["low"] += 1

    # Health score — rate-normalised by window length so the score actually
    # varies as the user switches the time filter (1h vs 24h).
    # Without this, any busy network saturates the caps and locks the score
    # at the same value regardless of window.
    hours = max(1, minutes / 60.0)
    crit_rate = sev_counts["critical"] / hours
    high_rate = sev_counts["high"] / hours
    med_rate = sev_counts["medium"] / hours
    health = 100
    health -= min(40, crit_rate * 4)        # 10 critical/hr → -40 (cap)
    health -= min(25, high_rate * 1.5)      # ~17 high/hr → -25
    health -= min(15, med_rate * 0.3)       # ~50 med/hr → -15
    health -= min(10, active_violations * 2)
    health -= min(10, open_incidents * 5)
    health = max(0, min(100, round(health)))

    if health >= 80:
        health_label = "Healthy"
    elif health >= 60:
        health_label = "At Risk"
    elif health >= 40:
        health_label = "Degraded"
    else:
        health_label = "Critical"

    # Week comparison
    comparison = get_week_comparison()

    return {
        "health_score": health,
        "health_label": health_label,
        "window_minutes": minutes,
        "kpis": {
            "total_alerts_24h": total_alerts,
            "critical_alerts_24h": sev_counts["critical"],
            "total_alerts": total_alerts,
            "critical_alerts": sev_counts["critical"],
            "open_incidents": open_incidents,
            "active_violations": active_violations,
            "asset_coverage": total_assets,
            "critical_assets": critical_assets,
            "mttr_hours": mttr,
            "sla_breaches": breached_sla,
            "tp_verdicts": tp,
            "fp_verdicts": fp,
            "pending_verdicts": pending,
        },
        "severity_breakdown": sev_counts,
        "comparison": comparison,
    }
