"""Alert Timeline Heatmap API — hour-of-day x day-of-week matrix."""

from collections import defaultdict
from bottle import request
from db import cache_get, cache_set
from eve_reader import iter_events
from datetime import datetime


def register(app):

    @app.get("/api/alert-heatmap")
    def api_alert_heatmap():
        minutes = int(request.query.get("minutes", 10080)) or 10080
        cache_key = f"alert_heatmap_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = _build_heatmap(minutes)
        cache_set(cache_key, result, ttl=120)
        return result


def _build_heatmap(minutes):
    """Build hour x day-of-week heatmap from alert timestamps."""
    matrix = defaultdict(lambda: defaultdict(int))
    severity_matrix = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    total = 0
    peak_hour = 0
    peak_count = 0
    hourly = defaultdict(int)
    daily = defaultdict(int)

    for ev in iter_events(event_types={"alert"}, minutes=minutes):
        ts = ev.get("timestamp", "")
        alert = ev.get("alert", {})
        severity = alert.get("severity", 3)
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts)
            hour = dt.hour
            dow = dt.weekday()
            matrix[dow][hour] += 1
            sev_label = {1: "critical", 2: "high", 3: "medium"}.get(severity, "low")
            severity_matrix[dow][hour][sev_label] += 1
            hourly[hour] += 1
            daily[dow] += 1
            total += 1
        except (ValueError, TypeError):
            continue

    cells = []
    for dow in range(7):
        for hour in range(24):
            count = matrix[dow][hour]
            cells.append({
                "day": dow,
                "hour": hour,
                "count": count,
                "severities": dict(severity_matrix[dow][hour]) if severity_matrix[dow][hour] else {},
            })
            if count > peak_count:
                peak_count = count
                peak_hour = hour

    day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    peak_day = max(range(7), key=lambda d: daily.get(d, 0)) if daily else 0
    quietest_day = min(range(7), key=lambda d: daily.get(d, 0)) if daily else 0

    return {
        "cells": cells,
        "total_alerts": total,
        "peak_hour": peak_hour,
        "peak_day": day_names[peak_day],
        "quietest_day": day_names[quietest_day],
        "max_value": peak_count,
        "hourly_totals": [hourly.get(h, 0) for h in range(24)],
        "daily_totals": {day_names[d]: daily.get(d, 0) for d in range(7)},
    }
