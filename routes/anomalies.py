"""
Anomaly detection API.
"""

from bottle import request
from analyzers.anomaly import detect_anomalies
from db import cache_get, cache_set


def register(app):

    @app.get("/api/anomalies")
    def api_anomalies():
        minutes = int(request.query.get("minutes", 60)) or 60
        cache_key = f"anomalies_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached

        result = detect_anomalies(minutes=minutes)
        cache_set(cache_key, result, ttl=120)
        return result
