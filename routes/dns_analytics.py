"""DNS Analytics API."""

from bottle import request
from db import cache_get, cache_set
from analyzers.dns_analytics import analyze_dns


def register(app):

    @app.get("/api/dns-analytics")
    def api_dns_analytics():
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"dns_analytics_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = analyze_dns(minutes=minutes)
        cache_set(cache_key, result, ttl=120)
        return result
