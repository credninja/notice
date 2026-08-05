"""OSINT Threat Feed API — fetch, correlate, search IOCs from free feeds."""

from bottle import request, response
from db import cache_get, cache_set
from analyzers.osint_feeds import (
    fetch_feed, fetch_all_feeds, correlate,
    get_feed_status, get_ioc_summary, get_matches,
    get_match_stats, search_ioc, FEEDS,
)


def register(app):

    @app.get("/api/threat-feeds/status")
    def feeds_status():
        cache_key = "osint_feed_status"
        cached = cache_get(cache_key)
        if cached:
            return cached
        status = get_feed_status()
        summary = get_ioc_summary()
        match_stats = get_match_stats()
        result = {"feeds": status, "summary": summary, "matches": match_stats}
        cache_set(cache_key, result, ttl=30)
        return result

    @app.post("/api/threat-feeds/fetch")
    def feeds_fetch():
        body = request.json or {}
        feed_id = body.get("feed")
        if feed_id:
            if feed_id not in FEEDS:
                response.status = 400
                return {"error": f"Unknown feed: {feed_id}"}
            return fetch_feed(feed_id)
        return fetch_all_feeds()

    @app.post("/api/threat-feeds/correlate")
    def feeds_correlate():
        body = request.json or {}
        minutes = int(body.get("minutes", 60))
        return correlate(minutes=minutes)

    @app.get("/api/threat-feeds/matches")
    def feeds_matches():
        limit = int(request.query.get("limit", 200))
        return {"matches": get_matches(limit=limit)}

    @app.get("/api/threat-feeds/search")
    def feeds_search():
        q = request.query.get("q", "").strip()
        if not q or len(q) < 3:
            response.status = 400
            return {"error": "Query must be at least 3 characters"}
        return search_ioc(q)
