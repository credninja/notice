"""
Plaintext communication detection API.
"""

from bottle import request
from analyzers.plaintext import detect_plaintext
from db import cache_get, cache_set


def register(app):

    @app.get("/api/plaintext")
    def api_plaintext():
        minutes = int(request.query.get("minutes", 60)) or 60
        cache_key = f"plaintext_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached

        result = detect_plaintext(minutes=minutes)
        cache_set(cache_key, result, ttl=120)
        return result
