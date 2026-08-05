"""File Hash Extraction API."""

from bottle import request
from db import cache_get, cache_set
from analyzers.file_hash import extract_file_hashes


def register(app):

    @app.get("/api/file-hashes")
    def api_file_hashes():
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"file_hashes_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = extract_file_hashes(minutes=minutes)
        cache_set(cache_key, result, ttl=120)
        return result
