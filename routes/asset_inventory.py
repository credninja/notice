"""
Asset Inventory API — passive discovery + active probing for unregistered assets.
"""

from bottle import request, response
from db import cache_get, cache_set
from analyzers.asset_discovery import discover_assets
from analyzers.asset_probe import get_unregistered_ips, probe_single_ip, probe_batch


def register(app):

    @app.get("/api/asset-inventory")
    def api_asset_inventory():
        minutes = int(request.query.get("minutes", 60)) or 60
        cache_key = f"asset_inventory_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        data = discover_assets(minutes=minutes)
        cache_set(cache_key, data, ttl=120)
        return data

    @app.get("/api/asset-inventory/unregistered")
    def api_unregistered():
        """List all unregistered internal IPs seen in traffic."""
        minutes = int(request.query.get("minutes", 60)) or 60
        cache_key = f"unregistered_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        ips = get_unregistered_ips(minutes=minutes)
        data = {"ips": ips, "count": len(ips)}
        cache_set(cache_key, data, ttl=120)
        return data

    @app.get("/api/asset-inventory/probe/<ip>")
    def api_probe_ip(ip):
        """Actively probe a single unregistered IP for SBOM/CBOM/HBOM."""
        from eve_reader import is_internal, is_ipv4
        if not is_ipv4(ip) or not is_internal(ip):
            response.status = 400
            return {"error": "Only internal IPv4 addresses can be probed"}
        result = probe_single_ip(ip, timeout=3)
        return result

    @app.post("/api/asset-inventory/probe-batch")
    def api_probe_batch():
        """Probe multiple IPs in parallel."""
        data = request.json or {}
        ips = data.get("ips", [])
        if not ips:
            response.status = 400
            return {"error": "No IPs provided"}
        # Limit to 20 IPs per batch
        from eve_reader import is_internal, is_ipv4
        safe_ips = [ip for ip in ips[:20] if is_ipv4(ip) and is_internal(ip)]
        results = probe_batch(safe_ips, timeout=2, max_workers=5)
        return {"results": results, "probed": len(safe_ips)}
