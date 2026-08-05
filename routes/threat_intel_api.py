"""
Unified threat-intelligence API.

  POST /api/intel/lookup           {type: 'ip'|'domain'|'url', value}      → unified score
  GET  /api/intel/ip/<ip>                                                  → unified IP score
  GET  /api/intel/domain/<domain>                                          → domain score
  GET  /api/intel/chips?ips=a,b,c                                          → cache-only chips
                                                                              (UI batch decoration; never blocks on API)
"""

from bottle import request, response

from analyzers.ti_score import score_ip, score_domain, score_url, quick_chip_for_ip


def register(app):

    @app.post("/api/intel/lookup")
    def intel_lookup():
        data = request.json or {}
        t = (data.get("type") or "").lower()
        v = (data.get("value") or "").strip()
        if not v:
            response.status = 400
            return {"error": "value is required"}
        if t == "ip":
            return score_ip(v)
        if t == "domain":
            return score_domain(v)
        if t == "url":
            return score_url(v)
        response.status = 400
        return {"error": f"unknown type '{t}'. Must be one of: ip, domain, url"}

    @app.get("/api/intel/ip/<ip>")
    def intel_ip(ip):
        return score_ip(ip)

    @app.get("/api/intel/domain/<domain>")
    def intel_domain(domain):
        return score_domain(domain)

    @app.get("/api/intel/queue/status")
    def intel_queue_status():
        """Status of the TI auto-enrichment queue.
        Returns: {pending, done_today, failed_today, oldest_pending_at, by_type}"""
        from analyzers.ti_queue import queue_status
        return queue_status()

    @app.post("/api/intel/queue/sweep")
    def intel_queue_sweep():
        """Manual catch-up: scan last N minutes of alerts and enqueue
        every indicator. Useful right after a restart."""
        from bottle import request as _r
        from analyzers.ti_queue import bulk_enrich_recent_alerts
        d = _r.json or {}
        minutes = int(d.get("minutes", 30) or 30)
        return bulk_enrich_recent_alerts(minutes=minutes, max_events=int(d.get("max_events", 500)))

    @app.get("/api/intel/chips")
    def intel_chips():
        """Bulk cached-only IP enrichment for alert-log decoration.

        Never hits the VT API — only returns whatever the local DB already
        knows about. Front-end calls this with the visible page of alerts so
        each row gets a tiny green/yellow/red chip without slowing the page.
        """
        raw = (request.query.get("ips") or "").strip()
        if not raw:
            return {"chips": {}}
        ips = [x.strip() for x in raw.split(",") if x.strip()]
        out = {}
        for ip in ips[:200]:  # cap to keep it cheap
            out[ip] = quick_chip_for_ip(ip)
        return {"chips": out}
