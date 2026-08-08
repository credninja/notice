"""
Local LLM triage assistant. Runs on Ollama (default localhost:11434).

Given an incident, assembles all relevant context (metadata, IOCs,
prior verdicts for the same signature, top events, threat-intel enrichment
where available) and asks the local model for a verdict recommendation
plus a suggested next action.

Nothing leaves the host. Free. Air-gappable.

Configuration via env vars:
    OLLAMA_HOST     — default http://127.0.0.1:11434
    OLLAMA_MODEL    — default llama3.2:3b
    OLLAMA_TIMEOUT  — default 60 (seconds)
"""

import json
import os
import urllib.request
import urllib.error
from db import get_db

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "60"))


SYSTEM_PROMPT = """You are a senior SOC analyst assistant. Given an incident and its context,
you produce a concise triage recommendation.

You MUST respond with a JSON object matching this exact schema and NOTHING else:
{
  "verdict": "likely_true_positive" | "likely_false_positive" | "investigate_further",
  "confidence": "low" | "medium" | "high",
  "reasoning": "1-3 sentences explaining your call using the evidence provided",
  "suggested_action": "one concrete next step for the analyst",
  "key_indicators": ["short bullets, 1-4 items, of the most important evidence pieces"]
}

Rules:
- "likely_false_positive" requires that the signature has strong historical FP evidence
  (e.g., >70% FP in prior closures) or the source is a known trusted asset (management server,
  monitoring probe, DNS resolver, etc.).
- "likely_true_positive" requires either external attacker source, exploit-family signature
  targeting critical asset, or a clear multi-stage attack chain.
- When in doubt, choose "investigate_further".
- Confidence "high" only when at least 2 independent evidence pieces align.
- Keep reasoning grounded in the specific numbers/facts provided; do not invent details."""


def _fetch_incident_context(incident_id):
    """Assemble everything the LLM needs to reason about this incident.

    Returns a dict with metadata + IOCs + related-history + top events.
    """
    conn = get_db()
    inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not inc:
        conn.close()
        return None
    inc = dict(inc)

    # Related history — prior verdicts for same signature
    sid = inc.get("signature_id")
    hist = {"total": 0, "tp": 0, "fp": 0}
    if sid:
        rows = conn.execute(
            "SELECT verdict, COUNT(*) as c FROM incidents "
            "WHERE signature_id=? AND status='closed' AND id != ? "
            "GROUP BY verdict",
            (sid, incident_id),
        ).fetchall()
        for r in rows:
            v = r["verdict"] or ""
            if v == "true_positive":
                hist["tp"] = r["c"]
            elif v == "false_positive":
                hist["fp"] = r["c"]
        hist["total"] = hist["tp"] + hist["fp"]

    # IOCs
    iocs = [dict(r) for r in conn.execute(
        "SELECT ioc_type, ioc_value, is_primary, frequency FROM incident_iocs "
        "WHERE incident_id=? ORDER BY is_primary DESC, frequency DESC LIMIT 15",
        (incident_id,),
    ).fetchall()]

    # Top few event samples
    events = [dict(r) for r in conn.execute(
        "SELECT src_ip, dest_ip, event_summary, timestamp "
        "FROM incident_events WHERE incident_id=? ORDER BY timestamp DESC LIMIT 5",
        (incident_id,),
    ).fetchall()]
    total_events = conn.execute(
        "SELECT COUNT(*) as c FROM incident_events WHERE incident_id=?", (incident_id,)
    ).fetchone()["c"]

    # Asset context — is src or dest a registered asset?
    def _asset_info(ip):
        if not ip:
            return None
        row = conn.execute(
            "SELECT ip, owner, hostname, asset_type, purdue_level, business_critical, scope "
            "FROM assets WHERE ip=?", (ip,)
        ).fetchone()
        return dict(row) if row else None

    src_asset = _asset_info(inc.get("attacker_ip"))
    dst_asset = _asset_info(inc.get("victim_ip"))

    conn.close()

    def _is_external(ip):
        if not ip:
            return False
        return not (ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("192.168."))

    return {
        "incident_id": inc["id"],
        "title": inc.get("title", ""),
        "signature": inc.get("signature", ""),
        "signature_id": sid,
        "severity": inc.get("severity", ""),
        "status": inc.get("status", ""),
        "created_at": inc.get("created_at", ""),
        "source_ip": inc.get("attacker_ip", ""),
        "source_is_external": _is_external(inc.get("attacker_ip", "")),
        "source_asset": src_asset,
        "destination_ip": inc.get("victim_ip", ""),
        "destination_is_external": _is_external(inc.get("victim_ip", "")),
        "destination_asset": dst_asset,
        "prior_verdicts_for_sid": hist,
        "iocs": iocs[:10],
        "sample_events": events,
        "total_events": total_events,
    }


def _build_user_prompt(ctx):
    """Convert context dict into a compact analyst-friendly narrative."""
    lines = []
    lines.append(f"Incident #{ctx['incident_id']}: {ctx['title']}")
    lines.append(f"Signature: {ctx['signature']} (SID {ctx['signature_id']})")
    lines.append(f"Severity: {ctx['severity']} · Created: {ctx['created_at']}")
    lines.append("")

    # Source
    src = ctx["source_ip"] or "(unknown)"
    src_tag = "EXTERNAL" if ctx["source_is_external"] else "INTERNAL"
    src_line = f"Source: {src} [{src_tag}]"
    if ctx["source_asset"]:
        a = ctx["source_asset"]
        parts = []
        if a.get("owner"): parts.append(f"owner={a['owner']}")
        if a.get("asset_type"): parts.append(f"type={a['asset_type']}")
        if a.get("business_critical"): parts.append("BUSINESS_CRITICAL")
        if a.get("purdue_level"): parts.append(f"purdue_level={a['purdue_level']}")
        if parts:
            src_line += " (" + ", ".join(parts) + ")"
    lines.append(src_line)

    # Destination
    dst = ctx["destination_ip"] or "(unknown)"
    dst_tag = "EXTERNAL" if ctx["destination_is_external"] else "INTERNAL"
    dst_line = f"Destination: {dst} [{dst_tag}]"
    if ctx["destination_asset"]:
        a = ctx["destination_asset"]
        parts = []
        if a.get("owner"): parts.append(f"owner={a['owner']}")
        if a.get("asset_type"): parts.append(f"type={a['asset_type']}")
        if a.get("business_critical"): parts.append("BUSINESS_CRITICAL")
        if a.get("purdue_level"): parts.append(f"purdue_level={a['purdue_level']}")
        if parts:
            dst_line += " (" + ", ".join(parts) + ")"
    lines.append(dst_line)

    lines.append("")

    # Prior verdicts
    h = ctx["prior_verdicts_for_sid"]
    if h["total"] > 0:
        fp_pct = round(h["fp"] / h["total"] * 100)
        lines.append(f"Prior verdicts for this SID: {h['total']} total closures — "
                     f"{h['tp']} True Positive, {h['fp']} False Positive ({fp_pct}% FP)")
    else:
        lines.append("Prior verdicts for this SID: FIRST OCCURRENCE (no history)")

    lines.append(f"Event volume: {ctx['total_events']} events aggregated into this incident")
    lines.append("")

    # IOCs
    if ctx["iocs"]:
        lines.append("Indicators of Compromise:")
        for i in ctx["iocs"]:
            marker = " [primary]" if i.get("is_primary") else ""
            lines.append(f"  - {i['ioc_type']}: {i['ioc_value']} (freq={i.get('frequency', 1)}){marker}")
        lines.append("")

    # Recent events
    if ctx["sample_events"]:
        lines.append("Sample recent events:")
        for ev in ctx["sample_events"][:3]:
            lines.append(f"  - {ev.get('timestamp', '')[:19]}  {ev.get('src_ip', '')} -> {ev.get('dest_ip', '')}  {ev.get('event_summary', '')[:100]}")
        lines.append("")

    lines.append("Provide your triage verdict as JSON per the schema.")
    return "\n".join(lines)


def _call_ollama(user_prompt, system_prompt=SYSTEM_PROMPT):
    """POST to Ollama /api/chat with a JSON format request."""
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "format": "json",     # force JSON output
        "stream": False,
        "options": {
            "temperature": 0.2,   # low, we want factual & consistent
            "num_predict": 400,
        },
    }
    req = urllib.request.Request(
        OLLAMA_HOST + "/api/chat",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        return {"error": f"Ollama unreachable at {OLLAMA_HOST}: {e}"}
    except Exception as e:
        return {"error": f"Ollama call failed: {e}"}

    content = ((body.get("message") or {}).get("content") or "").strip()
    if not content:
        return {"error": "Empty response from LLM"}
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return {"error": "LLM returned non-JSON output", "raw": content[:500]}


def analyze_incident(incident_id):
    """Public entry point. Returns the LLM verdict dict (or {'error': ...})."""
    ctx = _fetch_incident_context(incident_id)
    if ctx is None:
        return {"error": "Incident not found"}
    prompt = _build_user_prompt(ctx)
    result = _call_ollama(prompt)
    if "error" in result:
        return result
    # Attach the model+prompt hash so the UI can show which model produced it
    result["_model"] = OLLAMA_MODEL
    result["_context_summary"] = {
        "signature_id": ctx["signature_id"],
        "prior_fp_pct": (
            round(ctx["prior_verdicts_for_sid"]["fp"]
                  / ctx["prior_verdicts_for_sid"]["total"] * 100)
            if ctx["prior_verdicts_for_sid"]["total"] > 0 else None
        ),
        "source_external": ctx["source_is_external"],
        "destination_external": ctx["destination_is_external"],
        "total_events": ctx["total_events"],
    }
    return result


def health():
    """Quick check — can we reach Ollama and does the model exist?"""
    try:
        req = urllib.request.Request(OLLAMA_HOST + "/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        models = [m.get("name", "") for m in data.get("models", [])]
        return {
            "ok": True,
            "host": OLLAMA_HOST,
            "installed_models": models,
            "configured_model": OLLAMA_MODEL,
            "model_present": OLLAMA_MODEL in models,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "host": OLLAMA_HOST}
