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
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "120"))
# Keep the model resident in Ollama's RAM for this long between calls, so we
# don't pay the model-load penalty on every request. Default matches Ollama's
# own default of 5m but is bumped to 30m so a SOC session that clicks the AI
# every few minutes never hits a cold load.
OLLAMA_KEEP_ALIVE = os.environ.get("OLLAMA_KEEP_ALIVE", "30m")


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


def _call_ollama(user_prompt, system_prompt=SYSTEM_PROMPT,
                 json_mode=True, num_predict=400, temperature=0.2):
    """POST to Ollama /api/chat. If json_mode=True, forces + parses JSON.
    If json_mode=False, returns {"text": <plain text>}.

    Retries on transient network errors and on malformed-JSON responses —
    when json_mode is on the model occasionally emits stray text around the
    JSON block, so we salvage or retry once before returning the error.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "keep_alive": OLLAMA_KEEP_ALIVE,
        "options": {
            "temperature": temperature,
            "num_predict": num_predict,
        },
    }
    if json_mode:
        payload["format"] = "json"

    def _do_request():
        req = urllib.request.Request(
            OLLAMA_HOST + "/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
            return json.loads(resp.read().decode())

    # ── Attempt with one retry on transient failure ──
    last_net_err = None
    body = None
    for attempt in (1, 2):
        try:
            body = _do_request()
            break
        except (urllib.error.URLError, TimeoutError) as e:
            last_net_err = e
            # brief backoff before retry
            import time as _t; _t.sleep(0.5)
        except Exception as e:
            return {"error": f"Ollama call failed: {e}"}
    if body is None:
        return {"error": f"Ollama unreachable at {OLLAMA_HOST}: {last_net_err}"}

    content = ((body.get("message") or {}).get("content") or "").strip()
    if not content:
        return {"error": "Empty response from LLM"}
    if not json_mode:
        return {"text": content}

    # ── JSON parse with salvage + one retry ──
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    # Salvage: pull the biggest {...} substring
    salvaged = _extract_json_block(content)
    if salvaged is not None:
        try:
            return json.loads(salvaged)
        except json.JSONDecodeError:
            pass
    # Retry once — usually clears transient malformed output
    try:
        body2 = _do_request()
        content2 = ((body2.get("message") or {}).get("content") or "").strip()
        if content2:
            try:
                return json.loads(content2)
            except json.JSONDecodeError:
                salvaged2 = _extract_json_block(content2)
                if salvaged2 is not None:
                    try:
                        return json.loads(salvaged2)
                    except json.JSONDecodeError:
                        pass
    except Exception:
        pass
    return {"error": "LLM returned non-JSON output (after retry)", "raw": content[:500]}


def _extract_json_block(text):
    """Return the substring from the first '{' to the matching final '}'."""
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    return text[start:end + 1]


# ═══════════════════════════════════════════════════════════════════════
# Additional LLM helpers for various NOTICE workflows
# Each returns a dict; on failure {"error": "..."}; on success typed data.
# ═══════════════════════════════════════════════════════════════════════

# ── 1. Suricata rule explanation ─────────────────────────────────────
_RULE_EXPLAIN_SYSTEM = """You explain Suricata IDS rules to SOC analysts in plain English.
Given a rule (or its signature name if the raw text isn't available), respond in JSON with just two fields:
{
  "purpose": "one-sentence plain-English purpose — what this rule is meant to catch and why",
  "detection_logic": "1-3 sentences explaining what the rule is actually saying — decode the source/destination, ports, thresholds (count N in M seconds), flow direction, and any content matches into plain English"
}

Be concise and factual. Only describe what the rule literally does — do NOT invent TP/FP scenarios
or tuning advice. If the rule text isn't provided, base your explanation on the signature name."""


def explain_rule(signature_id=None, signature=None, rule_text=None):
    """Explain a Suricata rule. Provide any combination of sid/signature/raw rule text."""
    if not (signature_id or signature or rule_text):
        return {"error": "Provide signature_id, signature name, or rule_text"}
    parts = []
    if signature_id:
        parts.append(f"Signature ID: {signature_id}")
    if signature:
        parts.append(f"Signature name: {signature}")
    if rule_text:
        parts.append(f"Rule source:\n{rule_text[:2000]}")
    prompt = "\n".join(parts) + "\n\nExplain this rule as JSON per the schema."
    result = _call_ollama(prompt, system_prompt=_RULE_EXPLAIN_SYSTEM, num_predict=350)
    if "error" not in result:
        result["_model"] = OLLAMA_MODEL
    return result


# ── 2. Suricata rule generator (plain English -> rule) ───────────────
_RULE_GENERATE_SYSTEM = """You generate Suricata IDS rules from plain-English detection intent.
Given an analyst's description, produce a syntactically valid Suricata rule.
Respond in JSON:
{
  "rule": "the full alert rule as a single line, using sid:9999999; rev:1; (analyst edits SID before deploying)",
  "explanation": "one-sentence explanation of what this rule will catch",
  "caveats": "1-2 sentences on likely FP sources or when this may over-fire"
}
Guidelines:
- Use standard Suricata syntax and variables: $HOME_NET, $EXTERNAL_NET, $HTTP_SERVERS
- Prefer thresholds when the intent implies frequency (threshold:type both, track by_src, count N, seconds M;)
- Set classtype appropriately (attempted-recon, attempted-admin, trojan-activity, etc.)
- Always include msg, classtype, sid (use 9999999 as placeholder), rev
- If the intent is ambiguous, pick the most common interpretation and note it in caveats"""


def generate_rule(description):
    """Generate a Suricata rule from a plain-English description."""
    if not description or not description.strip():
        return {"error": "Description is required"}
    prompt = f"Detection intent: {description.strip()}\n\nProduce the Suricata rule as JSON per the schema."
    result = _call_ollama(prompt, system_prompt=_RULE_GENERATE_SYSTEM, num_predict=400)
    if "error" not in result:
        result["_model"] = OLLAMA_MODEL
    return result


# ── 3. Daily report executive summary ─────────────────────────────────
_EXEC_SUMMARY_SYSTEM = """You are a senior SOC lead writing a daily brief for management.
Given the day's incident statistics, produce a 3-paragraph executive summary
in JSON:
{
  "headline": "one-sentence bottom line for the CISO",
  "operational_summary": "2-3 sentences: what activity happened today",
  "notable_items": "1-2 sentences: any TP incidents needing follow-up, or notable patterns",
  "recommended_focus": "one sentence: what SOC should prioritize tomorrow"
}
Write for a non-technical exec. Avoid jargon. Only cite numbers from the input; do not invent."""


def executive_summary(stats):
    """Generate exec summary for a daily report.
    stats dict expected keys: date, total_closed, true_positives, false_positives,
    by_severity, top_classifications (list of {name, count}), top_sources (list),
    critical_incidents (list of titles).
    """
    lines = [f"Date: {stats.get('date', '')}"]
    lines.append(f"Total incidents closed: {stats.get('total_closed', 0)}")
    lines.append(f"  True positives: {stats.get('true_positives', 0)}")
    lines.append(f"  False positives: {stats.get('false_positives', 0)}")
    if stats.get("by_severity"):
        sev_line = ", ".join(f"{k}={v}" for k, v in stats["by_severity"].items() if v)
        lines.append(f"Severity breakdown: {sev_line}")
    if stats.get("top_classifications"):
        lines.append("Top classifications:")
        for c in stats["top_classifications"][:5]:
            lines.append(f"  - {c.get('name', '')}: {c.get('count', 0)}")
    if stats.get("critical_incidents"):
        lines.append("Notable true-positive incidents:")
        for t in stats["critical_incidents"][:5]:
            lines.append(f"  - {t}")
    prompt = "\n".join(lines) + "\n\nWrite the exec brief as JSON per the schema."
    result = _call_ollama(prompt, system_prompt=_EXEC_SUMMARY_SYSTEM, num_predict=500)
    if "error" not in result:
        result["_model"] = OLLAMA_MODEL
    return result


# ── 4. Auto-drafted closure summary + RCA ─────────────────────────────
_CLOSURE_DRAFT_SYSTEM = """You draft incident closure notes for SOC analysts to review and refine.
Given incident context (metadata, IOCs, events, verdict), produce a draft closure per this JSON:
{
  "summary": "2-3 sentence closure summary — what happened, what was decided",
  "root_cause": "1-2 sentence root cause analysis",
  "actions_taken": "1-2 sentences on containment/eradication steps that were (or should have been) taken",
  "lessons_learned": "1 sentence on what to improve"
}
Assume the analyst will edit. Draft the most likely narrative given the evidence.
- If verdict is 'false_positive', frame around why the alert was benign (misconfiguration, legitimate scanner, expected traffic).
- If verdict is 'true_positive', frame around what the attacker did and how it was stopped.
- If verdict is missing, produce a neutral draft covering the observed activity."""


def draft_closure(incident_id, verdict=None):
    """Draft closure fields for an incident."""
    ctx = _fetch_incident_context(incident_id)
    if ctx is None:
        return {"error": "Incident not found"}
    # If verdict wasn't passed, try to read it from context (won't be there for open incidents)
    lines = [f"Incident: {ctx['title']}"]
    lines.append(f"Signature: {ctx['signature']} (SID {ctx['signature_id']})")
    lines.append(f"Severity: {ctx['severity']}")
    lines.append(f"Verdict decision: {verdict or '(analyst has not chosen yet — draft neutrally)'}")
    lines.append(f"Source: {ctx['source_ip']} ({'external' if ctx['source_is_external'] else 'internal'})")
    if ctx["source_asset"]:
        a = ctx["source_asset"]
        lines.append(f"  Source asset: owner={a.get('owner', '?')}, type={a.get('asset_type', '?')}")
    lines.append(f"Destination: {ctx['destination_ip']} ({'external' if ctx['destination_is_external'] else 'internal'})")
    if ctx["destination_asset"]:
        a = ctx["destination_asset"]
        lines.append(f"  Dest asset: owner={a.get('owner', '?')}, type={a.get('asset_type', '?')}, critical={bool(a.get('business_critical'))}")
    h = ctx["prior_verdicts_for_sid"]
    if h["total"] > 0:
        lines.append(f"Prior verdicts for this SID: {h['tp']} TP / {h['fp']} FP")
    lines.append(f"Event volume: {ctx['total_events']}")
    if ctx["sample_events"]:
        lines.append("Sample events:")
        for ev in ctx["sample_events"][:3]:
            lines.append(f"  - {ev.get('event_summary', '')[:100]}")
    prompt = "\n".join(lines) + "\n\nDraft the closure fields as JSON per the schema."
    result = _call_ollama(prompt, system_prompt=_CLOSURE_DRAFT_SYSTEM, num_predict=500)
    if "error" not in result:
        result["_model"] = OLLAMA_MODEL
    return result


# ── 5. Alert-level triage (lighter than incident triage) ──────────────
_ALERT_TRIAGE_SYSTEM = """You are a SOC analyst rapid-triaging a single alert (not yet an incident).
Given an alert with its signature, source, destination, and prior verdicts for the same SID,
respond in JSON:
{
  "verdict": "likely_true_positive" | "likely_false_positive" | "promote_to_incident",
  "confidence": "low" | "medium" | "high",
  "reasoning": "1-2 sentences",
  "suggested_action": "one concrete verb — 'dismiss', 'monitor', 'promote', 'investigate source', etc."
}
Bias toward "likely_false_positive" if the prior FP rate is >80%.
Bias toward "promote_to_incident" if the signature name contains attack keywords
(brute, exploit, injection, backdoor, c2, reverse_shell) and the source is external."""


def analyze_alert(alert_dict):
    """Rapid triage of a single alert.
    alert_dict expected: {signature_id, signature, src_ip, dest_ip, dest_port,
    severity, category, prior_tp, prior_fp}
    """
    if not alert_dict:
        return {"error": "Alert dict required"}
    lines = []
    lines.append(f"Signature: {alert_dict.get('signature', '')} (SID {alert_dict.get('signature_id', '?')})")
    lines.append(f"Source: {alert_dict.get('src_ip', '?')} -> Destination: {alert_dict.get('dest_ip', '?')}:{alert_dict.get('dest_port', '?')}")
    lines.append(f"Category: {alert_dict.get('category', '?')} · Severity: {alert_dict.get('severity', '?')}")
    src = alert_dict.get("src_ip", "")
    is_ext = not (src.startswith("10.") or src.startswith("172.16.") or src.startswith("192.168.")) if src else False
    lines.append(f"Source is {'EXTERNAL' if is_ext else 'INTERNAL'}")
    tp = alert_dict.get("prior_tp", 0)
    fp = alert_dict.get("prior_fp", 0)
    if tp + fp > 0:
        lines.append(f"Prior verdicts for this SID: {tp} TP / {fp} FP ({round(fp/(tp+fp)*100)}% FP)")
    else:
        lines.append("Prior verdicts for this SID: none (never seen closed)")
    prompt = "\n".join(lines) + "\n\nTriage the alert as JSON per the schema."
    result = _call_ollama(prompt, system_prompt=_ALERT_TRIAGE_SYSTEM, num_predict=300)
    if "error" not in result:
        result["_model"] = OLLAMA_MODEL
    return result


# ── 6. Natural-language search (NL -> filter dict) ────────────────────
_NL_SEARCH_SYSTEM = """You translate an analyst's natural-language query into a JSON filter for
NOTICE's incident search. Respond ONLY with valid JSON per this schema:
{
  "status": "open" | "closed" | null,
  "severity": "critical" | "high" | "medium" | "low" | null,
  "verdict": "true_positive" | "false_positive" | null,
  "assigned_to": "<username>" | null,
  "q": "<free-text substring to search title/signature/IPs>" | null,
  "minutes": <int minutes lookback> | null,
  "explanation": "one sentence explaining what filter you built"
}
Rules:
- If the query mentions "external", "attackers", "internet", set q to include broader match, do not restrict IP
- "last 24 hours" -> minutes: 1440. "last week" -> minutes: 10080. "today" -> minutes: 1440.
- "assigned to me" -> assigned_to: "__me__" (server will substitute the caller)
- If the query mentions a specific IP/CIDR, put it in q
- Any unmentioned field must be null (not empty string)
- Keep q short and specific — a substring, not a full sentence"""


def parse_nl_search(query, current_user=None):
    """Translate a natural-language query into a filter dict."""
    if not query or not query.strip():
        return {"error": "Query required"}
    prompt = f"Analyst query: {query.strip()}\n\nProduce the filter as JSON per the schema."
    result = _call_ollama(prompt, system_prompt=_NL_SEARCH_SYSTEM, num_predict=250)
    if "error" in result:
        return result
    # Substitute __me__ with actual username
    if current_user and result.get("assigned_to") == "__me__":
        result["assigned_to"] = current_user
    result["_model"] = OLLAMA_MODEL
    return result


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


# ═══════════════════════════════════════════════════════════════════════
# SESSION 1 additions — enrichment narrators
# All follow the same pattern: gather context → prompt LLM → return dict
# ═══════════════════════════════════════════════════════════════════════

# ── Dashboard situation report (formerly "morning briefing") ──
_DASH_BRIEFING_SYSTEM = """You are a SOC lead writing a short factual situation report for another analyst.
Given security activity numbers for the last 24 hours, respond in JSON:
{
  "headline": "one-sentence bottom line — what's the current situation",
  "recent_activity": "2-3 sentences describing what happened in the last 24 hours (cite the actual numbers you were given)",
  "current_status": "one sentence on where things stand right now",
  "top_priorities": ["short priority 1", "short priority 2", "short priority 3"]
}

Hard rules:
- Only cite numbers YOU WERE GIVEN in the input. If a number is 0, that's a real observation — don't extrapolate.
- If no top open incidents were listed, say "no notable open incidents" — DO NOT invent incident titles.
- If no signatures were listed, say "no signature patterns to highlight" — DO NOT invent signature names.
- Never claim "no alerts today" unless the input actually shows alerts_last_24h=0.
- Keep it factual and terse. This is scanned in seconds, not read carefully."""


def dashboard_briefing(stats):
    """stats: {alerts_last_24h, open_incidents_total, incidents_closed_tp_24h,
    incidents_closed_fp_24h, top_open_incidents:[{title,severity}], top_signatures:[{name,count}]}"""
    if not stats:
        return {"error": "stats required"}
    lines = []
    lines.append(f"Alerts fired in last 24 hours: {stats.get('alerts_last_24h', 0)}")
    lines.append(f"Currently open incidents (all time): {stats.get('open_incidents_total', 0)}")
    lines.append(f"Incidents closed in last 24 hours: "
                 f"{stats.get('incidents_closed_tp_24h', 0)} true-positive, "
                 f"{stats.get('incidents_closed_fp_24h', 0)} false-positive")
    if stats.get("top_open_incidents"):
        lines.append("Top open incidents right now (by severity):")
        for i in stats["top_open_incidents"][:5]:
            lines.append(f"  - [{i.get('severity', '?')}] {i.get('title', '')[:100]}")
    else:
        lines.append("Top open incidents right now: none")
    if stats.get("top_signatures"):
        lines.append("Top signatures firing in last 24 hours:")
        for s in stats["top_signatures"][:5]:
            lines.append(f"  - {s.get('name', '')[:80]} ({s.get('count', 0)} times)")
    else:
        lines.append("Top signatures firing: none in the window")
    prompt = "\n".join(lines) + "\n\nWrite the situation report as JSON per the schema."
    r = _call_ollama(prompt, system_prompt=_DASH_BRIEFING_SYSTEM, num_predict=400)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


_STATE_OF_SEC_SYSTEM = """You write a plain-English security health check for a non-technical manager.
Given aggregate stats, respond in JSON:
{
  "assessment": "green | yellow | red",
  "summary": "1-2 sentences a non-technical manager can understand. Avoid jargon: no 'alert volume', 'FP suppression', 'traffic light'. Say things like 'things look normal', 'a few issues to keep an eye on', 'active problems that need attention'.",
  "reasoning": "one plain sentence citing the actual numbers — e.g. 'We have 15 open cases and 2 needed real response in the last day.'"
}
Assessment rules:
  green  = everything normal, no confirmed real incidents recently, small open backlog
  yellow = elevated activity OR 1-2 confirmed real incidents OR high-severity backlog
  red    = confirmed real incidents happening now OR attack in progress OR unmanageable backlog

Word "assessment" should be EXACTLY one of: green, yellow, red. Do not add prefixes like "traffic_light —"."""


def state_of_security(stats):
    lines = []
    lines.append(f"Total open incidents: {stats.get('open_incidents', 0)}")
    lines.append(f"  - critical: {stats.get('open_critical', 0)}")
    lines.append(f"  - SLA breached: {stats.get('sla_breached', 0)}")
    lines.append(f"TP incidents last 24h: {stats.get('recent_tp', 0)}")
    lines.append(f"Alerts (last hour): {stats.get('alerts_last_hour', 0)}")
    lines.append(f"Alerts (24h avg baseline): {stats.get('alerts_baseline_hourly', 0)}")
    lines.append(f"Active blocks: {stats.get('active_blocks', 0)}, quarantines: {stats.get('active_quarantines', 0)}")
    prompt = "\n".join(lines) + "\n\nProduce the state-of-security JSON."
    r = _call_ollama(prompt, system_prompt=_STATE_OF_SEC_SYSTEM, num_predict=250)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


_ANOMALY_SYSTEM = """You explain in plain English whether the network is behaving normally right now.
Given the current alert rate and a baseline of what's typical, respond in JSON:
{
  "is_anomalous": true | false,
  "explanation": "2-3 sentences in plain English. Say things like 'alerts are 3x higher than usual' or 'this hour is quieter than normal, which is fine'. Do NOT say 'metric', 'standard deviation', 'baseline', or 'ratio'.",
  "suggested_action": "one sentence — investigate now, keep watching, or nothing to do"
}

Rules:
- If the prompt says 'STATUS: insufficient_history', explain that the system has been collecting for less than an hour so there is nothing to compare against yet — set is_anomalous=false.
- Otherwise mark is_anomalous=true only when the current rate is 2x the typical rate OR higher.
- A current rate that is LOWER than baseline is normal — never anomalous.
- If current=0 and baseline is small (<2/hr), just say the network is quiet."""


def anomaly_narrator(current_metrics, baseline_metrics, hours_of_history=0):
    """current_metrics / baseline_metrics: dicts of metric_name -> number-or-None.
    hours_of_history: how many hours of alert data the DB actually has."""
    cur = current_metrics.get("alerts_per_hour", 0) or 0
    base = baseline_metrics.get("alerts_per_hour")
    lines = []
    if base is None or hours_of_history < 1.5:
        lines.append(f"STATUS: insufficient_history (system has {hours_of_history:.1f} hours of data)")
        lines.append(f"current alerts in the last hour: {cur}")
    else:
        ratio = (cur / base) if base > 0 else (float("inf") if cur > 0 else 0.0)
        ratio_str = "quiet" if base > 0 and cur == 0 else (
            "much higher than usual" if ratio >= 2 else
            "higher than usual" if ratio >= 1.3 else
            "typical" if ratio >= 0.7 else
            "lower than usual")
        lines.append(f"Alerts in the last hour: {cur}")
        lines.append(f"Typical alerts per hour (last 24h avg): {base:.1f}")
        lines.append(f"Ratio: {ratio:.2f}x — {ratio_str}")
        lines.append(f"History available: {hours_of_history:.1f} hours")
    prompt = "\n".join(lines) + "\n\nRespond in JSON per the schema."
    r = _call_ollama(prompt, system_prompt=_ANOMALY_SYSTEM, num_predict=250)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ── IP profile summary (Investigate page) ──
_IP_PROFILE_SYSTEM = """You produce an IP profile summary for a SOC analyst investigating an unknown IP.
Given the IP's activity data, respond in JSON:
{
  "attribution": "one-line best guess: 'developer workstation' / 'file server' / 'IoT camera' / 'known scanner' / 'external attacker' / 'CDN edge' / 'unknown'",
  "confidence": "low" | "medium" | "high",
  "profile": "2-3 sentence plain-English profile — activity patterns, services used, notable behaviors",
  "notable_indicators": ["short bullet 1", "short bullet 2", "short bullet 3"],
  "investigate_next": "one concrete next step for the analyst"
}
Base attribution on:
- If asset is registered with an owner/type, use that
- Volume of connections (heavy volume = server, low = client)
- Ports it connects TO (443/80 = web browsing, 53 = DNS, weird high ports = scanner or C2)
- Ports it listens ON (22 = SSH server, 445 = SMB server, none = client)
- Geographic pattern of external destinations
- Presence in threat intel (VT/AbuseIPDB scores)"""


def profile_ip(ip, ctx):
    """ctx: {is_internal, asset_info, top_dest_ports:[(port,count)], top_dest_ips:[(ip,count)],
    listening_ports:[...], countries_hit:[...], vt_score, abuse_score, tls_ja3s:[...],
    total_flows, active_days, top_signatures:[...]}"""
    lines = [f"IP: {ip} ({'INTERNAL' if ctx.get('is_internal') else 'EXTERNAL'})"]
    a = ctx.get("asset_info")
    if a:
        lines.append(f"Registered asset: owner={a.get('owner', '?')}, type={a.get('asset_type', '?')}, "
                     f"purdue_level={a.get('purdue_level', '?')}, critical={bool(a.get('business_critical'))}")
    lines.append(f"Total flows observed: {ctx.get('total_flows', 0)} over {ctx.get('active_days', '?')} days")
    if ctx.get("top_dest_ports"):
        lines.append("Top destination ports: " + ", ".join(f"{p}({c})" for p, c in ctx["top_dest_ports"][:8]))
    if ctx.get("top_dest_ips"):
        lines.append("Top destination IPs: " + ", ".join(f"{d}({c})" for d, c in ctx["top_dest_ips"][:5]))
    if ctx.get("listening_ports"):
        lines.append("Listening ports (server behaviour): " + ", ".join(str(p) for p in ctx["listening_ports"][:8]))
    if ctx.get("countries_hit"):
        lines.append("Countries connected to: " + ", ".join(ctx["countries_hit"][:8]))
    if ctx.get("vt_score") is not None:
        lines.append(f"VirusTotal score: {ctx['vt_score']}/100")
    if ctx.get("abuse_score") is not None:
        lines.append(f"AbuseIPDB abuse score: {ctx['abuse_score']}/100")
    if ctx.get("top_signatures"):
        lines.append("Alerts involving this IP: " + ", ".join(f"{s[0][:40]} x{s[1]}" for s in ctx["top_signatures"][:5]))
    prompt = "\n".join(lines) + "\n\nProduce the profile JSON."
    r = _call_ollama(prompt, system_prompt=_IP_PROFILE_SYSTEM, num_predict=400)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ── Asset profile summary / behavior change / auto-classify ──
_ASSET_PROFILE_SYSTEM = """You describe an asset's observed network behavior for a SOC analyst.
Given the data provided (and ONLY that data), respond in JSON:
{
  "role_summary": "one short line describing observed role — use generic terms: 'endpoint', 'server', 'infrastructure device', 'external service'. Do NOT invent a specific role like 'analyst workstation', 'IP camera', 'developer laptop'. If registered asset_type is given, use that. Otherwise say 'endpoint' or 'server' based on whether it acts more as a client (heavy outbound) or server (has listening ports).",
  "normal_behavior": "2-3 sentences describing what patterns YOU CAN SEE in the data — top ports, top peers, traffic volume. Do NOT mention OS (Windows/Linux/Mac) unless the data explicitly says so.",
  "recent_changes": "one sentence. If no change-signals were provided, say 'no change signals available'. Do NOT invent changes.",
  "watch_for": "one sentence on what would look unusual given the observed pattern — cite specific ports/behaviors from the data, not generic advice"
}

CRITICAL constraints:
- Do NOT guess the operating system unless the input explicitly says Windows/Linux/Mac.
- Do NOT invent user names, department names, or specific roles.
- Do NOT say 'analyst workstation' — use 'endpoint' if it's a client-like device.
- Only cite ports, peers, and services that appear in the input."""


def profile_asset(ip, ctx):
    """ctx: same shape as profile_ip, plus recent_change_signals if available"""
    lines = [f"Asset: {ip}"]
    a = ctx.get("asset_info") or {}
    if a:
        lines.append(f"Registered: owner={a.get('owner', '?')}, type={a.get('asset_type', '?')}")
    lines.append(f"Total flows: {ctx.get('total_flows', 0)}")
    if ctx.get("listening_ports"):
        lines.append("Listening on: " + ", ".join(str(p) for p in ctx["listening_ports"][:10]))
    if ctx.get("top_dest_ports"):
        lines.append("Outbound to: " + ", ".join(f":{p}({c})" for p, c in ctx["top_dest_ports"][:8]))
    if ctx.get("top_peers"):
        lines.append("Talks to: " + ", ".join(f"{d}({c})" for d, c in ctx["top_peers"][:5]))
    if ctx.get("recent_change_signals"):
        lines.append("Recent change signals: " + str(ctx["recent_change_signals"]))
    if ctx.get("services_detected"):
        lines.append("Detected services: " + ", ".join(ctx["services_detected"]))
    prompt = "\n".join(lines) + "\n\nProduce the asset profile JSON."
    r = _call_ollama(prompt, system_prompt=_ASSET_PROFILE_SYSTEM, num_predict=350)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


_ASSET_CLASSIFY_SYSTEM = """Classify an asset based ONLY on observed traffic evidence. No guessing.
Respond in JSON:
{
  "asset_type": "endpoint | server | infrastructure | scanner | unknown",
  "specific_role": "brief role based on evidence (e.g., 'web server' if listening on 80/443, 'DNS resolver' if handling port 53, 'management server' if MeshCentral/GLPI ports). Say 'unknown' if the data isn't clear.",
  "confidence": "low | medium | high",
  "reasoning": "1-2 sentences citing the specific ports/patterns YOU SAW that led to this classification"
}

CRITICAL constraints:
- Do NOT guess the operating system (Windows/Linux/Mac) unless it's in the input.
- Do NOT invent a role — if listening_ports is empty and outbound traffic is generic web browsing (80/443), just say 'endpoint' with 'client-side browsing' as the role.
- Confidence 'high' requires 2+ strong signals (e.g., listening on 443 AND HTTP User-Agent seen = web server).
- 'infrastructure' = DNS resolvers, DHCP servers, gateway/router-like behavior.
- 'scanner' = ONLY if traffic pattern shows connections to many distinct destinations on the same port(s).
- If in doubt, say 'unknown' with low confidence — better than a wrong guess."""


def auto_classify_asset(ip, ctx):
    lines = [f"Asset IP: {ip}"]
    if ctx.get("listening_ports"):
        lines.append(f"Listening ports: {ctx['listening_ports']}")
    if ctx.get("top_dest_ports"):
        lines.append(f"Outbound ports: {[p for p,_ in ctx['top_dest_ports'][:10]]}")
    lines.append(f"Total flows: {ctx.get('total_flows', 0)}")
    if ctx.get("mac_vendor"):
        lines.append(f"MAC vendor: {ctx['mac_vendor']}")
    if ctx.get("tls_ja3s"):
        lines.append(f"TLS JA3 fingerprints: {ctx['tls_ja3s'][:3]}")
    if ctx.get("user_agents"):
        lines.append(f"HTTP User-Agents: {ctx['user_agents'][:3]}")
    prompt = "\n".join(lines) + "\n\nClassify as JSON."
    r = _call_ollama(prompt, system_prompt=_ASSET_CLASSIFY_SYSTEM, num_predict=250)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ── IOC narrative (Threat Intel page) ──
_IOC_NARRATIVE_SYSTEM = """You produce a threat-intel narrative for an IOC (IP / domain / URL / hash).
Given enrichment data, respond in JSON:
{
  "verdict": "malicious | suspicious | benign | unknown",
  "narrative": "2-3 sentences telling the story — what this IOC is, why it matters, what threat intel says",
  "risk_score": <integer 0-100>,
  "recommended_action": "one concrete action: 'block', 'watchlist', 'monitor', 'dismiss'",
  "reasoning": "one sentence — why this verdict/action given the evidence"
}
Only mark 'malicious' if VT engines >5 flag it, or AbuseIPDB score >75, or on TI feeds.
Mark 'benign' if it's a well-known CDN/cloud provider with clean TI."""


def ioc_narrative(indicator_type, value, enrichment):
    lines = [f"IOC type: {indicator_type}", f"Value: {value}"]
    if enrichment.get("vt"):
        vt = enrichment["vt"]
        lines.append(f"VirusTotal: {vt.get('malicious_engines', 0)}/{vt.get('total_engines', 0)} engines flag it "
                     f"(categories: {vt.get('categories', [])[:5]})")
    if enrichment.get("abuseipdb"):
        ab = enrichment["abuseipdb"]
        lines.append(f"AbuseIPDB: score={ab.get('abuse_score', 0)}, reports={ab.get('total_reports', 0)}, "
                     f"country={ab.get('country_code', '?')}")
    if enrichment.get("geoip"):
        g = enrichment["geoip"]
        lines.append(f"Geo: {g.get('country', '?')}, ISP={g.get('isp', '?')}, org={g.get('org', '?')}")
    if enrichment.get("local_history"):
        lh = enrichment["local_history"]
        lines.append(f"Local history: seen {lh.get('flow_count', 0)} times, "
                     f"peers {lh.get('distinct_peers', 0)}, "
                     f"associated with {lh.get('alert_count', 0)} alerts")
    if enrichment.get("ti_feeds"):
        lines.append(f"On threat feeds: {enrichment['ti_feeds']}")
    prompt = "\n".join(lines) + "\n\nProduce the IOC narrative JSON."
    r = _call_ollama(prompt, system_prompt=_IOC_NARRATIVE_SYSTEM, num_predict=350)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ── Incident similar-finder + playbook + attack chain ──
_SIMILAR_INC_SYSTEM = """Given a current incident and a list of past closed incidents with the same signature,
explain the pattern in JSON:
{
  "pattern_summary": "one sentence describing the recurring pattern",
  "typical_verdict": "how these historically resolve (TP or FP)",
  "recommendation": "one sentence recommendation for the current incident based on history"
}"""


def similar_incidents_narrative(current_incident, past_incidents):
    lines = [f"Current incident: {current_incident.get('title', '')} (SID {current_incident.get('signature_id', '?')})"]
    lines.append(f"Historic closures for same SID: {len(past_incidents)}")
    if past_incidents:
        tp = sum(1 for i in past_incidents if i.get("verdict") == "true_positive")
        fp = sum(1 for i in past_incidents if i.get("verdict") == "false_positive")
        lines.append(f"  TP: {tp}, FP: {fp}")
        # Sample the closure summaries
        summaries = [i.get("closure_summary", "")[:120] for i in past_incidents[:3] if i.get("closure_summary")]
        if summaries:
            lines.append("Sample past closure summaries:")
            for s in summaries:
                lines.append(f"  - {s}")
    prompt = "\n".join(lines) + "\n\nProduce the pattern JSON."
    r = _call_ollama(prompt, system_prompt=_SIMILAR_INC_SYSTEM, num_predict=250)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


_PLAYBOOK_SYSTEM = """You recommend a response playbook for an incident.
Given incident context, respond in JSON:
{
  "playbook_name": "short name for the incident type (e.g., 'SSH Brute Force Response', 'Web Application Attack')",
  "steps": ["step 1 (be concrete: 'block source IP in firewall', 'reset user password', etc.)", "step 2", "step 3", "step 4", "step 5"],
  "priority": "immediate | within_1hr | within_24hr | routine",
  "notes": "1 sentence caveat or context"
}
Base playbook on the signature category (brute force, exploit, C2, exfil, recon, policy)."""


def playbook_recommendation(incident_context):
    lines = [f"Signature: {incident_context.get('signature', '')}",
             f"Severity: {incident_context.get('severity', '')}",
             f"Source: {incident_context.get('src_ip', '')} ({'external' if incident_context.get('source_is_external') else 'internal'})",
             f"Destination: {incident_context.get('dst_ip', '')}"]
    if incident_context.get("dst_asset"):
        lines.append(f"  Destination asset: {incident_context['dst_asset']}")
    if incident_context.get("kill_chain_phase"):
        lines.append(f"Kill-chain phase: {incident_context['kill_chain_phase']}")
    prompt = "\n".join(lines) + "\n\nProduce the playbook JSON."
    r = _call_ollama(prompt, system_prompt=_PLAYBOOK_SYSTEM, num_predict=400)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


_ATTACK_CHAIN_SYSTEM = """You narrate a multi-event security incident as a chronological story.
Given events sorted by time, respond in JSON:
{
  "story": "3-5 sentence narrative of what happened in chronological order",
  "phases_observed": ["Reconnaissance", "Exploitation", "..."],
  "attacker_progression": "one sentence on how far the attacker got"
}
Keep the story factual — cite specific timestamps and SIDs from the events."""


def attack_chain_narrative(events):
    if not events:
        return {"error": "No events to narrate"}
    lines = [f"Total events: {len(events)}", "Timeline:"]
    for ev in events[:20]:  # cap at 20 to keep prompt short
        lines.append(f"  {ev.get('timestamp', '')[:19]}  [{ev.get('sid', '?')}] "
                     f"{ev.get('src_ip', '')} -> {ev.get('dest_ip', '')}  "
                     f"{(ev.get('event_summary', '') or '')[:80]}")
    prompt = "\n".join(lines) + "\n\nProduce the attack-chain narrative JSON."
    r = _call_ollama(prompt, system_prompt=_ATTACK_CHAIN_SYSTEM, num_predict=400)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ══════════════════════════════════════════════════════════════════════
# Session 2 features
# ══════════════════════════════════════════════════════════════════════

# ── Bulk triage suggestion for a cluster of similar alerts ──
_BULK_TRIAGE_SYSTEM = """You are helping a SOC analyst clear a queue of similar alerts.
Given a cluster of alerts that all share the same signature, respond in JSON:
{
  "recommendation": "bulk_close_fp" | "bulk_close_tp" | "bulk_investigate" | "review_individually",
  "confidence": "low" | "medium" | "high",
  "reasoning": "1-2 sentences citing the numbers you were given",
  "why_similar": "one sentence on what makes these a coherent cluster"
}
Rules:
- Recommend bulk_close_fp only if prior FP ratio for this signature is >70% AND source is internal/known.
- Recommend bulk_close_tp only if the source is external AND this is a high-severity/known-exploit signature.
- Otherwise default to review_individually. Never bulk-close on thin evidence."""


def bulk_triage_suggestion(cluster_stats):
    """cluster_stats: {sid, signature, count, src_ips_sample, dst_ips_sample,
       severity, source_is_external, prior_fp_pct, prior_tp_pct}"""
    lines = [
        f"Signature: {cluster_stats.get('signature','?')} (sid={cluster_stats.get('sid','?')})",
        f"Cluster size: {cluster_stats.get('count',0)} alerts",
        f"Severity: {cluster_stats.get('severity','?')}",
        f"Source is external: {cluster_stats.get('source_is_external', False)}",
        f"Prior verdict history: TP={cluster_stats.get('prior_tp_pct',0)}%, FP={cluster_stats.get('prior_fp_pct',0)}%",
        f"Sample source IPs: {', '.join(cluster_stats.get('src_ips_sample', [])[:5])}",
        f"Sample destination IPs: {', '.join(cluster_stats.get('dst_ips_sample', [])[:5])}",
    ]
    prompt = "\n".join(lines) + "\n\nProduce the bulk-triage JSON."
    r = _call_ollama(prompt, system_prompt=_BULK_TRIAGE_SYSTEM, num_predict=250)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ── Alert cluster story: what does this cluster mean? ──
_ALERT_CLUSTER_STORY_SYSTEM = """You explain to a SOC analyst what a cluster of related alerts appears to represent.
Given the cluster's signature, endpoints, and timing, respond in JSON:
{
  "story": "2-3 sentence plain-English description of what this pattern suggests",
  "likely_cause": "one sentence best-guess cause (scanner, misconfigured device, legitimate scan, C2 beacon, etc.)",
  "what_to_check_next": "one concrete verification step"
}
Ground your explanation in the specific IPs / ports / timing. Do not invent details."""


def alert_cluster_story(cluster):
    """cluster: {signature, sid, count, first_seen, last_seen, unique_src_ips,
                 unique_dst_ips, common_dst_port, span_minutes}"""
    lines = [
        f"Signature: {cluster.get('signature','?')} (sid={cluster.get('sid','?')})",
        f"Alerts in cluster: {cluster.get('count',0)}",
        f"First seen: {cluster.get('first_seen','?')}",
        f"Last seen: {cluster.get('last_seen','?')}",
        f"Duration: {cluster.get('span_minutes','?')} minutes",
        f"Unique source IPs: {cluster.get('unique_src_ips',0)}",
        f"Unique destination IPs: {cluster.get('unique_dst_ips',0)}",
        f"Most common destination port: {cluster.get('common_dst_port','?')}",
    ]
    prompt = "\n".join(lines) + "\n\nProduce the cluster-story JSON."
    r = _call_ollama(prompt, system_prompt=_ALERT_CLUSTER_STORY_SYSTEM, num_predict=250)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ── Auto-promote reasoning: why did this alert become an incident? ──
_AUTO_PROMOTE_REASONING_SYSTEM = """You explain WHY an alert was auto-promoted to an incident, in plain English.
Given the alert and the promotion rule that fired, respond in JSON:
{
  "why": "2-3 sentences explaining what triggered promotion (severity + IOC score + burst + phase + critical-asset factors)",
  "should_analyst_prioritise": "yes" | "no" | "maybe",
  "next_step": "one concrete first triage step"
}
Base your explanation on the actual rule factors that were met. Do not invent factors that were not provided."""


def auto_promote_reasoning(alert, rule_hits):
    """alert: dict with severity/signature/src/dst/etc.
       rule_hits: dict of factors that met the promotion rule (e.g. {'severity_ok':True, 'ioc_score':45, 'burst':12, 'critical_asset':True})"""
    lines = [
        f"Alert signature: {alert.get('signature','?')} (sid={alert.get('sid','?')})",
        f"Severity: {alert.get('severity','?')}",
        f"Source: {alert.get('src_ip','?')}, Destination: {alert.get('dest_ip','?')}",
        f"Kill-chain phase: {alert.get('phase','?')}",
        "",
        "Rule factors that were met:",
    ]
    for k, v in (rule_hits or {}).items():
        lines.append(f"  {k}: {v}")
    prompt = "\n".join(lines) + "\n\nProduce the auto-promote reasoning JSON."
    r = _call_ollama(prompt, system_prompt=_AUTO_PROMOTE_REASONING_SYSTEM, num_predict=250)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ── Missing asset finder: which unregistered IPs should be onboarded? ──
_MISSING_ASSET_SYSTEM = """You help a SOC analyst decide which unregistered internal IPs should be added to the asset inventory.
Given a list of active-but-unregistered internal IPs with basic activity stats, respond in JSON:
{
  "high_priority": [{"ip":"...", "why":"one sentence — traffic volume, listening ports, or role hint"}],
  "medium_priority": [{"ip":"...", "why":"..."}],
  "skip_for_now": [{"ip":"...", "why":"why it's low-value to register"}]
}
Rules:
- High priority: IPs with heavy traffic, listening services (SSH/RDP/HTTP), or repeat appearance in alerts.
- Medium priority: IPs with modest steady traffic but no listening services.
- Skip: IPs with a single burst of DHCP-only or one-shot activity.
- Only include IPs from the input. Do not invent any IP addresses."""


def missing_asset_finder(unregistered_ips):
    """unregistered_ips: list of dicts {ip, flow_count, listening_ports, alert_count, days_seen}"""
    if not unregistered_ips:
        return {"high_priority": [], "medium_priority": [], "skip_for_now": [],
                "_note": "no unregistered internal IPs found"}
    lines = ["Unregistered internal IPs seen recently (sorted by activity):"]
    for a in unregistered_ips[:15]:
        lp = ",".join(str(p) for p in a.get("listening_ports", [])[:5]) or "none"
        lines.append(
            f"  {a['ip']}: flows={a.get('flow_count',0)}, "
            f"alerts={a.get('alert_count',0)}, days_seen={a.get('days_seen',0)}, "
            f"listening_ports=[{lp}]"
        )
    prompt = "\n".join(lines) + "\n\nProduce the missing-asset JSON."
    r = _call_ollama(prompt, system_prompt=_MISSING_ASSET_SYSTEM, num_predict=400)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ── Anomaly WHY: root cause hypothesis ──
_ANOMALY_WHY_SYSTEM = """You hypothesize the root cause of a detected anomaly for a SOC analyst.
Given a specific anomaly (DGA, DNS tunnel, beacon, scan, lateral movement, etc.) and the evidence, respond in JSON:
{
  "likely_cause": "one-line best hypothesis (compromise, misconfig, legitimate but noisy tool, tester, etc.)",
  "reasoning": "2-3 sentences explaining the hypothesis using the evidence",
  "evidence_that_supports": ["short bullet 1", "short bullet 2"],
  "evidence_that_contradicts": ["bullet or 'none'"]
}
Ground the hypothesis in the provided IPs / domains / patterns. Do not invent evidence."""


def anomaly_why(anomaly):
    """anomaly: dict with type, endpoint, description, sample_indicators"""
    lines = [
        f"Anomaly type: {anomaly.get('type','?')}",
        f"Endpoint: {anomaly.get('endpoint','?')}",
        f"Description: {anomaly.get('description','?')}",
        f"Sample indicators: {anomaly.get('sample_indicators','?')}",
    ]
    prompt = "\n".join(lines) + "\n\nProduce the anomaly-why JSON."
    r = _call_ollama(prompt, system_prompt=_ANOMALY_WHY_SYSTEM, num_predict=300)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ── Anomaly action recommendation: investigate or dismiss? ──
_ANOMALY_ACTION_SYSTEM = """You help a SOC analyst decide whether an anomaly is worth investigating or can be safely dismissed.
Given the anomaly and any context, respond in JSON:
{
  "action": "investigate_now" | "keep_watching" | "safe_to_dismiss",
  "reasoning": "1-2 sentences explaining the call",
  "if_dismiss_add_exception": true | false,
  "exception_hint": "if the recommendation is dismiss, one line for what suppression rule would remove this noise (e.g. 'suppress DNS anomalies from 10.4.20.21' — else empty string)"
}
Rules:
- investigate_now only when the evidence is strong and the endpoint is not a known service host.
- keep_watching when the pattern is worrying but the volume is low or the source is unclassified.
- safe_to_dismiss when it looks like known-legitimate tooling or a registered service (recursive DNS server, monitoring probe, etc.)."""


def anomaly_action_recommendation(anomaly, endpoint_context):
    """endpoint_context: {is_registered_asset, asset_type, asset_owner, prior_anomalies_dismissed}"""
    lines = [
        f"Anomaly type: {anomaly.get('type','?')}",
        f"Endpoint: {anomaly.get('endpoint','?')}",
        f"Evidence: {anomaly.get('description','?')}",
        f"Endpoint registered as asset: {endpoint_context.get('is_registered_asset', False)}",
        f"Asset type: {endpoint_context.get('asset_type','unknown')}",
        f"Asset owner: {endpoint_context.get('asset_owner','unknown')}",
        f"Prior dismissed anomalies from this endpoint: {endpoint_context.get('prior_anomalies_dismissed', 0)}",
    ]
    prompt = "\n".join(lines) + "\n\nProduce the action recommendation JSON."
    r = _call_ollama(prompt, system_prompt=_ANOMALY_ACTION_SYSTEM, num_predict=250)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ── Session narrator ──
_SESSION_NARRATOR_SYSTEM = """You narrate a network session (a single flow between two IPs) for a SOC analyst.
Given the session metadata, respond in JSON:
{
  "narrative": "2-3 sentence description of what this session likely represents — application, direction, and volume",
  "notable": "one sentence on anything unusual — long duration, huge byte count, off-hours, weird port, etc.",
  "risk_indicator": "low" | "medium" | "high"
}
Only mark high risk when there are clear signs of exfiltration, command-and-control patterns, or scanning."""


def session_narrator(session):
    """session: {src_ip, dst_ip, dst_port, protocol, bytes_toclient, bytes_toserver, duration_sec, app_proto, start_time}"""
    lines = [
        f"Session: {session.get('src_ip','?')} -> {session.get('dst_ip','?')}:{session.get('dst_port','?')}",
        f"Protocol: {session.get('protocol','?')} / app: {session.get('app_proto','?')}",
        f"Started: {session.get('start_time','?')}",
        f"Duration: {session.get('duration_sec','?')} seconds",
        f"Bytes to server: {session.get('bytes_toserver',0)}, to client: {session.get('bytes_toclient',0)}",
    ]
    prompt = "\n".join(lines) + "\n\nProduce the session-narrator JSON."
    r = _call_ollama(prompt, system_prompt=_SESSION_NARRATOR_SYSTEM, num_predict=250)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ── Suricata stats interpreter ──
_SURICATA_STATS_SYSTEM = """You interpret Suricata engine stats for an operator who is not a Suricata expert.
Given the raw counters, respond in JSON:
{
  "health": "healthy" | "degraded" | "unhealthy",
  "summary": "1-2 sentence plain-English overview (packets/sec, drops, memory)",
  "concerns": ["short bullet 1", "short bullet 2"],
  "action_items": ["short bullet 1", "short bullet 2"]
}
Rules:
- Drop % over 1% is 'degraded'; over 5% is 'unhealthy'.
- Memory near cap or ftp/http parser errors trending up are also concerns.
- If nothing is wrong, return empty arrays for concerns and action_items."""


def suricata_stats_interpreter(stats):
    """stats: dict of engine counters (packets, drops, mem, etc.)"""
    lines = ["Suricata engine stats:"]
    for k, v in list(stats.items())[:30]:
        lines.append(f"  {k}: {v}")
    prompt = "\n".join(lines) + "\n\nProduce the interpretation JSON."
    r = _call_ollama(prompt, system_prompt=_SURICATA_STATS_SYSTEM, num_predict=350)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ── MITRE ATT&CK gap analysis ──
_MITRE_GAP_SYSTEM = """You perform a MITRE ATT&CK coverage gap analysis for a SOC's detection rule set.
Given the list of covered techniques and the list of ATT&CK tactics we care about, respond in JSON:
{
  "coverage_summary": "1-2 sentence high-level assessment (X of Y tactics covered)",
  "critical_gaps": [{"tactic":"...","why_matters":"one line"}],
  "recommended_next_rules": [{"technique":"T1234","rule_hint":"one-line rule idea"}]
}
Focus on the tactics that are entirely uncovered or under-covered (only 1 rule). Prioritise Initial Access, Execution, Persistence, Credential Access, Lateral Movement, and Exfiltration."""


def mitre_gap_analysis(covered_techniques, all_tactics):
    """covered_techniques: list of {technique_id, tactic, rule_count}
       all_tactics: list of tactic names we consider important"""
    lines = ["Covered ATT&CK techniques (by rule count):"]
    for t in covered_techniques[:40]:
        lines.append(f"  {t.get('technique_id','?')} ({t.get('tactic','?')}): {t.get('rule_count',0)} rules")
    lines.append("")
    lines.append(f"Tactics we care about: {', '.join(all_tactics)}")
    prompt = "\n".join(lines) + "\n\nProduce the gap analysis JSON."
    r = _call_ollama(prompt, system_prompt=_MITRE_GAP_SYSTEM, num_predict=500)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ── Rule improvement ──
_RULE_IMPROVEMENT_SYSTEM = """You suggest concrete improvements to a Suricata rule based on its recent behaviour.
Given the rule text and its hit stats (TP vs FP ratios, hit volume), respond in JSON:
{
  "improvements": [
    {"change":"one-line rule tweak","why":"one line","how_to_apply":"which rule option to add/change (threshold, content, flowbits, etc.)"}
  ],
  "keep_or_retire": "keep" | "retire" | "keep_but_lower_severity",
  "reasoning": "one paragraph tying the suggestions to the stats"
}
Rules:
- If TP=0 and FP>10, recommend retire or big scoping change.
- If TP:FP is 1:5+ but the rule still fires TPs occasionally, suggest a threshold or content anchor.
- Never suggest changing sid or msg (those are inventory)."""


def rule_improvement(rule_text, hit_stats):
    """hit_stats: {total_hits, tp, fp, avg_hits_per_day, top_src_ips, top_dst_ips}"""
    lines = [
        f"Rule: {rule_text[:400]}",
        f"Total hits: {hit_stats.get('total_hits',0)}",
        f"Verdicts: TP={hit_stats.get('tp',0)}, FP={hit_stats.get('fp',0)}",
        f"Average hits per day: {hit_stats.get('avg_hits_per_day',0)}",
        f"Top source IPs: {', '.join(hit_stats.get('top_src_ips', [])[:5])}",
        f"Top destination IPs: {', '.join(hit_stats.get('top_dst_ips', [])[:5])}",
    ]
    prompt = "\n".join(lines) + "\n\nProduce the improvement JSON."
    r = _call_ollama(prompt, system_prompt=_RULE_IMPROVEMENT_SYSTEM, num_predict=400)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ── Rule health check ──
_RULE_HEALTH_SYSTEM = """You assess the overall health of a Suricata rule set.
Given aggregate stats across the rules, respond in JSON:
{
  "overall_health": "healthy" | "needs_attention" | "poor",
  "summary": "2-3 sentence overview",
  "top_issues": [{"issue":"one line","affected_count":"integer or 'many'"}],
  "recommendations": ["short bullet 1", "short bullet 2", "short bullet 3"]
}
Rules:
- Consider these health signals: many rules with 0 hits (dead rules), many rules with 100% FP (noisy rules), MITRE coverage gaps, rule counts by severity balance."""


def rule_health_check(agg_stats):
    """agg_stats: {total_rules, silent_rules, noisy_fp_rules, by_severity:{critical,high,medium,low},
                   mitre_coverage_pct, last_updated}"""
    lines = [
        f"Total rules: {agg_stats.get('total_rules',0)}",
        f"Silent rules (0 hits in 30d): {agg_stats.get('silent_rules',0)}",
        f"Noisy FP rules (100% FP in last 30d): {agg_stats.get('noisy_fp_rules',0)}",
        f"By severity: {agg_stats.get('by_severity',{})}",
        f"MITRE ATT&CK coverage: {agg_stats.get('mitre_coverage_pct',0)}%",
        f"Rule set last updated: {agg_stats.get('last_updated','unknown')}",
    ]
    prompt = "\n".join(lines) + "\n\nProduce the health check JSON."
    r = _call_ollama(prompt, system_prompt=_RULE_HEALTH_SYSTEM, num_predict=400)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r


# ── Rule dedup finder ──
_RULE_DEDUP_SYSTEM = """You find near-duplicate Suricata rules that a SOC operator could consolidate.
Given a list of rules (sid, msg, protocol, content), respond in JSON:
{
  "duplicate_groups": [
    {"sids":[123,456], "reason":"one sentence why they overlap"}
  ],
  "consolidation_savings": "one line — 'You could remove N rules' or 'No meaningful duplicates found'"
}
Rules:
- Only flag rules that clearly overlap in content/direction/protocol. Do not flag rules that just share a message keyword.
- If unsure, err on side of listing fewer groups. Never invent sids that weren't provided."""


def rule_dedup_finder(rules):
    """rules: list of {sid, msg, protocol, content, action, direction}"""
    if not rules:
        return {"duplicate_groups": [], "consolidation_savings": "no rules to analyse"}
    lines = [f"Rule set ({len(rules)} rules):"]
    for r in rules[:80]:
        lines.append(
            f"  sid={r.get('sid','?')} {r.get('action','alert')} {r.get('protocol','?')} "
            f"{r.get('direction','->')} msg=\"{(r.get('msg','') or '')[:80]}\" "
            f"content=\"{(r.get('content','') or '')[:60]}\""
        )
    prompt = "\n".join(lines) + "\n\nProduce the dedup analysis JSON."
    r = _call_ollama(prompt, system_prompt=_RULE_DEDUP_SYSTEM, num_predict=500)
    if "error" not in r:
        r["_model"] = OLLAMA_MODEL
    return r
