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


def _call_ollama(user_prompt, system_prompt=SYSTEM_PROMPT,
                 json_mode=True, num_predict=400, temperature=0.2):
    """POST to Ollama /api/chat. If json_mode=True, forces + parses JSON.
    If json_mode=False, returns {"text": <plain text>}.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": num_predict,
        },
    }
    if json_mode:
        payload["format"] = "json"
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
    if not json_mode:
        return {"text": content}
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return {"error": "LLM returned non-JSON output", "raw": content[:500]}


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
Given current numbers and a baseline of what's typical, respond in JSON:
{
  "is_anomalous": true | false,
  "explanation": "2-3 sentences in plain English — no jargon like 'metric', 'baseline', 'standard deviation'. Say things like 'alerts are 3x higher than usual', 'this is normal for a weekday afternoon'.",
  "suggested_action": "one sentence — should the analyst investigate, keep watching, or ignore"
}

Rules:
- Mark is_anomalous=true only if a value is roughly 2x its typical rate or higher.
- If either current or baseline is 0, be careful — don't call it anomalous based on math alone.
- If the ratio symbol shows "infx" or "infinite", that means the baseline was 0 — in that case just say "we don't have enough history to compare" instead of calling it anomalous."""


def anomaly_narrator(current_metrics, baseline_metrics):
    lines = ["Current vs baseline metrics:"]
    for k in sorted(set(list(current_metrics.keys()) + list(baseline_metrics.keys()))):
        cv = current_metrics.get(k, 0)
        bv = baseline_metrics.get(k, 0)
        ratio = (cv / bv) if bv else float("inf") if cv else 1
        lines.append(f"  {k}: current={cv}, baseline={bv} ({ratio:.1f}x)")
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
