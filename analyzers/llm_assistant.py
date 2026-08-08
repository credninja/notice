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
_RULE_EXPLAIN_SYSTEM = """You explain Suricata IDS rules to SOC analysts.
Given a rule (or its signature name if the raw text isn't available), respond in JSON:
{
  "purpose": "one-sentence plain-English purpose of the rule",
  "detection_logic": "1-3 sentences on WHAT patterns/conditions trigger it",
  "common_true_positive": "typical malicious scenario that would fire it",
  "common_false_positive": "typical benign scenario that could fire it",
  "tuning_advice": "concrete guidance on how to reduce FPs if noisy (one sentence)"
}

CRITICAL — how Suricata thresholds work (get this right, users will apply your advice):
- 'threshold:type both, track by_src, count N, seconds M;' means: fire an alert only when
  the same source triggers the rule N or more times within an M-second window.
- To REDUCE false positives on a noisy threshold rule:
  * INCREASE count (requires MORE events before firing — less sensitive)
  * DECREASE seconds (shorter window means events must be MORE concentrated — less sensitive)
  * Add source/destination exclusions (e.g. '!$HOME_NET', '![10.1.96.53]') to skip legit sources
  * Narrow the port list or add missing ports to a baseline exclusion (![port1,port2,...])
  * Add flow:established or content: filters to require more specific traffic
- To INCREASE sensitivity (find MORE alerts): DECREASE count or INCREASE seconds.
- NEVER suggest "reduce count and increase seconds" — that combination makes the rule fire MORE, not less.

For rules with a baseline exclusion like ![5601,22,53]:
- If FPs come from a specific legitimate port, ADD that port to the exclusion list.
- If FPs come from a specific legitimate source, add a source exclusion (![10.1.96.53] any -> ...).

Be concise and technical. If the rule reference is missing details, use signature name for context."""


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
