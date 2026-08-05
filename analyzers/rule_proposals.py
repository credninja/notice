"""
Rule Proposal Engine.

Mines observed signals (unmapped alert signatures, anomalies, hot ports)
and surfaces concrete detection improvements: kill-chain mappings to add,
IDS rules to consider, policy rules to enable.

Proposals are read-only suggestions for an analyst — nothing is auto-applied.
"""

from collections import defaultdict
from eve_reader import iter_events, is_internal, is_ipv4
from analyzers.correlation import SIGNATURE_MAP


# Source ports of "well-known" services we don't propose blocking on
WELL_KNOWN_PORTS = {
    20, 21, 22, 25, 53, 67, 68, 80, 110, 123, 143, 161, 162,
    389, 443, 465, 587, 631, 636, 993, 995, 1433, 1521, 3306,
    3389, 5060, 5061, 5432, 5900, 8080, 8443, 27017,
}


def _guess_kill_chain_phase(signature):
    """Heuristic: pick a likely kill-chain phase from signature text."""
    s = signature.lower()
    rules = [
        ((1, "Reconnaissance"), ["scan", "recon", "enum", "probe", "discovery", "fingerprint", "directory listing"]),
        ((3, "Delivery"), ["phish", "malicious attachment", "dropper", "deliver", "macro"]),
        ((4, "Exploitation"), ["exploit", "rce", "injection", "overflow", "deserialization", "shellshock", "log4j", "shell upload"]),
        ((5, "Installation"), ["persist", "backdoor", "implant", "service install", "registry run", "scheduled task"]),
        ((6, "Command & Control"), ["c2", "c&c", "beacon", "cobaltstrike", "metasploit", "callback", "rat ", "tunnel"]),
        ((7, "Actions on Objectives"), ["exfil", "data leak", "encrypt", "ransom", "wiper", "destructive", "cred dump"]),
    ]
    for (phase_id, phase_name), keywords in rules:
        if any(k in s for k in keywords):
            return {"phase": phase_id, "phase_name": phase_name}
    return {"phase": 0, "phase_name": "Unclassified"}


def _unmapped_signature_proposals(minutes, unmapped=None):
    """Find alert signatures with no SIGNATURE_MAP entry — propose mapping them.
    If `unmapped` is supplied as a dict {signature: {"count": int, "sid": int}},
    we skip the eve.json scan entirely. The daily report uses this to avoid a
    redundant alert pass."""
    if unmapped is not None:
        sig_counts = {sig: info["count"] for sig, info in unmapped.items()}
        sig_seen_ids = {sig: info.get("sid", 0) for sig, info in unmapped.items()}
    else:
        sig_counts = defaultdict(int)
        sig_seen_ids = {}
        for ev in iter_events(event_types={"alert"}, minutes=minutes):
            alert = ev.get("alert", {})
            sig = alert.get("signature", "")
            sid = alert.get("signature_id", 0)
            if not sig:
                continue
            sig_lower = sig.lower()
            if any(m["pattern"] in sig_lower for m in SIGNATURE_MAP):
                continue
            sig_counts[sig] += 1
            if sig not in sig_seen_ids:
                sig_seen_ids[sig] = sid

    out = []
    for sig, count in sorted(sig_counts.items(), key=lambda x: -x[1]):
        if count < 3:
            continue
        if len(out) >= 15:
            break
        guess = _guess_kill_chain_phase(sig)
        # Pattern: a short distinctive substring that wouldn't false-match other alerts
        words = sig.lower().split()
        pattern_candidate = " ".join(words[:4]) if len(words) >= 4 else sig.lower()
        out.append({
            "id": f"map:{sig_seen_ids.get(sig, 0)}",
            "type": "kill_chain_mapping",
            "title": f"Map signature → kill-chain phase",
            "subject": sig,
            "rationale": (
                f"This signature fired {count} times but isn't in the kill-chain map, "
                f"so its alerts are excluded from the Kill Chain view. Adding it lets "
                f"the dashboard correctly attribute these alerts to a phase."
            ),
            "evidence": {
                "occurrences": count,
                "sid": sig_seen_ids.get(sig, 0),
                "sample_signature": sig,
            },
            "proposed_change": {
                "where": "analyzers/correlation.py SIGNATURE_MAP",
                "snippet": (
                    f'{{"pattern": "{pattern_candidate[:40]}", "phase": {guess["phase"]}, '
                    f'"phase_name": "{guess["phase_name"]}", "tactic": "", "technique": ""}}'
                ),
                "phase_guess": guess,
            },
            "severity": "high" if count >= 100 else "medium" if count >= 25 else "low",
            "confidence": "medium" if guess["phase"] != 0 else "low",
        })
    return out


def _anomaly_to_rule_proposals(minutes, anom=None):
    """Translate observed anomalies (with no companion alert rule) into IDS rule proposals.
    Optional `anom` lets callers pass in pre-computed detect_anomalies() output to avoid
    a redundant eve.json scan (the daily report uses this)."""
    if anom is None:
        from analyzers.anomaly import detect_anomalies
        anom = detect_anomalies(minutes=minutes)
    proposals = []

    # Deprecated TLS (1.0 / 1.1)
    tls_list = anom.get("deprecated_tls", []) or []
    if len(tls_list) >= 2:
        sample_ips = sorted({t.get("src_ip", "") for t in tls_list[:5] if t.get("src_ip")})
        proposals.append({
            "id": "rule:tls-deprecated",
            "type": "ids_rule",
            "title": "Alert on deprecated TLS (1.0 / 1.1)",
            "subject": "TLS protocol downgrade",
            "rationale": (
                f"{len(tls_list)} TLS sessions used TLS 1.0 or 1.1 within the window. "
                f"These versions are deprecated and indicate either misconfigured clients "
                f"or downgrade attempts. There is no detection rule alerting on this today."
            ),
            "evidence": {"occurrences": len(tls_list), "sample_sources": sample_ips},
            "proposed_change": {
                "where": "IDS local rules file",
                "snippet": (
                    'alert tls $HOME_NET any -> any any '
                    '(msg:"NOTICE PROPOSAL Deprecated TLS Version"; '
                    'tls.version:1.0; classtype:policy-violation; sid:9100001; rev:1;)\n'
                    'alert tls $HOME_NET any -> any any '
                    '(msg:"NOTICE PROPOSAL Deprecated TLS Version"; '
                    'tls.version:1.1; classtype:policy-violation; sid:9100002; rev:1;)'
                ),
            },
            "severity": "medium",
            "confidence": "high",
        })

    # Nmap scanning observed via SSH client banner
    nmap_list = anom.get("nmap_scanning", []) or []
    if len(nmap_list) >= 1:
        sample_ips = [n.get("src_ip", "") for n in nmap_list[:5]]
        proposals.append({
            "id": "rule:nmap-ssh-banner",
            "type": "ids_rule",
            "title": "Alert on Nmap SSH client banner",
            "subject": "Nmap reconnaissance",
            "rationale": (
                f"Detected {len(nmap_list)} sources advertising Nmap in their SSH client banner. "
                f"This is high-confidence reconnaissance activity that deserves an explicit alert "
                f"rule rather than relying on flow-pattern detection alone."
            ),
            "evidence": {"occurrences": len(nmap_list), "sample_sources": sample_ips},
            "proposed_change": {
                "where": "IDS local rules file",
                "snippet": (
                    'alert ssh any any -> $HOME_NET any '
                    '(msg:"NOTICE PROPOSAL Nmap SSH client banner"; '
                    'ssh.software; content:"Nmap"; nocase; classtype:network-scan; '
                    'sid:9100010; rev:1;)'
                ),
            },
            "severity": "high",
            "confidence": "high",
        })

    # DNS tunnel suspicion (lots of long subdomains or NXDOMAIN floods)
    dns_susp = anom.get("dns_suspicious", []) or []
    if len(dns_susp) >= 1:
        sample_ips = [d.get("src_ip", "") for d in dns_susp[:5]]
        proposals.append({
            "id": "rule:dns-tunnel-suspect",
            "type": "ids_rule",
            "title": "Alert on suspicious DNS query patterns",
            "subject": "Possible DNS tunneling / DGA",
            "rationale": (
                f"Observed {len(dns_susp)} hosts with anomalous DNS behavior (long subdomains, "
                f"NXDOMAIN floods, or query-rate spikes). These are classic DNS-tunnel and DGA "
                f"indicators that should fire a stateful IDS alert."
            ),
            "evidence": {"occurrences": len(dns_susp), "sample_sources": sample_ips},
            "proposed_change": {
                "where": "IDS local rules file",
                "snippet": (
                    'alert dns $HOME_NET any -> any any '
                    '(msg:"NOTICE PROPOSAL DNS query name >=50 chars (tunnel suspect)"; '
                    'dns.query; content:"."; pcre:"/^[a-z0-9.-]{50,}$/i"; '
                    'classtype:trojan-activity; sid:9100020; rev:1;)'
                ),
            },
            "severity": "high",
            "confidence": "medium",
        })

    return proposals


def _hot_port_proposals(minutes):
    """Find dest ports outside the well-known set with high traffic — propose policy rules."""
    port_stats = defaultdict(lambda: {"flows": 0, "bytes": 0, "internal_dests": set(), "ext_dests": set()})
    for ev in iter_events(event_types={"flow"}, minutes=minutes):
        port = ev.get("dest_port", 0)
        if not port or port in WELL_KNOWN_PORTS or port < 1024:
            continue
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        if not is_ipv4(src) or not is_ipv4(dst):
            continue
        if not is_internal(src) and not is_internal(dst):
            continue
        flow = ev.get("flow", {})
        b = flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
        d = port_stats[port]
        d["flows"] += 1
        d["bytes"] += b
        if is_internal(dst):
            d["internal_dests"].add(dst)
        else:
            d["ext_dests"].add(dst)

    proposals = []
    # Pick top 3 by bytes that aren't already covered by anomalies
    candidates = sorted(port_stats.items(), key=lambda x: -x[1]["bytes"])
    for port, stats in candidates[:3]:
        if stats["flows"] < 20:
            continue
        proposals.append({
            "id": f"policy:port-{port}",
            "type": "policy_rule",
            "title": f"Investigate high-volume traffic on port {port}",
            "subject": f"TCP/UDP {port}",
            "rationale": (
                f"Port {port} carried {stats['bytes']:,} bytes across {stats['flows']} flows. "
                f"It's not a well-known service port; it could be a legitimate internal app, "
                f"an unauthorized service, or covert channel. Decide whether to whitelist or block."
            ),
            "evidence": {
                "port": port,
                "flows": stats["flows"],
                "bytes": stats["bytes"],
                "internal_destinations": len(stats["internal_dests"]),
                "external_destinations": len(stats["ext_dests"]),
            },
            "proposed_change": {
                "where": "Policy Engine (Compliance tab) — new rule",
                "snippet": (
                    f'{{"name": "Port {port} traffic", '
                    f'"rule_type": "unauthorized_service", '
                    f'"config": {{"ports": [{port}]}}, "severity": "medium"}}'
                ),
            },
            "severity": "medium",
            "confidence": "low",
        })
    return proposals


def generate_proposals(minutes=1440, anom=None, unmapped=None, skip_port_scan=False):
    """Generate the full proposal list, sorted with highest-impact first.

    Optional args (used by the daily report to avoid redundant scans):
      anom           - pre-computed detect_anomalies() result
      unmapped       - dict {signature: {"count": int, "sid": int}} from caller
      skip_port_scan - if True, skip _hot_port_proposals (1 flow scan saved)
    """
    out = []
    out.extend(_unmapped_signature_proposals(minutes, unmapped=unmapped))
    out.extend(_anomaly_to_rule_proposals(minutes, anom=anom))
    if not skip_port_scan:
        out.extend(_hot_port_proposals(minutes))

    sev_rank = {"high": 3, "medium": 2, "low": 1}
    conf_rank = {"high": 3, "medium": 2, "low": 1}
    out.sort(
        key=lambda p: (
            -sev_rank.get(p.get("severity", "low"), 0),
            -conf_rank.get(p.get("confidence", "low"), 0),
            -p.get("evidence", {}).get("occurrences", 0),
        )
    )

    by_type = defaultdict(int)
    for p in out:
        by_type[p["type"]] += 1

    return {
        "proposals": out[:50],
        "summary": {
            "total": len(out),
            "by_type": dict(by_type),
            "by_severity": {
                "high": sum(1 for p in out if p["severity"] == "high"),
                "medium": sum(1 for p in out if p["severity"] == "medium"),
                "low": sum(1 for p in out if p["severity"] == "low"),
            },
        },
    }
