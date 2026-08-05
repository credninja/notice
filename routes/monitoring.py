"""
Security Monitoring API — protected assets, rule coverage,
adversary profiling, and cross-asset attack patterns.

Performance: single-pass eve.json scan computes overview + adversaries +
attack outcomes simultaneously, then caches result for 60s.
"""

from collections import defaultdict
from bottle import request, response
from db import get_db, close_db, cache_get, cache_set
from auth import require_auth, require_role
from eve_reader import iter_events, is_internal, is_ipv4
from analyzers.suricata_rules import get_rule_stats, get_rules_for_asset
from analyzers.rule_coverage import get_full_coverage
from analyzers.rule_generator import generate_all_asset_rules, write_rules_to_file
from analyzers.asset_baseline import refresh_and_save, load_baselines
from analyzers.correlation import SIGNATURE_MAP
from analyzers.rule_proposals import generate_proposals


def _count_asset_types(protected_assets):
    """Aggregate the protected-asset list by asset_type for the Monitoring breakdown widget.
    Always returns the canonical type slots (even when zero) so the UI keeps a stable layout."""
    canonical = ["workstation", "server", "router", "iot", "service", "other"]
    counts = {t: 0 for t in canonical}
    for a in protected_assets:
        t = (a.get("asset_type") or "other").strip().lower()
        if t not in counts:
            t = "other"
        counts[t] += 1
    return counts


def register(app):

    @app.get("/api/monitoring/overview")
    def monitoring_overview():
        """Combined overview: assets, rules, adversaries, attack outcomes (single eve.json pass)."""
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"monitoring_combined_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached

        rules = get_rule_stats()

        conn = get_db()
        assets = [dict(r) for r in conn.execute(
            "SELECT * FROM assets WHERE scope='internal' ORDER BY business_critical DESC, ip"
        ).fetchall()]
        verdicts = {}
        for v in conn.execute("SELECT * FROM alert_verdicts").fetchall():
            key = f"{v['signature_id']}_{v['src_ip']}_{v['dest_ip']}"
            verdicts[key] = v["verdict"]
        # Per-asset missed detection (false negative) counts
        missed_by_asset = {}
        for r in conn.execute("SELECT asset_ip, COUNT(*) as c FROM missed_detections GROUP BY asset_ip").fetchall():
            missed_by_asset[r["asset_ip"]] = r["c"]
        # IP reputation lookups for adversary classification
        rep_by_ip = {}
        for r in conn.execute("SELECT * FROM ip_reputation").fetchall():
            rep_by_ip[r["ip"]] = dict(r)
        # Persisted first-seen for cross-window "new" classification
        seen_by_ip = {}
        for r in conn.execute("SELECT * FROM adversary_seen").fetchall():
            seen_by_ip[r["ip"]] = dict(r)
        conn.close()

        asset_set = {a["ip"] for a in assets}
        asset_map = {a["ip"]: a for a in assets}

        # Per-asset alert tracking with full outcome breakdown
        asset_alerts = defaultdict(lambda: {
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "blocked": 0, "true_positive": 0, "false_positive": 0,
            "false_negative": 0, "attempted": 0, "investigating": 0,
            "attackers": set(), "signatures": set(),
        })

        # Per-adversary tracking
        attackers_data = defaultdict(lambda: {
            "ip": "",
            "targets": defaultdict(lambda: {
                "alerts": [], "techniques": set(), "signatures": set(),
                "first_seen": None, "last_seen": None,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            }),
            "total_alerts": 0, "techniques": set(), "signatures": set(),
            "first_seen": None, "last_seen": None, "timeline": [],
        })

        # Global attack outcome counters
        outcome = {
            "total_attempts": 0,
            "successful_breach": 0,
            "blocked_or_dropped": 0,
            "failed_or_unsuccessful": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "investigating": 0,
        }

        # Single pass through eve.json
        for ev in iter_events(event_types={"alert"}, minutes=minutes):
            src = ev.get("src_ip", "")
            dst = ev.get("dest_ip", "")
            if not is_ipv4(src) or not is_ipv4(dst):
                continue

            alert = ev.get("alert", {})
            sev = alert.get("severity", 3)
            sid = alert.get("signature_id", 0)
            sig = alert.get("signature", "")
            action = alert.get("action", "allowed")
            ts = ev.get("timestamp", "")
            sev_key = {1: "critical", 2: "high", 3: "medium"}.get(sev, "low")

            # Determine attacker (external, or internal hitting internal)
            attacker_ip = None
            target_ip = None
            if not is_internal(src) and is_internal(dst):
                attacker_ip = src
                target_ip = dst
            elif is_internal(src) and is_internal(dst) and src != dst:
                attacker_ip = src
                target_ip = dst

            # Asset alert tracking (target must be internal)
            if is_internal(dst):
                a = asset_alerts[dst]
                a["total"] += 1
                a[sev_key] += 1
                a["attackers"].add(src)
                a["signatures"].add(sig[:80])

                # Classify outcome
                vkey = f"{sid}_{src}_{dst}"
                verdict = verdicts.get(vkey, "investigating")

                outcome["total_attempts"] += 1
                if action in ("blocked", "dropped"):
                    a["blocked"] += 1
                    outcome["blocked_or_dropped"] += 1
                elif verdict == "true_positive":
                    a["true_positive"] += 1
                    outcome["successful_breach"] += 1
                elif verdict == "false_positive":
                    a["false_positive"] += 1
                    outcome["false_positives"] += 1
                elif verdict == "false_negative":
                    a["false_negative"] += 1
                    outcome["false_negatives"] += 1
                else:
                    a["attempted"] += 1
                    a["investigating"] += 1
                    outcome["failed_or_unsuccessful"] += 1
                    outcome["investigating"] += 1

            # Adversary profiling
            if attacker_ip:
                # Map to MITRE technique
                technique = ""
                sig_lower = sig.lower()
                for mapping in SIGNATURE_MAP:
                    if mapping["pattern"] in sig_lower:
                        technique = mapping.get("technique_name", "")
                        break

                ad = attackers_data[attacker_ip]
                ad["ip"] = attacker_ip
                ad["total_alerts"] += 1
                ad["techniques"].add(technique or sig[:60])
                ad["signatures"].add(sig[:100])
                if not ad["first_seen"] or ts < ad["first_seen"]:
                    ad["first_seen"] = ts
                if not ad["last_seen"] or ts > ad["last_seen"]:
                    ad["last_seen"] = ts

                t = ad["targets"][target_ip]
                t["severity_counts"][sev_key] += 1
                t["techniques"].add(technique or sig[:60])
                t["signatures"].add(sig[:100])
                if not t["first_seen"] or ts < t["first_seen"]:
                    t["first_seen"] = ts
                if not t["last_seen"] or ts > t["last_seen"]:
                    t["last_seen"] = ts
                if len(t["alerts"]) < 20:
                    t["alerts"].append({
                        "timestamp": ts, "signature": sig, "signature_id": sid,
                        "severity": sev, "technique": technique,
                    })
                if len(ad["timeline"]) < 100:
                    ad["timeline"].append({
                        "timestamp": ts, "target": target_ip,
                        "signature": sig[:80], "severity": sev,
                    })

        # Build asset list
        protected_assets = []
        for asset in assets:
            ip = asset["ip"]
            alerts_data = asset_alerts.get(ip, {})
            total = alerts_data.get("total", 0) if isinstance(alerts_data, dict) else 0

            # Risk score: only critical and high severities count.
            # Medium/low are treated as noise and excluded from the score.
            risk = 0
            risk += alerts_data.get("critical", 0) * 20
            risk += alerts_data.get("high", 0) * 10
            if asset.get("business_critical"):
                risk = int(risk * 1.5)
            risk = min(100, risk)

            # Per-asset rule coverage (uses cached index — fast)
            try:
                ar = get_rules_for_asset(ip)
                rule_count = {"direct": ar.get("direct_count", 0), "inherited": ar.get("inherited_count", 0)}
            except Exception:
                rule_count = {"direct": 0, "inherited": 0}

            # Outcome metrics
            blocked = alerts_data.get("blocked", 0) if isinstance(alerts_data, dict) else 0
            successful = alerts_data.get("true_positive", 0) if isinstance(alerts_data, dict) else 0
            unsuccessful = alerts_data.get("attempted", 0) if isinstance(alerts_data, dict) else 0
            fp = alerts_data.get("false_positive", 0) if isinstance(alerts_data, dict) else 0
            fn = alerts_data.get("false_negative", 0) if isinstance(alerts_data, dict) else 0
            fn += missed_by_asset.get(ip, 0)  # add manually-recorded missed detections

            # Mitigation rate: blocked / (blocked + breach + attempted)
            mitigatable = blocked + successful + unsuccessful
            mitigation_rate = round(blocked / mitigatable * 100, 1) if mitigatable else 0
            # Breach rate: successful / total (excluding FP)
            real_alerts = blocked + successful + unsuccessful
            breach_rate = round(successful / real_alerts * 100, 1) if real_alerts else 0
            # FP rate: fp / total
            fp_rate = round(fp / total * 100, 1) if total else 0

            protected_assets.append({
                "id": asset["id"],
                "ip": ip,
                "owner": asset.get("owner", ""),
                "hostname": asset.get("hostname", ""),
                "asset_type": asset.get("asset_type", ""),
                "department": asset.get("department", ""),
                "business_critical": asset.get("business_critical", 0),
                "total_alerts": total,
                "severity": {
                    "critical": alerts_data.get("critical", 0),
                    "high": alerts_data.get("high", 0),
                    "medium": alerts_data.get("medium", 0),
                    "low": alerts_data.get("low", 0),
                },
                "classification": {
                    "blocked": blocked,
                    "true_positive": successful,
                    "false_positive": fp,
                    "false_negative": fn,
                    "attempted": unsuccessful,
                    "investigating": alerts_data.get("investigating", 0),
                },
                "outcomes": {
                    "successful": successful,
                    "unsuccessful": unsuccessful,
                    "blocked": blocked,
                    "false_positive": fp,
                    "false_negative": fn,
                    "mitigation_rate": mitigation_rate,
                    "breach_rate": breach_rate,
                    "fp_rate": fp_rate,
                },
                "unique_attackers": len(alerts_data.get("attackers", set())),
                "unique_signatures": len(alerts_data.get("signatures", set())),
                "risk_score": risk,
                "rule_count": rule_count,
            })
        protected_assets.sort(key=lambda x: x["risk_score"], reverse=True)

        # Build adversary list
        adversaries = []
        technique_spread = defaultdict(lambda: {"attackers": set(), "targets": set(), "count": 0})

        for ip, data in sorted(attackers_data.items(), key=lambda x: x[1]["total_alerts"], reverse=True):
            targets_list = []
            for tip, tdata in sorted(data["targets"].items(),
                                     key=lambda x: sum(x[1]["severity_counts"].values()),
                                     reverse=True):
                a_info = asset_map.get(tip, {})
                targets_list.append({
                    "ip": tip,
                    "owner": a_info.get("owner", ""),
                    "hostname": a_info.get("hostname", ""),
                    "asset_type": a_info.get("asset_type", ""),
                    "business_critical": a_info.get("business_critical", 0),
                    "alert_count": sum(tdata["severity_counts"].values()),
                    "severity_counts": tdata["severity_counts"],
                    "techniques": list(tdata["techniques"]),
                    "signatures": list(tdata["signatures"])[:10],
                    "first_seen": tdata["first_seen"],
                    "last_seen": tdata["last_seen"],
                    "alerts": tdata["alerts"],
                })

            total = data["total_alerts"]
            target_count = len(data["targets"])
            has_critical = any(t["severity_counts"]["critical"] > 0 for t in targets_list)
            hits_critical_assets = any(t["business_critical"] for t in targets_list)

            if has_critical and target_count >= 3:
                threat_level = "critical"
            elif has_critical or target_count >= 3 or hits_critical_assets:
                threat_level = "high"
            elif total >= 5 or target_count >= 2:
                threat_level = "medium"
            else:
                threat_level = "low"

            # Classify adversary: known / new / unidentified / compromised_insider
            # Authoritative "new" comes from adversary_seen table — true first
            # contact across all scans, not window-relative.
            internal = is_internal(ip)
            rep = rep_by_ip.get(ip, {})
            abuse_score = rep.get("abuse_score", 0) if rep else 0
            seen_record = seen_by_ip.get(ip)

            # Compromised-insider heuristic: an internal IP behaving like an
            # attacker. We use "appears as src in alerts hitting other internal
            # hosts" as the base signal (already filtered into this loop), then
            # add behavioural bars that distinguish a misbehaving insider from
            # ordinary noise:
            #   - hits multiple internal targets (lateral movement signal), OR
            #   - has critical alerts confirmed against it, OR
            #   - shows MITRE techniques associated with later kill-chain phases
            #     (exploitation / installation / C2 / exfil — phases 4-7)
            critical_targets = sum(1 for t in targets_list if t["severity_counts"].get("critical", 0) > 0)
            high_targets = sum(1 for t in targets_list if t["severity_counts"].get("high", 0) > 0)
            late_phase_keywords = {
                "exploit", "rce", "injection", "shell", "persist", "backdoor",
                "implant", "c2", "beacon", "exfil", "ransom", "lateral",
            }
            late_phase_hit = any(
                any(kw in tech.lower() for kw in late_phase_keywords)
                for tech in data["techniques"] if tech
            )
            is_compromised_insider = internal and (
                target_count >= 3
                or critical_targets > 0
                or (high_targets >= 1 and late_phase_hit)
                or late_phase_hit
            )

            if is_compromised_insider:
                classification = "compromised_insider"
                bits = []
                if target_count >= 3: bits.append(f"hit {target_count} internal targets")
                if critical_targets > 0: bits.append(f"{critical_targets} target(s) with critical alerts")
                if late_phase_hit: bits.append("late-phase MITRE techniques observed")
                classification_reason = (
                    "internal host exhibiting attacker behaviour — "
                    + (", ".join(bits) if bits else "lateral movement pattern")
                )
            elif internal:
                classification = "known"
                classification_reason = "internal source (origin within our network)"
            elif rep and (abuse_score > 0 or rep.get("total_reports", 0) > 0 or rep.get("is_tor")):
                classification = "known"
                bits = []
                if abuse_score: bits.append(f"AbuseIPDB {abuse_score}/100")
                if rep.get("is_tor"): bits.append("Tor exit")
                if rep.get("country_code"): bits.append(rep["country_code"])
                classification_reason = "; ".join(bits) or "reputation record"
            elif seen_record is None:
                classification = "new"
                classification_reason = "first contact — never observed attacking before"
            else:
                classification = "unidentified"
                classification_reason = (
                    f"seen since {seen_record['first_seen'][:10]}, "
                    f"{seen_record.get('total_attacks', 0)} prior attacks, no reputation"
                )

            adv_profile = {
                "ip": ip,
                "is_internal": internal,
                "total_alerts": total,
                "target_count": target_count,
                "technique_count": len(data["techniques"] - {""}),
                "techniques": list(data["techniques"] - {""})[:15],
                "unique_signatures": len(data["signatures"]),
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "threat_level": threat_level,
                "classification": classification,
                "classification_reason": classification_reason,
                "abuse_score": abuse_score,
                "country_code": rep.get("country_code", "") if rep else "",
                "is_tor": bool(rep.get("is_tor")) if rep else False,
                "targets": targets_list,
                "timeline": sorted(data["timeline"], key=lambda x: x["timestamp"]),
            }
            adversaries.append(adv_profile)

            # Cross-pattern aggregation
            for tech in data["techniques"]:
                if not tech:
                    continue
                ts = technique_spread[tech]
                ts["attackers"].add(ip)
                for t in targets_list:
                    ts["targets"].add(t["ip"])
                ts["count"] += total

        cross_patterns = []
        for tech, data in sorted(technique_spread.items(), key=lambda x: x[1]["count"], reverse=True):
            cross_patterns.append({
                "technique": tech,
                "attacker_count": len(data["attackers"]),
                "target_count": len(data["targets"]),
                "total_alerts": data["count"],
            })

        # Persist adversary first-seen so future scans can classify "new" vs returning.
        # Idempotent: first_seen is set once and never overwritten; last_seen and
        # target_count only advance. total_attacks intentionally tracks max-per-scan
        # rather than running sum to avoid double-counting on overlapping scans.
        try:
            persist_conn = get_db()
            for adv in adversaries:
                if adv["is_internal"] or not adv["first_seen"]:
                    continue
                ip = adv["ip"]
                first = adv["first_seen"]
                last = adv["last_seen"]
                count = adv["total_alerts"]
                targets = adv["target_count"]
                existing = seen_by_ip.get(ip)
                if existing is None:
                    persist_conn.execute(
                        "INSERT OR IGNORE INTO adversary_seen (ip, first_seen, last_seen, total_attacks, target_count) VALUES (?, ?, ?, ?, ?)",
                        (ip, first, last, count, targets),
                    )
                else:
                    persist_conn.execute(
                        "UPDATE adversary_seen SET "
                        "last_seen = MAX(last_seen, ?), "
                        "total_attacks = MAX(total_attacks, ?), "
                        "target_count = MAX(target_count, ?), "
                        "updated_at = datetime('now','localtime') WHERE ip = ?",
                        (last, count, targets, ip),
                    )
            persist_conn.commit()
            persist_conn.close()
        except Exception:
            # Persistence failure should never break the live view
            pass

        # Cache the full adversary blob separately so /api/monitoring/adversaries
        # can serve it without re-scanning. The overview drops it to keep the
        # default response small (was ~490 KB, now ~25 KB on a 24h window).
        adversaries_cache = {
            "adversaries": adversaries[:50],
            "cross_patterns": cross_patterns[:20],
            "summary": {
                "total_adversaries": len(adversaries),
                "internal_adversaries": sum(1 for p in adversaries if p["is_internal"]),
                "external_adversaries": sum(1 for p in adversaries if not p["is_internal"]),
                "critical_threat": sum(1 for p in adversaries if p["threat_level"] == "critical"),
                "high_threat": sum(1 for p in adversaries if p["threat_level"] == "high"),
                "unique_techniques": len(cross_patterns),
                "known_adversaries": sum(1 for p in adversaries if p["classification"] == "known"),
                "new_adversaries": sum(1 for p in adversaries if p["classification"] == "new"),
                "unidentified_adversaries": sum(1 for p in adversaries if p["classification"] == "unidentified"),
                "compromised_insiders": sum(1 for p in adversaries if p["classification"] == "compromised_insider"),
            },
        }
        cache_set(f"monitoring_adversaries_{minutes}", adversaries_cache, ttl=60)

        result = {
            "assets": protected_assets,
            "outcomes": outcome,
            "rules": {
                "total_active": rules["total_active"],
                "total_disabled": rules["total_disabled"],
                "general_rules": rules["general_rules"],
                "asset_specific_rules": rules["asset_specific_rules"],
                "custom_rules": rules["custom_rules"],
                "et_pro_rules": rules["et_pro_rules"],
                "by_action": rules["rules_by_action"],
                "by_service": rules["rules_by_service"],
                "by_category": rules["rules_by_category"],
            },
            "summary": {
                "total_assets": len(protected_assets),
                "assets_with_alerts": sum(1 for a in protected_assets if a["total_alerts"] > 0),
                "critical_assets": sum(1 for a in protected_assets if a["business_critical"]),
                "total_alerts": sum(a["total_alerts"] for a in protected_assets),
                "asset_types": _count_asset_types(protected_assets),
                "total_adversaries": len(adversaries),
                "external_adversaries": sum(1 for p in adversaries if not p["is_internal"]),
                "internal_adversaries": sum(1 for p in adversaries if p["is_internal"]),
                "critical_threat_actors": sum(1 for p in adversaries if p["threat_level"] == "critical"),
                "known_adversaries": sum(1 for p in adversaries if p["classification"] == "known"),
                "new_adversaries": sum(1 for p in adversaries if p["classification"] == "new"),
                "unidentified_adversaries": sum(1 for p in adversaries if p["classification"] == "unidentified"),
                "compromised_insiders": sum(1 for p in adversaries if p["classification"] == "compromised_insider"),
            },
        }
        cache_set(cache_key, result, ttl=60)
        return result

    @app.get("/api/monitoring/asset/<ip>")
    def asset_detail(ip):
        """Detailed security view for a specific asset."""
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"asset_detail_{ip}_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached

        conn = get_db()
        asset_row = conn.execute("SELECT * FROM assets WHERE ip = ?", (ip,)).fetchone()
        verdicts = {}
        for v in conn.execute("SELECT * FROM alert_verdicts").fetchall():
            key = f"{v['signature_id']}_{v['src_ip']}_{v['dest_ip']}"
            verdicts[key] = {"verdict": v["verdict"], "notes": v["analyst_notes"]}
        # Manually-recorded missed detections (false negatives) for this asset
        missed_rows = conn.execute(
            "SELECT * FROM missed_detections WHERE asset_ip = ? ORDER BY discovered_at DESC", (ip,)
        ).fetchall()
        missed_detections = [dict(r) for r in missed_rows]
        conn.close()

        asset = dict(asset_row) if asset_row else {"ip": ip, "owner": "", "hostname": ""}
        rules = get_rules_for_asset(ip)

        alerts = []
        attackers = defaultdict(lambda: {"count": 0, "signatures": set(), "first": None, "last": None})
        for ev in iter_events(event_types={"alert"}, minutes=minutes, dest_ip=ip):
            src = ev.get("src_ip", "")
            alert_data = ev.get("alert", {})
            sid = alert_data.get("signature_id", 0)
            sig = alert_data.get("signature", "")
            sev = alert_data.get("severity", 3)
            ts = ev.get("timestamp", "")
            action = alert_data.get("action", "allowed")

            vkey = f"{sid}_{src}_{ip}"
            verdict_info = verdicts.get(vkey, {})
            verdict = verdict_info.get("verdict", "investigating")

            if action in ("blocked", "dropped"):
                status = "blocked"
            elif verdict == "true_positive":
                status = "breach"
            elif verdict == "false_positive":
                status = "false_positive"
            elif verdict == "false_negative":
                status = "false_negative"
            else:
                status = "attempted"

            alerts.append({
                "timestamp": ts, "signature": sig, "signature_id": sid,
                "severity": sev, "attacker": src, "action": action, "status": status,
                "mitigated": action in ("blocked", "dropped") or verdict == "false_positive",
            })

            a = attackers[src]
            a["count"] += 1
            a["signatures"].add(sig[:80])
            if not a["first"] or ts < a["first"]:
                a["first"] = ts
            if not a["last"] or ts > a["last"]:
                a["last"] = ts

        # Per-attacker classification breakdown
        for ev in iter_events(event_types={"alert"}, minutes=minutes, dest_ip=ip):
            pass  # already iterated above in alerts collection
        attacker_class = defaultdict(lambda: {"blocked": 0, "breach": 0, "attempted": 0, "false_positive": 0, "false_negative": 0})
        for a in alerts:
            attacker_class[a["attacker"]][a["status"]] = attacker_class[a["attacker"]].get(a["status"], 0) + 1

        attacker_list = []
        for aip, data in sorted(attackers.items(), key=lambda x: x[1]["count"], reverse=True):
            cls = attacker_class.get(aip, {})
            attacker_list.append({
                "ip": aip, "is_internal": is_internal(aip),
                "alert_count": data["count"], "unique_signatures": len(data["signatures"]),
                "techniques": list(data["signatures"])[:5],
                "first_seen": data["first"], "last_seen": data["last"],
                "blocked": cls.get("blocked", 0),
                "breach": cls.get("breach", 0),
                "attempted": cls.get("attempted", 0),
                "false_positive": cls.get("false_positive", 0),
                "false_negative": cls.get("false_negative", 0),
            })

        # Outcome metrics
        blocked = sum(1 for a in alerts if a["status"] == "blocked")
        breach = sum(1 for a in alerts if a["status"] == "breach")
        fp = sum(1 for a in alerts if a["status"] == "false_positive")
        attempted = sum(1 for a in alerts if a["status"] == "attempted")
        fn_alerts = sum(1 for a in alerts if a["status"] == "false_negative")
        fn_total = fn_alerts + len(missed_detections)
        total = len(alerts)
        real_alerts = blocked + breach + attempted
        mitigation_rate = round(blocked / real_alerts * 100, 1) if real_alerts else 0
        breach_rate = round(breach / real_alerts * 100, 1) if real_alerts else 0
        fp_rate = round(fp / total * 100, 1) if total else 0

        result = {
            "asset": asset,
            "rules": {
                "direct": [{"sid": r["sid"], "msg": r["msg"], "category": r.get("category", ""),
                            "dest_port": r.get("dest_port", "")} for r in rules["direct_rules"]],
                "direct_count": rules["direct_count"],
                "inherited_count": rules["inherited_count"],
            },
            "alerts": alerts[:200],
            "total_alerts": len(alerts),
            "attackers": attacker_list,
            "classification": {
                "blocked": blocked,
                "breach": breach,
                "false_positive": fp,
                "false_negative": fn_total,
                "attempted": attempted,
                "mitigated": sum(1 for a in alerts if a["mitigated"]),
            },
            "outcomes": {
                "successful_attacks": breach,
                "unsuccessful_attacks": attempted,
                "blocked_attacks": blocked,
                "false_positives": fp,
                "false_negatives": fn_total,
                "mitigation_rate": mitigation_rate,
                "breach_rate": breach_rate,
                "fp_rate": fp_rate,
            },
            "missed_detections": missed_detections,
        }
        cache_set(cache_key, result, ttl=120)
        return result

    @app.get("/api/monitoring/adversaries")
    def adversaries_endpoint():
        """Full adversary blob (timelines, signatures, targets) — fetched lazily by UI when Adversaries sub-tab opens."""
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cached = cache_get(f"monitoring_adversaries_{minutes}")
        if cached:
            return cached
        # Cache miss — trigger an overview build to populate both caches, then return.
        monitoring_overview()
        return cache_get(f"monitoring_adversaries_{minutes}") or {"adversaries": [], "cross_patterns": [], "summary": {}}

    @app.get("/api/monitoring/killchain")
    def killchain_endpoint():
        """Lockheed Martin Cyber Kill Chain view: alerts bucketed into 7 phases."""
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"killchain_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached

        # 7 LM kill-chain phases. Phase 2 (Weaponization) is rarely visible
        # at the network layer — the IDS sees Delivery onward. We expose all 7
        # to communicate the model; empty phases are still meaningful (no signal).
        PHASES = [
            {"id": 1, "name": "Reconnaissance",         "desc": "Probing, scanning, info gathering"},
            {"id": 2, "name": "Weaponization",          "desc": "Coupling exploit with payload (offline; rarely visible on wire)"},
            {"id": 3, "name": "Delivery",               "desc": "Phishing, malicious email, drive-by, USB"},
            {"id": 4, "name": "Exploitation",           "desc": "Exploit triggers — RCE, injection, vulnerability use"},
            {"id": 5, "name": "Installation",           "desc": "Malware install, persistence mechanisms"},
            {"id": 6, "name": "Command & Control",      "desc": "Beaconing, C2 channel established"},
            {"id": 7, "name": "Actions on Objectives",  "desc": "Exfiltration, destruction, lateral spread, impact"},
        ]
        phase_data = {p["id"]: {
            "alerts": 0,
            "techniques": defaultdict(int),
            "attackers": set(),
            "targets": set(),
            "signatures": defaultdict(int),
            "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        } for p in PHASES}
        unmapped = 0

        for ev in iter_events(event_types={"alert"}, minutes=minutes):
            sig = ev.get("alert", {}).get("signature", "")
            sev = ev.get("alert", {}).get("severity", 3)
            sev_key = {1: "critical", 2: "high", 3: "medium"}.get(sev, "low")
            src = ev.get("src_ip", "")
            dst = ev.get("dest_ip", "")
            sig_lower = sig.lower()

            matched = False
            for mapping in SIGNATURE_MAP:
                if mapping["pattern"] in sig_lower:
                    phase_id = mapping.get("phase", 0)
                    if phase_id in phase_data:
                        d = phase_data[phase_id]
                        d["alerts"] += 1
                        d["severity"][sev_key] += 1
                        tech = mapping.get("technique_name") or sig[:60]
                        d["techniques"][tech] += 1
                        d["signatures"][sig[:100]] += 1
                        if is_ipv4(src):
                            d["attackers"].add(src)
                        if is_ipv4(dst):
                            d["targets"].add(dst)
                        matched = True
                    break
            if not matched:
                unmapped += 1

        # Build serializable phase output
        phases_out = []
        for p in PHASES:
            d = phase_data[p["id"]]
            top_techniques = sorted(d["techniques"].items(), key=lambda x: -x[1])[:5]
            top_signatures = sorted(d["signatures"].items(), key=lambda x: -x[1])[:5]
            phases_out.append({
                "id": p["id"], "name": p["name"], "desc": p["desc"],
                "alerts": d["alerts"],
                "severity": d["severity"],
                "attackers": sorted(d["attackers"]),
                "attacker_count": len(d["attackers"]),
                "targets": sorted(d["targets"]),
                "target_count": len(d["targets"]),
                "top_techniques": [{"name": t, "count": c} for t, c in top_techniques],
                "top_signatures": [{"name": s, "count": c} for s, c in top_signatures],
            })

        deepest = max((p["id"] for p in phases_out if p["alerts"] > 0), default=0)
        total = sum(p["alerts"] for p in phases_out)

        result = {
            "phases": phases_out,
            "summary": {
                "total_mapped": total,
                "total_unmapped": unmapped,
                "active_phases": sum(1 for p in phases_out if p["alerts"] > 0),
                "deepest_phase_reached": deepest,
                "deepest_phase_name": next((p["name"] for p in phases_out if p["id"] == deepest), "None"),
            },
        }
        cache_set(cache_key, result, ttl=120)
        return result

    @app.get("/api/monitoring/proposals")
    def proposals_endpoint():
        """Auto-generated rule and mapping proposals derived from observed traffic."""
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"rule_proposals_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        data = generate_proposals(minutes=minutes)
        cache_set(cache_key, data, ttl=300)
        return data

    @app.get("/api/monitoring/rules")
    def rule_stats_endpoint():
        cached = cache_get("rule_stats")
        if cached:
            return cached
        data = get_rule_stats()
        cache_set("rule_stats", data, ttl=600)
        return data

    @app.post("/api/monitoring/regenerate-rules")
    def regenerate_rules():
        """Generate asset-specific rules from the asset DB and write to local.rules."""
        result = write_rules_to_file()
        # Clear caches
        from db import get_db as _get_db
        conn = _get_db()
        conn.execute("DELETE FROM cache WHERE key LIKE 'monitoring_combined_%' OR key LIKE 'rule_stats' OR key LIKE 'asset_detail_%'")
        conn.commit()
        conn.close()
        return result

    @app.get("/api/monitoring/preview-rules")
    def preview_rules():
        """Preview what rules would be generated without writing."""
        content, stats = generate_all_asset_rules()
        return {"preview": content, "stats": stats}

    @app.post("/api/monitoring/missed-detection")
    def record_missed_detection():
        """Record a missed detection (false negative) for an asset."""
        data = request.json or {}
        asset_ip = (data.get("asset_ip") or "").strip()
        description = (data.get("description") or "").strip()
        if not asset_ip or not description:
            response.status = 400
            return {"error": "asset_ip and description required"}
        conn = get_db()
        conn.execute(
            """INSERT INTO missed_detections (asset_ip, attacker_ip, description, severity, notes)
               VALUES (?, ?, ?, ?, ?)""",
            (asset_ip, data.get("attacker_ip", ""), description,
             data.get("severity", "high"), data.get("notes", "")),
        )
        conn.commit()
        # Invalidate caches
        conn.execute("DELETE FROM cache WHERE key LIKE 'monitoring_%' OR key LIKE 'asset_detail_%'")
        conn.commit()
        conn.close()
        response.status = 201
        return {"ok": True}

    @app.delete("/api/monitoring/missed-detection/<mid:int>")
    def delete_missed_detection(mid):
        conn = get_db()
        conn.execute("DELETE FROM missed_detections WHERE id = ?", (mid,))
        conn.execute("DELETE FROM cache WHERE key LIKE 'monitoring_%' OR key LIKE 'asset_detail_%'")
        conn.commit()
        conn.close()
        return {"ok": True}

    @app.post("/api/monitoring/refresh-baseline")
    def refresh_baseline_endpoint():
        """Recompute behavioral baselines for all assets. Slow but cached."""
        try:
            minutes = int(request.json.get("minutes", 10080)) if request.json else 10080
        except Exception:
            minutes = 10080
        result = refresh_and_save(minutes=minutes)
        return result

    @app.get("/api/monitoring/baseline")
    def get_baselines_endpoint():
        """Return all stored baselines."""
        return {"baselines": load_baselines()}

    @app.get("/api/monitoring/baseline/<ip>")
    def get_baseline_for_ip(ip):
        b = load_baselines().get(ip)
        if not b:
            response.status = 404
            return {"error": "No baseline for this asset. Run /api/monitoring/refresh-baseline first."}
        return b

    @app.get("/api/monitoring/rule-coverage")
    def rule_coverage_full():
        """Comprehensive rule coverage analysis across all rule files."""
        cache_key = "rule_coverage_full"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = get_full_coverage()
        cache_set(cache_key, result, ttl=300)
        return result

    @app.get("/api/monitoring/rule-analytics")
    def rule_analytics():
        """Live rule analytics — triggered rules, never-triggered, noisy, etc."""
        minutes = int(request.query.get("minutes", 1440)) or 1440
        cache_key = f"rule_analytics_{minutes}"
        cached = cache_get(cache_key)
        if cached:
            return cached
        result = _build_rule_analytics(minutes)
        cache_set(cache_key, result, ttl=30)
        return result

    @app.get("/api/monitoring/rule-text/<sid:int>")
    def rule_text_endpoint(sid):
        """Return the full rule text for a given SID."""
        import os, re
        rules_dir = os.environ.get("SURICATA_RULES_DIR", "/var/lib/suricata/rules")
        re_sid = re.compile(r"sid:\s*" + str(sid) + r"\s*;")
        try:
            for fn in sorted(os.listdir(rules_dir)):
                if not fn.endswith(".rules"):
                    continue
                with open(os.path.join(rules_dir, fn), "r", errors="ignore") as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped.startswith("#"):
                            stripped = stripped.lstrip("# ")
                        if re_sid.search(stripped):
                            return {"sid": sid, "file": fn, "rule": stripped}
        except Exception:
            pass
        response.status = 404
        return {"error": f"Rule SID {sid} not found"}

    @app.delete("/api/monitoring/rule/<sid:int>")
    @require_auth
    @require_role("admin")
    def delete_rule(sid):
        """Disable (comment out) a rule by SID in its rule file."""
        import os, re
        rules_dir = os.environ.get("SURICATA_RULES_DIR", "/var/lib/suricata/rules")
        re_sid = re.compile(r"sid:\s*" + str(sid) + r"\s*;")
        found = False
        try:
            for fn in sorted(os.listdir(rules_dir)):
                if not fn.endswith(".rules"):
                    continue
                fpath = os.path.join(rules_dir, fn)
                lines = []
                modified = False
                with open(fpath, "r", errors="ignore") as f:
                    for line in f:
                        if not line.strip().startswith("#") and re_sid.search(line):
                            lines.append("# " + line)
                            modified = True
                            found = True
                        else:
                            lines.append(line)
                if modified:
                    with open(fpath, "w") as f:
                        f.writelines(lines)
            if found:
                conn = get_db()
                conn.execute("DELETE FROM cache WHERE key LIKE 'rule_%' OR key LIKE 'monitoring_%'")
                conn.commit()
                close_db(conn)
                return {"ok": True, "sid": sid, "action": "disabled"}
        except Exception as e:
            response.status = 500
            return {"error": str(e)}
        response.status = 404
        return {"error": f"Active rule SID {sid} not found"}


def _build_rule_analytics(minutes):
    """Cross-reference active rules with triggered alerts from eve.json."""
    import os
    import re

    rules_dir = os.environ.get("SURICATA_RULES_DIR", "/var/lib/suricata/rules")
    re_sid = re.compile(r"sid:\s*(\d+)")
    re_msg = re.compile(r'msg:"([^"]+)"')
    re_cls = re.compile(r"classtype:\s*(\S+?);")

    rule_index = {}
    deprecated_sids = set()
    disabled_rules = []

    try:
        for fn in sorted(os.listdir(rules_dir)):
            if not fn.endswith(".rules"):
                continue
            with open(os.path.join(rules_dir, fn), "r", errors="ignore") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    is_disabled = stripped.startswith("#")
                    inner = stripped.lstrip("# ") if is_disabled else stripped
                    if not inner.startswith(("alert ", "drop ", "reject ", "pass ")):
                        continue
                    sid_m = re_sid.search(inner)
                    if not sid_m:
                        continue
                    sid = int(sid_m.group(1))
                    msg_m = re_msg.search(inner)
                    msg = msg_m.group(1) if msg_m else ""
                    cls_m = re_cls.search(inner)
                    cls = cls_m.group(1) if cls_m else ""
                    action = inner.split()[0]

                    if is_disabled:
                        disabled_rules.append({
                            "sid": sid, "msg": msg, "file": fn,
                            "classtype": cls, "action": action,
                        })
                        if "DELETED" in msg or "deprecated" in msg.lower():
                            deprecated_sids.add(sid)
                    else:
                        rule_index[sid] = {
                            "sid": sid, "msg": msg, "file": fn,
                            "classtype": cls, "action": action,
                            "triggers": 0, "first_seen": "", "last_seen": "",
                            "src_ips": set(), "dst_ips": set(),
                        }
    except Exception:
        pass

    total_alerts = 0
    trigger_counts = defaultdict(int)
    sig_to_sid = {}

    for ev in iter_events(event_types={"alert"}, minutes=minutes):
        alert = ev.get("alert", {})
        sid = alert.get("signature_id", 0)
        sig = alert.get("signature", "")
        ts = ev.get("timestamp", "")
        if not sid:
            continue

        total_alerts += 1
        trigger_counts[sid] += 1
        sig_to_sid[sig] = sid

        r = rule_index.get(sid)
        if r:
            r["triggers"] += 1
            if not r["first_seen"] or ts < r["first_seen"]:
                r["first_seen"] = ts
            if not r["last_seen"] or ts > r["last_seen"]:
                r["last_seen"] = ts
            src = ev.get("src_ip", "")
            dst = ev.get("dest_ip", "")
            if src and len(r["src_ips"]) < 50:
                r["src_ips"].add(src)
            if dst and len(r["dst_ips"]) < 50:
                r["dst_ips"].add(dst)

    triggered = []
    never_triggered = []
    for sid, r in rule_index.items():
        entry = {
            "sid": r["sid"], "msg": r["msg"], "file": r["file"],
            "classtype": r["classtype"], "action": r["action"],
            "triggers": r["triggers"],
            "first_seen": r["first_seen"][:19].replace("T", " ") if r["first_seen"] else "",
            "last_seen": r["last_seen"][:19].replace("T", " ") if r["last_seen"] else "",
            "unique_sources": len(r["src_ips"]),
            "unique_destinations": len(r["dst_ips"]),
        }
        if r["triggers"] > 0:
            triggered.append(entry)
        else:
            never_triggered.append(entry)

    triggered.sort(key=lambda x: -x["triggers"])
    never_triggered.sort(key=lambda x: x["sid"])

    noisy_threshold = max(total_alerts * 0.02, 10)
    noisy = [r for r in triggered if r["triggers"] >= noisy_threshold]

    dup_map = defaultdict(list)
    for r in triggered:
        key = r["msg"].lower().strip()
        dup_map[key].append(r)
    duplicates = []
    for msg, rules in dup_map.items():
        if len(rules) > 1:
            duplicates.append({
                "msg": rules[0]["msg"],
                "sids": [r["sid"] for r in rules],
                "files": list({r["file"] for r in rules}),
                "total_triggers": sum(r["triggers"] for r in rules),
            })

    deprecated_active = [r for r in triggered if r["sid"] in deprecated_sids]
    deprecated_disabled = [r for r in disabled_rules if r["sid"] in deprecated_sids]

    return {
        "minutes": minutes,
        "total_active_rules": len(rule_index),
        "total_disabled_rules": len(disabled_rules),
        "total_alerts": total_alerts,
        "total_triggered_rules": len(triggered),
        "total_never_triggered": len(never_triggered),
        "trigger_rate": round(len(triggered) / len(rule_index) * 100, 1) if rule_index else 0,
        "top_triggered": triggered[:30],
        "noisy_rules": noisy[:20],
        "never_triggered": never_triggered[:100],
        "duplicates": duplicates[:20],
        "deprecated_active": deprecated_active[:20],
        "deprecated_disabled_count": len(deprecated_disabled),
        "disabled_sample": disabled_rules[:50],
    }
