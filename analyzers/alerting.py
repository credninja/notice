"""
Notification engine for NOTICE.

Sends alert/incident notifications via Discord webhook based on configurable
rules stored in the notification_rules table. Supports cooldown periods,
multiple condition types, and logs all attempts to notification_log.

Also retains email support as a fallback when SMTP is configured.
"""

import json
import logging
import os
import re
import smtplib
import time
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.request import Request, urlopen
from urllib.error import URLError

from db import get_db, close_db

log = logging.getLogger("notice.alerting")

# ---------------------------------------------------------------------------
# Discord configuration
# ---------------------------------------------------------------------------
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")

# ---------------------------------------------------------------------------
# SMTP configuration (optional fallback)
# ---------------------------------------------------------------------------
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "notice@localhost")
SMTP_TLS = os.environ.get("SMTP_TLS", "true").lower() in ("true", "1", "yes")

SEV_COLORS = {1: 0xE74C3C, 2: 0xE67E22, 3: 0xF1C40F, 4: 0x3498DB}
SEV_LABELS = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}


# ---------------------------------------------------------------------------
# Discord webhook sender
# ---------------------------------------------------------------------------
def send_discord(webhook_url, embed):
    """Post a Discord embed to a webhook URL. Returns True on success."""
    try:
        if not webhook_url:
            log.warning("No Discord webhook URL configured")
            return False
        payload = json.dumps({"embeds": [embed]}).encode("utf-8")
        req = Request(webhook_url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "NOTICE/1.0")
        resp = urlopen(req, timeout=15)
        code = resp.getcode()
        if code in (200, 204):
            return True
        log.warning("Discord webhook returned %s", code)
        return False
    except Exception:
        log.exception("Failed to send Discord notification")
        return False


def _build_alert_embed(alert_dict, rule_name=""):
    """Build a Discord embed dict for an alert."""
    sig = alert_dict.get("signature") or alert_dict.get("sig") or "Unknown"
    src = alert_dict.get("src_ip", "N/A")
    dst = alert_dict.get("dest_ip", "N/A")
    sev = alert_dict.get("severity", 3)
    ts = alert_dict.get("timestamp", "")
    category = alert_dict.get("category", "")

    try:
        sev_int = int(sev)
    except (TypeError, ValueError):
        sev_int = 3

    return {
        "title": "Alert: {}".format(sig[:200]),
        "color": SEV_COLORS.get(sev_int, 0x95A5A6),
        "fields": [
            {"name": "Severity", "value": SEV_LABELS.get(sev_int, str(sev)), "inline": True},
            {"name": "Source IP", "value": str(src), "inline": True},
            {"name": "Dest IP", "value": str(dst), "inline": True},
            {"name": "Category", "value": str(category) or "N/A", "inline": True},
            {"name": "Rule", "value": str(rule_name) or "—", "inline": True},
            {"name": "Time", "value": str(ts)[:19] or "—", "inline": True},
        ],
        "footer": {"text": "NOTICE Network Security Monitor"},
        "timestamp": datetime.now().isoformat(),
    }


def _build_incident_embed(incident_dict):
    """Build a Discord embed dict for a new incident."""
    title = incident_dict.get("title", "New Incident")
    severity = incident_dict.get("severity", "medium")
    inc_id = incident_dict.get("id", "?")
    attacker = incident_dict.get("attacker_ip", "N/A")
    victim = incident_dict.get("victim_ip", "N/A")
    created = incident_dict.get("created_at", "")

    sev_map = {"critical": 1, "high": 2, "medium": 3, "low": 4}
    sev_int = sev_map.get(str(severity).lower(), 3)

    return {
        "title": "Incident #{} — {}".format(inc_id, title[:180]),
        "color": SEV_COLORS.get(sev_int, 0xE67E22),
        "fields": [
            {"name": "Severity", "value": str(severity).capitalize(), "inline": True},
            {"name": "Attacker", "value": str(attacker), "inline": True},
            {"name": "Victim", "value": str(victim), "inline": True},
            {"name": "Created", "value": str(created)[:19], "inline": True},
        ],
        "footer": {"text": "NOTICE Network Security Monitor"},
        "timestamp": datetime.now().isoformat(),
    }


# ---------------------------------------------------------------------------
# Email sender (fallback)
# ---------------------------------------------------------------------------
def send_email(to, subject, body_html):
    """Send an HTML email. Returns True on success, False on failure."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = to

        plain = re.sub(r"<[^>]+>", "", body_html)
        plain = re.sub(r"\s+", " ", plain).strip()

        msg.attach(MIMEText(plain, "plain", "utf-8"))
        msg.attach(MIMEText(body_html, "html", "utf-8"))

        if not SMTP_HOST:
            log.warning("SMTP_HOST not configured — email to %s suppressed", to)
            return False

        srv = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
        try:
            srv.ehlo()
            if SMTP_TLS:
                srv.starttls()
                srv.ehlo()
            if SMTP_USER and SMTP_PASS:
                srv.login(SMTP_USER, SMTP_PASS)
            srv.sendmail(SMTP_FROM, [to], msg.as_string())
        finally:
            srv.quit()

        log.info("Email sent to %s — %s", to, subject)
        return True

    except Exception:
        log.exception("Failed to send email to %s — %s", to, subject)
        return False


# ---------------------------------------------------------------------------
# Unified send — tries Discord first, falls back to email
# ---------------------------------------------------------------------------
def send_notification(recipient, subject, body_html, embed=None):
    """Send via Discord webhook (if configured) or email.

    `recipient` for Discord rules is ignored (goes to the webhook channel).
    For email rules, `recipient` is the email address.
    Returns (ok, method) tuple.
    """
    if DISCORD_WEBHOOK_URL and embed:
        ok = send_discord(DISCORD_WEBHOOK_URL, embed)
        return ok, "discord"

    if SMTP_HOST:
        ok = send_email(recipient, subject, body_html)
        return ok, "email"

    log.warning("No notification channel configured (set DISCORD_WEBHOOK_URL or SMTP_HOST)")
    return False, "none"


# ---------------------------------------------------------------------------
# Condition evaluation helpers
# ---------------------------------------------------------------------------

def _check_severity_gte(alert, threshold_str):
    try:
        threshold = int(threshold_str)
        severity = int(alert.get("severity", 3))
        return severity <= threshold
    except (TypeError, ValueError):
        return False


def _check_signature_match(alert, pattern):
    sig = alert.get("signature") or alert.get("sig") or ""
    try:
        return bool(re.search(pattern, sig, re.IGNORECASE))
    except re.error:
        log.warning("Invalid regex in notification rule: %s", pattern)
        return False


def _check_asset_alert(alert):
    dest_ip = alert.get("dest_ip", "")
    if not dest_ip:
        return False
    conn = get_db()
    try:
        row = conn.execute("SELECT id FROM assets WHERE ip = ?", (dest_ip,)).fetchone()
        return row is not None
    finally:
        close_db(conn)


def _check_any_critical(alert):
    try:
        return int(alert.get("severity", 3)) == 1
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Cooldown check
# ---------------------------------------------------------------------------

def _cooldown_expired(rule):
    last = rule.get("last_fired_at")
    if not last:
        return True
    try:
        last_dt = datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        try:
            last_dt = datetime.fromisoformat(last)
        except (ValueError, TypeError):
            return True
    cooldown = int(rule.get("cooldown_minutes") or 30)
    return datetime.now() >= last_dt + timedelta(minutes=cooldown)


# ---------------------------------------------------------------------------
# check_and_notify — main entry point for alert-driven notifications
# ---------------------------------------------------------------------------

def check_and_notify(alert_dict):
    """Check an alert against all enabled notification rules.

    For each matching rule whose cooldown has expired, send notification via
    Discord (primary) or email (fallback), update last_fired_at, and log.
    """
    results = []
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM notification_rules WHERE enabled = 1"
        ).fetchall()
        rules = [dict(r) for r in rows]
    finally:
        close_db(conn)

    for rule in rules:
        ctype = rule.get("condition_type", "")
        cvalue = rule.get("condition_value", "")

        match = False
        if ctype == "severity_gte":
            match = _check_severity_gte(alert_dict, cvalue)
        elif ctype == "signature_match":
            match = _check_signature_match(alert_dict, cvalue)
        elif ctype == "asset_alert":
            match = _check_asset_alert(alert_dict)
        elif ctype == "any_critical":
            match = _check_any_critical(alert_dict)
        else:
            continue

        if not match:
            continue

        if not _cooldown_expired(rule):
            continue

        sig = alert_dict.get("signature") or alert_dict.get("sig") or "Unknown"
        sev = alert_dict.get("severity", "?")
        subject = "[NOTICE] Alert: {} (sev {})".format(sig[:80], sev)

        embed = _build_alert_embed(alert_dict, rule.get("name", ""))

        body_html = (
            "<html><body>"
            "<h2 style='color:#c0392b;'>NOTICE Alert Notification</h2>"
            "<table style='border-collapse:collapse;'>"
            "<tr><td style='padding:4px 12px;font-weight:bold;'>Rule:</td>"
            "<td style='padding:4px 12px;'>{rule_name}</td></tr>"
            "<tr><td style='padding:4px 12px;font-weight:bold;'>Signature:</td>"
            "<td style='padding:4px 12px;'>{sig}</td></tr>"
            "<tr><td style='padding:4px 12px;font-weight:bold;'>Severity:</td>"
            "<td style='padding:4px 12px;'>{sev}</td></tr>"
            "<tr><td style='padding:4px 12px;font-weight:bold;'>Source IP:</td>"
            "<td style='padding:4px 12px;'>{src}</td></tr>"
            "<tr><td style='padding:4px 12px;font-weight:bold;'>Dest IP:</td>"
            "<td style='padding:4px 12px;'>{dst}</td></tr>"
            "<tr><td style='padding:4px 12px;font-weight:bold;'>Timestamp:</td>"
            "<td style='padding:4px 12px;'>{ts}</td></tr>"
            "</table>"
            "<p style='color:#7f8c8d;font-size:12px;'>Sent by NOTICE notification engine.</p>"
            "</body></html>"
        ).format(
            rule_name=rule.get("name", ""),
            sig=sig,
            sev=sev,
            src=alert_dict.get("src_ip", "N/A"),
            dst=alert_dict.get("dest_ip", "N/A"),
            ts=alert_dict.get("timestamp", ""),
        )

        recipients = [r.strip() for r in rule.get("recipients", "").split(",") if r.strip()]
        if not recipients:
            recipients = ["discord-channel"]

        for rcpt in recipients:
            ok, method = send_notification(rcpt, subject, body_html, embed)
            status = "sent" if ok else "failed"
            error_msg = "" if ok else "{} delivery failed".format(method)

            conn = get_db()
            try:
                conn.execute(
                    "INSERT INTO notification_log "
                    "(rule_id, rule_name, recipient, subject, body_preview, status, error_message, sent_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now','localtime'))",
                    (
                        rule["id"],
                        rule.get("name", ""),
                        rcpt,
                        subject,
                        body_html[:200],
                        status,
                        error_msg,
                    ),
                )
                conn.commit()
            finally:
                close_db(conn)

            results.append({
                "rule_id": rule["id"],
                "rule_name": rule.get("name", ""),
                "recipient": rcpt,
                "status": status,
                "method": method,
            })

        conn = get_db()
        try:
            conn.execute(
                "UPDATE notification_rules SET last_fired_at = datetime('now','localtime') WHERE id = ?",
                (rule["id"],),
            )
            conn.commit()
        finally:
            close_db(conn)

    return results


# ---------------------------------------------------------------------------
# notify_incident_created
# ---------------------------------------------------------------------------

def notify_incident_created(incident_dict):
    """Send notification for a newly auto-created incident."""
    results = []
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM notification_rules "
            "WHERE enabled = 1 AND condition_type = 'incident_created'"
        ).fetchall()
        rules = [dict(r) for r in rows]
    finally:
        close_db(conn)

    title = incident_dict.get("title", "New Incident")
    severity = incident_dict.get("severity", "medium")
    inc_id = incident_dict.get("id", "?")

    subject = "[NOTICE] Incident #{} — {} ({})".format(inc_id, title[:60], severity)
    embed = _build_incident_embed(incident_dict)

    body_html = (
        "<html><body>"
        "<h2 style='color:#e67e22;'>NOTICE — New Incident Created</h2>"
        "<table style='border-collapse:collapse;'>"
        "<tr><td style='padding:4px 12px;font-weight:bold;'>ID:</td>"
        "<td style='padding:4px 12px;'>#{inc_id}</td></tr>"
        "<tr><td style='padding:4px 12px;font-weight:bold;'>Title:</td>"
        "<td style='padding:4px 12px;'>{title}</td></tr>"
        "<tr><td style='padding:4px 12px;font-weight:bold;'>Severity:</td>"
        "<td style='padding:4px 12px;'>{severity}</td></tr>"
        "<tr><td style='padding:4px 12px;font-weight:bold;'>Attacker:</td>"
        "<td style='padding:4px 12px;'>{attacker}</td></tr>"
        "<tr><td style='padding:4px 12px;font-weight:bold;'>Victim:</td>"
        "<td style='padding:4px 12px;'>{victim}</td></tr>"
        "</table></body></html>"
    ).format(
        inc_id=inc_id,
        title=title,
        severity=severity,
        attacker=incident_dict.get("attacker_ip", "N/A"),
        victim=incident_dict.get("victim_ip", "N/A"),
    )

    for rule in rules:
        if not _cooldown_expired(rule):
            continue

        recipients = [r.strip() for r in rule.get("recipients", "").split(",") if r.strip()]
        if not recipients:
            recipients = ["discord-channel"]

        for rcpt in recipients:
            ok, method = send_notification(rcpt, subject, body_html, embed)
            status = "sent" if ok else "failed"
            error_msg = "" if ok else "{} delivery failed".format(method)

            conn = get_db()
            try:
                conn.execute(
                    "INSERT INTO notification_log "
                    "(rule_id, rule_name, recipient, subject, body_preview, status, error_message, sent_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now','localtime'))",
                    (rule["id"], rule.get("name", ""), rcpt, subject, body_html[:200], status, error_msg),
                )
                conn.commit()
            finally:
                close_db(conn)

            results.append({"rule_id": rule["id"], "recipient": rcpt, "status": status, "method": method})

        conn = get_db()
        try:
            conn.execute(
                "UPDATE notification_rules SET last_fired_at = datetime('now','localtime') WHERE id = ?",
                (rule["id"],),
            )
            conn.commit()
        finally:
            close_db(conn)

    return results


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def send_test_discord(webhook_url=None):
    """Send a test message to Discord. Returns (ok, error_msg)."""
    url = webhook_url or DISCORD_WEBHOOK_URL
    if not url:
        return False, "No Discord webhook URL configured. Set DISCORD_WEBHOOK_URL in .env"
    embed = {
        "title": "NOTICE Test Notification",
        "description": "If you see this, your Discord webhook is working correctly.",
        "color": 0x2ECC71,
        "fields": [
            {"name": "Status", "value": "Connected", "inline": True},
            {"name": "Time", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"), "inline": True},
        ],
        "footer": {"text": "NOTICE Network Security Monitor"},
        "timestamp": datetime.now().isoformat(),
    }
    ok = send_discord(url, embed)
    if ok:
        return True, ""
    return False, "Discord webhook request failed. Check the URL."


# ---------------------------------------------------------------------------
# get_notification_stats
# ---------------------------------------------------------------------------

def get_notification_stats():
    """Return counts of sent/failed/total notifications in the last 24 hours."""
    conn = get_db()
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM notification_log WHERE sent_at >= datetime('now', '-1 day')"
        ).fetchone()[0]
        sent = conn.execute(
            "SELECT COUNT(*) FROM notification_log "
            "WHERE status = 'sent' AND sent_at >= datetime('now', '-1 day')"
        ).fetchone()[0]
        failed = conn.execute(
            "SELECT COUNT(*) FROM notification_log "
            "WHERE status = 'failed' AND sent_at >= datetime('now', '-1 day')"
        ).fetchone()[0]
    finally:
        close_db(conn)

    return {
        "total_24h": total,
        "sent_24h": sent,
        "failed_24h": failed,
        "discord_configured": bool(DISCORD_WEBHOOK_URL),
        "smtp_configured": bool(SMTP_HOST),
    }
