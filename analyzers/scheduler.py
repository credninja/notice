"""
Background scheduler for NOTICE scheduled reports.

Runs in a daemon thread. Every 60 seconds it checks the scheduled_reports table
for reports whose next_run has passed, generates the report, emails it to the
configured recipients, and updates last_run / next_run.
"""

import logging
import threading
import time
from datetime import datetime, timedelta

from db import get_db, close_db

log = logging.getLogger("notice.scheduler")

_scheduler_started = False
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# compute_next_run — schedule arithmetic
# ---------------------------------------------------------------------------

def compute_next_run(schedule, time_of_day, day_of_week=1, day_of_month=1):
    """Compute the next run datetime string based on schedule type.

    Args:
        schedule:     'daily', 'weekly', or 'monthly'
        time_of_day:  'HH:MM' string (24-hour)
        day_of_week:  0=Monday .. 6=Sunday (used for weekly)
        day_of_month: 1-28 (used for monthly)

    Returns:
        Datetime string formatted as 'YYYY-MM-DD HH:MM:SS'.
    """
    try:
        hour, minute = (int(x) for x in time_of_day.split(":"))
    except (ValueError, AttributeError):
        hour, minute = 8, 0

    now = datetime.now()

    if schedule == "daily":
        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate.strftime("%Y-%m-%d %H:%M:%S")

    elif schedule == "weekly":
        day_of_week = max(0, min(6, int(day_of_week)))
        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        # Advance to the target weekday
        days_ahead = day_of_week - candidate.weekday()
        if days_ahead < 0 or (days_ahead == 0 and candidate <= now):
            days_ahead += 7
        candidate += timedelta(days=days_ahead)
        return candidate.strftime("%Y-%m-%d %H:%M:%S")

    elif schedule == "monthly":
        day_of_month = max(1, min(28, int(day_of_month)))
        candidate = now.replace(
            day=day_of_month, hour=hour, minute=minute, second=0, microsecond=0
        )
        if candidate <= now:
            # Move to next month
            if candidate.month == 12:
                candidate = candidate.replace(year=candidate.year + 1, month=1)
            else:
                candidate = candidate.replace(month=candidate.month + 1)
        return candidate.strftime("%Y-%m-%d %H:%M:%S")

    else:
        # Fallback: next day at the given time
        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# run_single_report — generate + email one report
# ---------------------------------------------------------------------------

def run_single_report(report_dict):
    """Generate a report and email it to the recipients.

    Args:
        report_dict: a dict from the scheduled_reports table row.

    Returns:
        (success: bool, detail: str)
    """
    from analyzers.alerting import send_email

    report_name = report_dict.get("name", "Scheduled Report")
    recipients_str = report_dict.get("recipients", "")
    recipients = [r.strip() for r in recipients_str.split(",") if r.strip()]
    report_id = report_dict.get("id")

    if not recipients:
        return False, "No recipients configured"

    # Generate the report data
    try:
        from analyzers.report import generate_report as generate_management_report
        report_data = generate_management_report(minutes=1440)
    except Exception as exc:
        log.exception("Failed to generate report '%s'", report_name)
        return False, "Report generation error: {}".format(str(exc))

    # Build a summary HTML email from the report data
    total_alerts = report_data.get("total_alerts", 0) if isinstance(report_data, dict) else 0
    total_flows = report_data.get("total_flows", 0) if isinstance(report_data, dict) else 0
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    subject = "[NOTICE] {} — {}".format(report_name, now_str)
    body_html = (
        "<html><body>"
        "<h2 style='color:#2c3e50;'>NOTICE Scheduled Report</h2>"
        "<p><strong>{name}</strong> &mdash; generated {ts}</p>"
        "<table style='border-collapse:collapse;margin:16px 0;'>"
        "<tr><td style='padding:4px 12px;font-weight:bold;'>Total Alerts:</td>"
        "<td style='padding:4px 12px;'>{alerts}</td></tr>"
        "<tr><td style='padding:4px 12px;font-weight:bold;'>Total Flows:</td>"
        "<td style='padding:4px 12px;'>{flows}</td></tr>"
        "</table>"
        "<p>Log in to the NOTICE dashboard for the full interactive report.</p>"
        "<p style='color:#7f8c8d;font-size:12px;'>Automated report from NOTICE scheduler.</p>"
        "</body></html>"
    ).format(
        name=report_name,
        ts=now_str,
        alerts=total_alerts,
        flows=total_flows,
    )

    # Send to each recipient
    sent_count = 0
    fail_count = 0
    for rcpt in recipients:
        if send_email(rcpt, subject, body_html):
            sent_count += 1
        else:
            fail_count += 1

    # Update last_run and next_run
    schedule = report_dict.get("schedule", "daily")
    time_of_day = report_dict.get("time_of_day", "08:00")
    day_of_week = report_dict.get("day_of_week", 1)
    day_of_month = report_dict.get("day_of_month", 1)
    next_run = compute_next_run(schedule, time_of_day, day_of_week, day_of_month)

    conn = get_db()
    try:
        conn.execute(
            "UPDATE scheduled_reports SET last_run = datetime('now','localtime'), next_run = ? WHERE id = ?",
            (next_run, report_id),
        )
        conn.commit()
    finally:
        close_db(conn)

    detail = "Sent to {}/{} recipients".format(sent_count, sent_count + fail_count)
    if fail_count:
        log.warning("Report '%s': %s", report_name, detail)
    else:
        log.info("Report '%s': %s", report_name, detail)

    return fail_count == 0, detail


# ---------------------------------------------------------------------------
# _scheduler_loop — internal loop that runs in the daemon thread
# ---------------------------------------------------------------------------

def _scheduler_loop():
    """Check for due reports every 60 seconds and execute them."""
    log.info("Scheduler thread started")
    while True:
        try:
            _check_due_reports()
        except Exception:
            log.exception("Scheduler tick error")
        time.sleep(60)


def _check_due_reports():
    """Find all enabled reports whose next_run <= now and run them."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM scheduled_reports "
            "WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= datetime('now','localtime')"
        ).fetchall()
        due = [dict(r) for r in rows]
    finally:
        close_db(conn)

    for report in due:
        log.info("Running due report: '%s' (id=%s)", report.get("name"), report.get("id"))
        try:
            run_single_report(report)
        except Exception:
            log.exception("Failed to run scheduled report id=%s", report.get("id"))


# ---------------------------------------------------------------------------
# start_scheduler — public entry point
# ---------------------------------------------------------------------------

def start_scheduler():
    """Start the background scheduler daemon thread (idempotent)."""
    global _scheduler_started
    with _lock:
        if _scheduler_started:
            return
        _scheduler_started = True

    t = threading.Thread(target=_scheduler_loop, name="notice-scheduler", daemon=True)
    t.start()
    log.info("Background report scheduler started")
