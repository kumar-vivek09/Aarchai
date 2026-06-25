"""Slack + email alert notifications for new critical/high findings."""
from __future__ import annotations
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import os


SLACK_WEBHOOK   = os.getenv("SLACK_WEBHOOK_URL", "")
SMTP_HOST       = os.getenv("SMTP_HOST", "")
SMTP_PORT       = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER       = os.getenv("SMTP_USER", "")
SMTP_PASS       = os.getenv("SMTP_PASS", "")
ALERT_EMAIL_TO  = os.getenv("ALERT_EMAIL_TO", "")


def notify_new_findings(target: str, scan_id: int, new_findings: list):
    """Send alerts for new critical/high findings."""
    critical = [f for f in new_findings if f.get("severity") == "critical"]
    high     = [f for f in new_findings if f.get("severity") == "high"]

    if not critical and not high:
        return  # Only alert on critical/high

    summary = _build_summary(target, scan_id, critical, high)

    if SLACK_WEBHOOK:
        _send_slack(target, scan_id, critical, high, summary)

    if SMTP_HOST and ALERT_EMAIL_TO:
        _send_email(target, scan_id, summary)


def _build_summary(target, scan_id, critical, high) -> str:
    lines = [
        f"Aarchai Alert — New findings on {target} (Scan #{scan_id})",
        f"Critical: {len(critical)}  High: {len(high)}",
        "",
    ]
    for f in (critical + high)[:10]:
        sev = f.get("severity", "").upper()
        lines.append(f"[{sev}] {f.get('title', '')} — {f.get('host', '')}")
    return "
".join(lines)


def _send_slack(target, scan_id, critical, high, summary):
    try:
        colour = "danger" if critical else "warning"
        payload = {
            "attachments": [{
                "color": colour,
                "title": f":rotating_light: Aarchai: {len(critical)} critical, {len(high)} high on {target}",
                "text": summary,
                "footer": f"Scan #{scan_id} | Aarchai",
            }]
        }
        requests.post(SLACK_WEBHOOK, json=payload, timeout=10)
    except Exception as e:
        print(f"[notifier] Slack error: {e}")


def _send_email(target, scan_id, summary):
    try:
        msg = MIMEMultipart()
        msg["From"]    = SMTP_USER
        msg["To"]      = ALERT_EMAIL_TO
        msg["Subject"] = f"[Aarchai Alert] New findings on {target} — Scan #{scan_id}"
        msg.attach(MIMEText(summary, "plain"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as srv:
            srv.starttls()
            srv.login(SMTP_USER, SMTP_PASS)
            srv.send_message(msg)
    except Exception as e:
        print(f"[notifier] Email error: {e}")
