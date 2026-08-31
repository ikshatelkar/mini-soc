"""Email alerts: an immediate message for the worst-tier alerts, plus a
periodic digest of everything else.

Uses only Python's standard library (smtplib + email) - no paid service, no
extra dependency. Two things kept deliberately separate from the popup path:

  * A popup only reaches you if you're at the machine. Email exists
    specifically for when you're not - so a critical alert emails immediately,
    independent of whether a human happened to be looking.
  * Sending one email per alert would just move the original spam problem
    from your desktop into your inbox. Routine severities accumulate into a
    digest instead - "everything that happened since the last email," sent on
    a schedule, not per event.
"""

from __future__ import annotations

import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage

import config  # type: ignore
from core import db  # type: ignore
from core.events import meets_threshold  # type: ignore

DIGEST_CHECKPOINT_NAME = 'email_digest_last_sent'


def is_configured() -> bool:
    return bool(
        config.EMAIL_ENABLED and config.EMAIL_SMTP_HOST and config.EMAIL_USERNAME
        and config.EMAIL_APP_PASSWORD and config.EMAIL_TO
    )


def _send(subject: str, body: str) -> None:
    """Send one email. Raises on failure - callers decide how to log that."""
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = config.EMAIL_USERNAME
    msg['To'] = config.EMAIL_TO
    msg.set_content(body)

    context = ssl.create_default_context()
    # Port 465 is implicit TLS (SMTP_SSL); 587 is plaintext-then-STARTTLS.
    # Supporting both covers Gmail (465) and Outlook/Office365 (587) without
    # asking the user to know which is which.
    if config.EMAIL_SMTP_PORT == 465:
        with smtplib.SMTP_SSL(config.EMAIL_SMTP_HOST, config.EMAIL_SMTP_PORT,
                              context=context, timeout=15) as server:
            server.login(config.EMAIL_USERNAME, config.EMAIL_APP_PASSWORD)
            server.send_message(msg)
    else:
        with smtplib.SMTP(config.EMAIL_SMTP_HOST, config.EMAIL_SMTP_PORT, timeout=15) as server:
            server.starttls(context=context)
            server.login(config.EMAIL_USERNAME, config.EMAIL_APP_PASSWORD)
            server.send_message(msg)


def send_immediate(alert) -> bool:
    """Email a single critical alert right away. Returns True on success."""
    if not is_configured() or not meets_threshold(alert.severity, config.EMAIL_IMMEDIATE_MIN_SEVERITY):
        return False
    origin = f' from {alert.source_ip}' if alert.source_ip else ''
    subject = f'[Mini SOC] {alert.severity}: {alert.alert_type}'
    body = (
        f'{alert.description}\n\n'
        f'Module: {alert.module}\n'
        f'Severity: {alert.severity}\n'
        f'Rule: {alert.rule_id or "n/a"}\n'
        f'ATT&CK technique: {alert.technique or "n/a"}\n'
        f'Source{origin}\n'
        f'Time: {db.utc_iso(alert.timestamp)}\n\n'
        f'This was sent immediately because it is severity {alert.severity} or '
        f'higher, which closes the gap for when you are not at the machine to '
        f'see a desktop popup.\n'
    )
    try:
        _send(subject, body)
        return True
    except Exception as exc:
        print(f'[!] Failed to send immediate email alert: {exc}')
        return False


def _format_digest(alerts: list[dict], window_start: str, window_end: str) -> tuple[str, str]:
    if not alerts:
        subject = '[Mini SOC] All quiet - no new alerts'
        body = (
            f'No new alerts between {window_start} and {window_end}.\n\n'
            f'This is the expected, good state - it means nothing needing your '
            f'attention has happened in this window.\n'
        )
        return subject, body

    critical = sum(1 for a in alerts if a['severity'] == 'CRITICAL')
    high = sum(1 for a in alerts if a['severity'] == 'HIGH')
    subject = f'[Mini SOC] {len(alerts)} alert(s) - {critical} critical, {high} high'

    lines = [
        f'{len(alerts)} alert(s) between {window_start} and {window_end}:',
        '',
    ]
    for a in alerts:
        origin = f' from {a["source_ip"]}' if a.get('source_ip') else ''
        count = f' (x{a["occurrence_count"]})' if a.get('occurrence_count', 1) > 1 else ''
        lines.append(f'[{a["severity"]}] {a["description"]}{origin}{count}')
    lines.append('')
    lines.append('Open the dashboard for full detail and to mark these handled.')
    return subject, '\n'.join(lines)


def send_digest_if_due(conn) -> bool:
    """Send the periodic summary if the interval has elapsed. Returns True if sent."""
    if not is_configured():
        return False

    now = datetime.now(timezone.utc)
    last_sent_iso = db.load_checkpoint(conn, DIGEST_CHECKPOINT_NAME)
    if last_sent_iso:
        last_sent = datetime.fromisoformat(last_sent_iso)
        elapsed_hours = (now - last_sent).total_seconds() / 3600
        if elapsed_hours < config.EMAIL_DIGEST_INTERVAL_HOURS:
            return False
    else:
        # First run: don't immediately dump all history into an email. Start
        # the clock from now, so the first digest covers only what happens next.
        db.save_checkpoint(conn, DIGEST_CHECKPOINT_NAME, db.utc_iso(now))
        return False

    c = conn.cursor()
    c.execute('SELECT * FROM alerts WHERE last_seen >= ? ORDER BY severity, last_seen DESC',
              (last_sent_iso,))
    alerts = [dict(r) for r in c.fetchall()]

    subject, body = _format_digest(alerts, last_sent_iso, db.utc_iso(now))
    try:
        _send(subject, body)
    except Exception as exc:
        print(f'[!] Failed to send digest email: {exc}')
        return False

    db.save_checkpoint(conn, DIGEST_CHECKPOINT_NAME, db.utc_iso(now))
    return True
