"""Notifier companion - the piece that actually shows you a popup.

WHY THIS IS A SEPARATE PROGRAM FROM THE SERVICE
-------------------------------------------------
Once Mini SOC's engine runs as a real Windows Service (service.py), it is not
allowed to draw anything on your screen. Windows Services run in "Session 0",
and Windows has forbidden services from showing UI there since Vista - a
deliberate, permanent anti-malware rule, not a bug to route around. So the
popup has to come from somewhere else: a small, separate program running in
your own login session, which is exactly what this is.

This is the same shape every real antivirus uses: a silent background engine
plus a small notification companion that lives in your session. The engine
(the service) does the actual watching; this does the actual telling you.

HOW IT WORKS
-------------------------------------------------
Polls the dashboard's own API every few seconds for alerts newer than the last
one it already showed you. The server (see app.py's /api/notifications/pending)
already decides what counts as notify-worthy using the exact same rule the
engine itself uses - so this script stays completely dumb about thresholds by
design; it can never drift out of sync with what the engine considers urgent.

A burst of several new alerts at once becomes ONE combined popup rather than
one each - the same anti-spam principle applied everywhere else in this tool,
just enforced here instead of centrally, since this process owns its own
display cadence.

Runs with no console window when launched via pythonw.exe (what the autostart
installer sets up) rather than python.exe.
"""

import json
import os
import time
import urllib.error
import urllib.request

import config  # type: ignore

STATE_FILE = os.path.join(config.BASE_DIR, 'notifier_state.json')
POLL_INTERVAL_SECONDS = 5
BATCH_THRESHOLD = 3  # more than this many new alerts in one poll -> one combined popup

SEVERITY_RANK = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}


def _dashboard_url() -> str:
    return f'http://{config.WEB_HOST}:{config.WEB_PORT}'


def _load_last_seen_id() -> int:
    try:
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            return int(json.load(f).get('last_seen_id', 0))
    except (OSError, ValueError, json.JSONDecodeError):
        return 0


def _save_last_seen_id(value: int) -> None:
    try:
        with open(STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump({'last_seen_id': value}, f)
    except OSError as exc:
        print(f'[!] Could not persist notifier state: {exc}')


def _poll(since_id: int) -> dict | None:
    """Ask the dashboard for anything new. Returns None if it's unreachable
    (service still starting, or momentarily restarting) - handled by backing
    off and trying again, not by giving up."""
    url = f'{_dashboard_url()}/api/notifications/pending?since_id={since_id}'
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def _show_popup(title: str, message: str) -> None:
    try:
        import winsound  # type: ignore
        winsound.MessageBeep(winsound.MB_ICONHAND)
    except Exception:
        pass  # non-Windows or sound device unavailable - the toast still matters
    try:
        from plyer import notification  # type: ignore
        notification.notify(title=title, message=message, app_name='Mini SOC', timeout=10)
    except Exception as exc:
        print(f'[!] Failed to show notification: {exc}')


def _deliver(alerts: list[dict]) -> None:
    if not alerts:
        return
    if len(alerts) > BATCH_THRESHOLD:
        worst = max(alerts, key=lambda a: SEVERITY_RANK.get(a.get('severity'), 0))
        _show_popup(
            f'Mini SOC: {len(alerts)} new alerts',
            f'Most severe: {worst["description"][:100]}\nOpen the dashboard for the rest.',
        )
        return
    for alert in alerts:
        _show_popup(f'Mini SOC: {alert["severity"]}', alert['description'][:200])


def main() -> None:
    last_seen = _load_last_seen_id()
    print(f'[*] Mini SOC notifier watching {_dashboard_url()} (resuming from id {last_seen})')

    consecutive_failures = 0
    while True:
        result = _poll(last_seen)

        if result is None:
            consecutive_failures += 1
            # Back off the more consecutive failures pile up, capped at a
            # minute - avoids hammering a dashboard that is mid-restart while
            # still noticing quickly once it's back.
            time.sleep(min(POLL_INTERVAL_SECONDS * consecutive_failures, 60))
            continue
        consecutive_failures = 0

        _deliver(result.get('alerts', []))

        max_id = result.get('max_id', last_seen)
        if max_id != last_seen:
            last_seen = max_id
            _save_last_seen_id(last_seen)

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == '__main__':
    main()
