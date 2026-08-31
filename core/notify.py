"""Alert delivery.

Three independent guards stand between a detection and your desktop, because a
security tool that cries wolf gets switched off and then protects nothing:

1. The pipeline's dedup gate - a recurring condition never reaches this module
   more than once per dedup window.
2. A severity floor - routine LOW/INFO activity is recorded and charted but does
   not interrupt anyone.
3. A hard per-minute ceiling - even a burst of genuinely *distinct* alerts cannot
   flood you. Anything shed here is counted and reported on /api/health, so
   suppression is visible rather than silent.

Sinks are pluggable. Desktop is the only pluggable one; email lives on its own
separate path below (`EmailImmediateDispatcher`) rather than joining the
desktop sink list, and that separation is deliberate: the desktop path's 6/min
cap exists to protect a human from being interrupted too often, but that same
cap must never be the reason a genuine critical breach fails to email someone
who isn't even at the machine. Email gets its own, much more generous safety
cap - one that guards against a runaway bug spamming the mail provider, not
against annoying a human.
"""

import queue
import threading
import time
from collections import deque

import config  # type: ignore
from core.events import Alert, meets_threshold  # type: ignore


def notification_floors() -> tuple[str, dict]:
    """The current (default floor, per-module override) pair.

    One function so the in-process desktop dispatcher and the notifier
    companion's polling endpoint (`/api/notifications/pending`) can never
    silently disagree about what counts as notify-worthy - both call this
    rather than each hardcoding the DUMMY_DATA_NOTIFY_MIN_SEVERITY special case.
    """
    module_floors = {'AUTHLOG': config.DUMMY_DATA_NOTIFY_MIN_SEVERITY} \
        if config.USE_DUMMY_DATA else {}
    return config.NOTIFY_MIN_SEVERITY, module_floors


def meets_notification_floor(module: str, severity: str) -> bool:
    min_severity, module_floors = notification_floors()
    floor = module_floors.get(module, min_severity)
    return meets_threshold(severity, floor)


class NotificationSink:
    """A destination for alerts."""

    name = 'sink'

    def available(self) -> bool:
        return True

    def send(self, alert: Alert) -> None:
        raise NotImplementedError


class DesktopSink(NotificationSink):
    """Windows sound + toast notification.

    Both dependencies are optional and Windows-only. If either is missing the
    sink reports itself unavailable *once* at startup instead of printing a
    failure for every alert, which is how the previous implementation behaved.
    """

    name = 'desktop'

    def __init__(self):
        self._winsound = None
        self._notification = None
        self._reason = None
        try:
            import winsound  # type: ignore
            self._winsound = winsound
        except ImportError:
            self._reason = 'winsound unavailable (non-Windows platform)'
        try:
            from plyer import notification  # type: ignore
            self._notification = notification
        except ImportError:
            self._reason = 'plyer is not installed (pip install plyer)'

    def available(self) -> bool:
        return self._notification is not None

    def unavailable_reason(self) -> str | None:
        return self._reason

    def send(self, alert: Alert) -> None:
        if self._winsound is not None:
            self._winsound.MessageBeep(self._winsound.MB_ICONHAND)
        if self._notification is not None:
            self._notification.notify(
                title=alert.notification_title(),
                message=alert.notification_body(),
                app_name='Mini SOC',
                timeout=10,
            )


class NotificationDispatcher:
    """Delivers alerts to sinks on a background thread.

    Runs off its own queue so that a slow or hung sink - a mail server timing
    out, a toast waiting on the shell - can never stall the database writer that
    handed it the alert.
    """

    def __init__(self, sinks: list[NotificationSink], min_severity: str = 'HIGH',
                 max_per_minute: int = 6, queue_size: int = 500,
                 module_floors: dict | None = None):
        self._sinks = [s for s in sinks if s.available()]
        self._min_severity = min_severity
        self._max_per_minute = max_per_minute
        # Per-module severity floor overrides. Currently used to hold synthetic
        # demo traffic to a stricter floor than real telemetry - see
        # config.DUMMY_DATA_NOTIFY_MIN_SEVERITY.
        self._module_floors = module_floors or {}
        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._recent: deque = deque()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

        self.sent = 0
        self.suppressed_by_severity = 0
        self.suppressed_by_rate = 0
        self.dropped = 0
        self.errors = 0

        for sink in sinks:
            if not sink.available():
                reason = getattr(sink, 'unavailable_reason', lambda: None)()
                print(f'[!] Notification sink "{sink.name}" disabled: {reason or "unavailable"}')

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name='notifier', daemon=True)
        self._thread.start()

    def submit(self, alert: Alert) -> None:
        """Queue an alert for delivery. Never blocks and never raises."""
        if not self._sinks:
            return
        floor = self._module_floors.get(alert.module, self._min_severity)
        if not meets_threshold(alert.severity, floor):
            self.suppressed_by_severity += 1
            return
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            self.dropped += 1

    def _within_rate_limit(self) -> bool:
        now = time.monotonic()
        while self._recent and now - self._recent[0] > 60.0:
            self._recent.popleft()
        if len(self._recent) >= self._max_per_minute:
            return False
        self._recent.append(now)
        return True

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                alert = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if not self._within_rate_limit():
                self.suppressed_by_rate += 1
                continue

            for sink in self._sinks:
                try:
                    sink.send(alert)
                    self.sent += 1
                except Exception as exc:
                    self.errors += 1
                    print(f'[!] Notification sink "{sink.name}" failed: {exc}')

    def stop(self) -> None:
        self._stop.set()

    def stats(self) -> dict:
        return {
            'sinks': [s.name for s in self._sinks],
            'sent': self.sent,
            'suppressed_by_severity': self.suppressed_by_severity,
            'suppressed_by_rate': self.suppressed_by_rate,
            'dropped': self.dropped,
            'errors': self.errors,
            'queue_depth': self._queue.qsize(),
        }


class EmailImmediateDispatcher:
    """Emails critical alerts right away, on its own thread and its own cap.

    Deliberately separate from NotificationDispatcher above - see the module
    docstring. The hourly cap here exists only to stop a misbehaving rule from
    hammering the mail provider (which can get an account rate-limited or
    flagged as sending spam); it is not a UX throttle, so it is set generously
    high rather than tuned for human comfort.
    """

    def __init__(self, min_severity: str = 'CRITICAL', max_per_hour: int = 20,
                 queue_size: int = 200):
        self._min_severity = min_severity
        self._max_per_hour = max_per_hour
        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._recent: deque = deque()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

        self.sent = 0
        self.suppressed_by_severity = 0
        self.suppressed_by_rate = 0
        self.dropped = 0
        self.errors = 0

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name='email-immediate', daemon=True)
        self._thread.start()

    def submit(self, alert: Alert) -> None:
        if not meets_threshold(alert.severity, self._min_severity):
            self.suppressed_by_severity += 1
            return
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            self.dropped += 1

    def _within_rate_limit(self) -> bool:
        now = time.monotonic()
        while self._recent and now - self._recent[0] > 3600.0:
            self._recent.popleft()
        if len(self._recent) >= self._max_per_hour:
            return False
        self._recent.append(now)
        return True

    def _run(self) -> None:
        from core import email_alerts  # local import: avoids a circular import at module load

        while not self._stop.is_set():
            try:
                alert = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if not self._within_rate_limit():
                self.suppressed_by_rate += 1
                continue

            try:
                if email_alerts.send_immediate(alert):
                    self.sent += 1
            except Exception as exc:
                self.errors += 1
                print(f'[!] Immediate email failed: {exc}')

    def stop(self) -> None:
        self._stop.set()

    def stats(self) -> dict:
        return {
            'sent': self.sent,
            'suppressed_by_severity': self.suppressed_by_severity,
            'suppressed_by_rate': self.suppressed_by_rate,
            'dropped': self.dropped,
            'errors': self.errors,
            'queue_depth': self._queue.qsize(),
        }
