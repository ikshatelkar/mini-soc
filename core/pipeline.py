"""The alert pipeline.

Detection modules call `submit()` and return immediately. Everything slow -
database writes, geolocation lookups, desktop toasts - happens on background
workers behind a bounded queue. That separation is the whole point of this
module: previously a detection thread performed an HTTP call and a blocking UI
notification inline, so a single unreachable geolocation provider could stop
detection entirely.

Threads started here:

  writer      drains the alert queue into SQLite, applying the dedup gate
  enrichment  resolves geolocation for pending alerts, rate limited
  retention   prunes alerts past the retention window

Backpressure is explicit. If detection outruns the writer the queue fills and
further alerts are counted as dropped rather than blocking detection or being
silently discarded - a security tool that quietly loses events is worse than no
tool, because you would still trust it.
"""

import queue
import threading
import time
from datetime import datetime, timezone

import config  # type: ignore
from core import db  # type: ignore
from core import email_alerts  # type: ignore
from core.events import Alert  # type: ignore
from core.ip_tracer import RateLimiter, geolocate_ip  # type: ignore
from core.notify import (  # type: ignore
    DesktopSink, EmailImmediateDispatcher, NotificationDispatcher, notification_floors,
)


class AlertPipeline:
    def __init__(self):
        self._queue: queue.Queue = queue.Queue(maxsize=config.ALERT_QUEUE_SIZE)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._started = threading.Event()

        self._geo_limiter = RateLimiter(config.GEO_LOOKUPS_PER_MINUTE)

        sinks = [DesktopSink()] if config.DESKTOP_NOTIFICATIONS_ENABLED else []
        min_severity, module_floors = notification_floors()
        self.notifier = NotificationDispatcher(
            sinks,
            min_severity=min_severity,
            max_per_minute=config.NOTIFY_MAX_PER_MINUTE,
            module_floors=module_floors,
        )

        # Separate path, separate cap - see notify.py's module docstring for why
        # email must not share the desktop popup's rate limiter.
        self.email_immediate = EmailImmediateDispatcher(
            min_severity=config.EMAIL_IMMEDIATE_MIN_SEVERITY,
        ) if email_alerts.is_configured() else None

        # Extension point for Phase 6. Response actions (firewall block, process
        # kill, account disable) register here and receive newly inserted alerts.
        # Deliberately empty for now: the user chose detection-only for this
        # phase, but the seam belongs in the design rather than being retrofitted.
        self._response_handlers: list = []

        self.received = 0
        self.inserted = 0
        self.aggregated = 0
        self.dropped = 0
        self.write_errors = 0
        self.geo_resolved = 0
        self.geo_failed = 0
        self.pruned = 0
        self._started_at = time.monotonic()

        # Last time each module reported activity, so a module that dies quietly
        # is visible on /api/health instead of just going silent.
        self._heartbeats: dict[str, str] = {}
        self._heartbeat_lock = threading.Lock()

    # -- public API ---------------------------------------------------------

    def start(self) -> None:
        if self._started.is_set():
            return
        self._started.set()
        self.notifier.start()
        if self.email_immediate is not None:
            self.email_immediate.start()

        self._spawn(self._writer_loop, 'alert-writer')
        if config.GEO_ENRICHMENT_ENABLED:
            self._spawn(self._enrichment_loop, 'geo-enrichment')
        self._spawn(self._retention_loop, 'retention')
        if email_alerts.is_configured():
            self._spawn(self._email_digest_loop, 'email-digest')

    def submit(self, alert: Alert) -> bool:
        """Hand an alert to the pipeline. Never blocks, never raises.

        Returns False if the alert was shed because the queue was full.
        """
        self.received += 1
        self.heartbeat(alert.module)
        try:
            self._queue.put_nowait(alert)
            return True
        except queue.Full:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 100 == 0:
                print(f'[!] Alert queue full - {self.dropped} alerts shed. '
                      f'Detection is outrunning the writer.')
            return False

    def heartbeat(self, module: str) -> None:
        with self._heartbeat_lock:
            self._heartbeats[module] = db.utc_iso()

    def register_response_handler(self, handler) -> None:
        """Register a callable invoked with each newly inserted alert."""
        self._response_handlers.append(handler)

    def stop(self) -> None:
        self._stop.set()
        self.notifier.stop()
        if self.email_immediate is not None:
            self.email_immediate.stop()

    def stats(self) -> dict:
        with self._heartbeat_lock:
            heartbeats = dict(self._heartbeats)
        return {
            'uptime_seconds': int(time.monotonic() - self._started_at),
            'queue_depth': self._queue.qsize(),
            'queue_capacity': config.ALERT_QUEUE_SIZE,
            'received': self.received,
            'inserted': self.inserted,
            'aggregated': self.aggregated,
            'dropped': self.dropped,
            'write_errors': self.write_errors,
            'geo_resolved': self.geo_resolved,
            'geo_failed': self.geo_failed,
            'pruned': self.pruned,
            'module_heartbeats': heartbeats,
            'notifications': self.notifier.stats(),
            'email_immediate': self.email_immediate.stats() if self.email_immediate else None,
            'email_configured': email_alerts.is_configured(),
            'threads': {t.name: t.is_alive() for t in self._threads},
        }

    # -- workers -----------------------------------------------------------

    def _spawn(self, target, name: str) -> None:
        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

    def _writer_loop(self) -> None:
        """Single owner of alert inserts. Holds one long-lived connection."""
        conn = db.get_connection()
        try:
            while not self._stop.is_set():
                try:
                    alert = self._queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                try:
                    action, _row_id = db.insert_or_aggregate(
                        conn, alert, config.ALERT_DEDUP_WINDOW_SECONDS)
                except Exception as exc:
                    # Never let one bad alert kill the writer - if this thread
                    # dies the tool looks alive while recording nothing.
                    self.write_errors += 1
                    print(f'[!] Failed to write alert: {exc}')
                    continue

                if action == 'inserted':
                    self.inserted += 1
                    self.notifier.submit(alert)
                    if self.email_immediate is not None:
                        self.email_immediate.submit(alert)
                    for handler in self._response_handlers:
                        try:
                            handler(alert)
                        except Exception as exc:
                            print(f'[!] Response handler failed: {exc}')
                else:
                    # A recurrence: the dashboard row's counter was bumped, and
                    # nobody gets interrupted again for a condition they have
                    # already been told about.
                    self.aggregated += 1
        finally:
            conn.close()

    def _enrichment_loop(self) -> None:
        """Resolve geolocation for alerts written with geo_status='pending'.

        Work is discovered from the database rather than an in-memory queue, so a
        restart mid-backlog resumes instead of leaving rows unenriched forever.
        """
        conn = db.get_connection()
        try:
            while not self._stop.is_set():
                try:
                    pending = db.get_pending_geo_ips(conn, limit=25)
                except Exception as exc:
                    print(f'[!] Enrichment query failed: {exc}')
                    self._stop.wait(5)
                    continue

                if not pending:
                    self._stop.wait(3)
                    continue

                for ip in pending:
                    if self._stop.is_set():
                        break
                    cached = db.get_cached_geo(conn, ip, config.GEO_CACHE_TTL_DAYS)
                    if cached is not None:
                        geo = cached if cached['status'] == 'success' else None
                        status = 'done' if geo else 'skipped'
                    else:
                        geo, lookup_status = geolocate_ip(
                            ip,
                            timeout=config.GEO_REQUEST_TIMEOUT_SECONDS,
                            limiter=self._geo_limiter,
                        )
                        db.cache_geo(conn, ip, geo, lookup_status)
                        status = 'done' if lookup_status == 'success' else 'skipped'
                        if lookup_status == 'success':
                            self.geo_resolved += 1
                        else:
                            self.geo_failed += 1
                    try:
                        db.apply_geo_to_alerts(conn, ip, geo, status)
                    except Exception as exc:
                        print(f'[!] Failed to apply geo for {ip}: {exc}')
        finally:
            conn.close()

    def _retention_loop(self) -> None:
        conn = db.get_connection()
        try:
            while not self._stop.is_set():
                try:
                    removed = db.prune_old_alerts(
                        conn, config.RETENTION_DAYS, config.RETENTION_MAX_ALERTS)
                    if removed:
                        self.pruned += removed
                        print(f'[*] Retention: pruned {removed} alerts')
                except Exception as exc:
                    print(f'[!] Retention pass failed: {exc}')
                self._stop.wait(config.RETENTION_INTERVAL_SECONDS)
        finally:
            conn.close()

    def _email_digest_loop(self) -> None:
        """Send the periodic summary email once the configured interval elapses.

        Checked every few minutes rather than computing a precise next-send
        time - send_digest_if_due is cheap to call and idempotent when not yet
        due, so simple polling is easier to reason about than a scheduler.
        """
        conn = db.get_connection()
        check_interval = min(900, config.EMAIL_DIGEST_INTERVAL_HOURS * 3600)
        try:
            while not self._stop.is_set():
                try:
                    if email_alerts.send_digest_if_due(conn):
                        print('[*] Sent email digest')
                except Exception as exc:
                    print(f'[!] Email digest check failed: {exc}')
                self._stop.wait(check_interval)
        finally:
            conn.close()


# Single shared instance used by every detection module.
pipeline = AlertPipeline()


def submit(alert: Alert) -> bool:
    return pipeline.submit(alert)


def log_alert(module: str, alert_type: str, severity: str, description: str,
              source_ip: str | None = None, **kwargs) -> bool:
    """Convenience wrapper matching how detection modules already report alerts.

    Accepts the Alert extras (rule_id, technique, entities, raw, dedup_subject)
    as keyword arguments so modules can be enriched one at a time.
    """
    return submit(Alert(
        module=module,
        alert_type=alert_type,
        severity=severity,
        description=description,
        source_ip=source_ip,
        timestamp=datetime.now(timezone.utc),
        **kwargs,
    ))
