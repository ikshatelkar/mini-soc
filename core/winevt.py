"""Windows Event Log collector.

This is the module that turns Mini SOC from a tool watching synthetic logs into
one watching the real operating system. Windows already records every logon
attempt, service installation and account change; this reads that firehose.

Three design points worth knowing:

**Push vs pull.** Windows offers a callback-based subscription, but this uses the
pull model (`SignalEvent` + `EvtNext`). The callback runs on an OS-owned thread
where an exception has nowhere useful to go, and it hands events over faster than
they can be processed with no way to push back. Pulling in batches keeps event
processing on our own thread, under our own error handling, at our own pace.

**Checkpoints.** Every batch advances a bookmark that is persisted to the
database. On restart the subscription resumes immediately *after* the last event
already handled - so a service restart neither replays the channel as a burst of
fresh alerts nor silently skips whatever arrived while it was down. Verified by
round-tripping a bookmark and confirming zero record overlap.

**Graceful degradation.** Channel availability varies by host and privilege. The
Security channel requires administrator rights; Sysmon's channel only exists if
Sysmon is installed. A collector that cannot open its channel reports why and
stops, rather than crashing the service or retrying in a hot loop. What is and
is not being collected shows up on /api/health, because a security tool silently
monitoring less than you think is worse than one that is honestly offline.
"""

from __future__ import annotations

import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import config  # type: ignore
from core import db  # type: ignore
from core.pipeline import pipeline  # type: ignore

EVENT_NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

# Populated on import so the rest of the module can degrade cleanly on non-Windows
# hosts or a Python without pywin32, rather than failing at import time.
try:
    import win32event  # type: ignore
    import win32evtlog  # type: ignore
    WINEVT_AVAILABLE = True
    WINEVT_IMPORT_ERROR = None
except ImportError as exc:  # pragma: no cover - platform dependent
    win32event = None  # type: ignore
    win32evtlog = None  # type: ignore
    WINEVT_AVAILABLE = False
    WINEVT_IMPORT_ERROR = str(exc)

# Windows error codes we interpret rather than surface as opaque failures.
_ERROR_ACCESS_DENIED = 5
_ERROR_CHANNEL_NOT_FOUND = 15007
_ERROR_NO_MORE_ITEMS = 259


def parse_event_xml(xml_text: str) -> dict:
    """Turn rendered event XML into a normalized dict.

    Event XML splits into a System section (identity, time, provider) and an
    EventData section whose fields differ per event ID. Unnamed Data elements are
    given positional keys so nothing is silently dropped.
    """
    root = ET.fromstring(xml_text)

    def system_text(tag: str) -> str | None:
        node = root.find(f'./e:System/e:{tag}', EVENT_NS)
        return node.text if node is not None else None

    time_created = None
    tc_node = root.find('./e:System/e:TimeCreated', EVENT_NS)
    if tc_node is not None and tc_node.get('SystemTime'):
        raw = tc_node.get('SystemTime')
        try:
            # Windows emits more fractional-second digits than fromisoformat
            # accepts on older Pythons, so truncate to microseconds.
            cleaned = raw.rstrip('Z')
            if '.' in cleaned:
                head, frac = cleaned.split('.', 1)
                cleaned = f'{head}.{frac[:6]}'
            time_created = datetime.fromisoformat(cleaned).replace(tzinfo=timezone.utc)
        except ValueError:
            time_created = None

    provider_node = root.find('./e:System/e:Provider', EVENT_NS)

    data: dict[str, str | None] = {}
    for index, node in enumerate(root.findall('./e:EventData/e:Data', EVENT_NS)):
        data[node.get('Name') or f'_{index}'] = node.text

    event_id_text = system_text('EventID') or '0'
    record_id_text = system_text('EventRecordID') or '0'

    return {
        'event_id': int(event_id_text) if event_id_text.isdigit() else 0,
        'record_id': int(record_id_text) if record_id_text.isdigit() else 0,
        'channel': system_text('Channel'),
        'computer': system_text('Computer'),
        'provider': provider_node.get('Name') if provider_node is not None else None,
        'time_created': time_created or datetime.now(timezone.utc),
        'data': data,
        'raw_xml': xml_text,
    }


class ChannelCollector:
    """Tails one event log channel and hands normalized events to a callback."""

    def __init__(self, channel: str, event_ids: list[int], handler,
                 required: bool = True, batch_size: int = 50):
        self.channel = channel
        self.event_ids = event_ids
        self.handler = handler
        self.required = required
        self.batch_size = batch_size

        self.status = 'not_started'
        self.detail: str | None = None
        self.events_seen = 0
        self.handler_errors = 0

        self._stop = threading.Event()
        self._checkpoint_name = f'winevt:{channel}'

    def query(self) -> str:
        """XPath selecting only the event IDs we care about.

        Filtering in the query rather than in Python matters: the Security channel
        on a busy host produces enormous volume, and letting Windows do the
        filtering avoids rendering and parsing events we would only discard.
        """
        if not self.event_ids:
            return '*'
        clause = ' or '.join(f'EventID={eid}' for eid in self.event_ids)
        return f'*[System[({clause})]]'

    def _classify_error(self, exc: Exception) -> tuple[str, str]:
        code = exc.args[0] if exc.args and isinstance(exc.args[0], int) else None
        if code == _ERROR_ACCESS_DENIED:
            return ('access_denied',
                    'Administrator privileges are required to read this channel. '
                    'Run Mini SOC elevated to enable it.')
        if code == _ERROR_CHANNEL_NOT_FOUND:
            return ('not_available',
                    'Channel does not exist on this host (the providing software '
                    'is not installed).')
        return 'error', str(exc)

    def stop(self) -> None:
        self._stop.set()

    def stats(self) -> dict:
        return {
            'channel': self.channel,
            'status': self.status,
            'detail': self.detail,
            'event_ids': self.event_ids,
            'events_seen': self.events_seen,
            'handler_errors': self.handler_errors,
        }

    def run(self) -> None:
        if not WINEVT_AVAILABLE:
            self.status = 'unavailable'
            self.detail = f'pywin32 not importable: {WINEVT_IMPORT_ERROR}'
            print(f'[!] Event Log collector for {self.channel} disabled: {self.detail}')
            return

        conn = db.get_connection()
        try:
            saved = db.load_checkpoint(conn, self._checkpoint_name)

            try:
                subscription, bookmark = self._subscribe(saved)
            except Exception as exc:
                self.status, self.detail = self._classify_error(exc)
                level = '!' if self.required else '*'
                print(f'[{level}] Event Log channel "{self.channel}" unavailable '
                      f'({self.status}): {self.detail}')
                return

            self.status = 'running'
            resumed = 'resuming from checkpoint' if saved else 'starting at new events'
            print(f'[*] Event Log collector -> {self.channel} ({resumed}, '
                  f'{len(self.event_ids)} event IDs)')

            self._pump(conn, subscription, bookmark)
        finally:
            conn.close()

    def _subscribe(self, saved_bookmark: str | None):
        """Open the subscription, resuming from a saved bookmark when present."""
        signal = win32event.CreateEvent(None, 0, 0, None)

        if saved_bookmark:
            bookmark = win32evtlog.EvtCreateBookmark(saved_bookmark)
            subscription = win32evtlog.EvtSubscribe(
                self.channel,
                win32evtlog.EvtSubscribeStartAfterBookmark,
                SignalEvent=signal,
                Query=self.query(),
                Bookmark=bookmark,
            )
        else:
            bookmark = win32evtlog.EvtCreateBookmark(None)
            # Without a checkpoint, start at future events only. Starting at the
            # oldest record would alert on months of historical activity as
            # though it were happening now.
            subscription = win32evtlog.EvtSubscribe(
                self.channel,
                win32evtlog.EvtSubscribeToFutureEvents,
                SignalEvent=signal,
                Query=self.query(),
            )

        self._signal = signal
        return subscription, bookmark

    def _pump(self, conn, subscription, bookmark) -> None:
        """Drain available events, then wait to be signalled that more arrived."""
        while not self._stop.is_set():
            drained_any = False
            while not self._stop.is_set():
                try:
                    events = win32evtlog.EvtNext(subscription, self.batch_size)
                except Exception as exc:
                    code = exc.args[0] if exc.args and isinstance(exc.args[0], int) else None
                    if code == _ERROR_NO_MORE_ITEMS:
                        break
                    self.status = 'error'
                    self.detail = str(exc)
                    print(f'[!] EvtNext failed on {self.channel}: {exc}')
                    return

                if not events:
                    break

                drained_any = True
                for event_handle in events:
                    try:
                        xml_text = win32evtlog.EvtRender(
                            event_handle, win32evtlog.EvtRenderEventXml)
                        event = parse_event_xml(xml_text)
                    except Exception as exc:
                        self.handler_errors += 1
                        print(f'[!] Failed to render event on {self.channel}: {exc}')
                        continue

                    self.events_seen += 1
                    pipeline.heartbeat(f'WINEVT:{self.channel}')

                    try:
                        self.handler(event)
                    except Exception as exc:
                        # One unhandled event must never stop collection.
                        self.handler_errors += 1
                        print(f'[!] Handler failed for event '
                              f'{event.get("event_id")} on {self.channel}: {exc}')

                    win32evtlog.EvtUpdateBookmark(bookmark, event_handle)

                # Checkpoint per batch rather than per event: a crash costs at
                # most one batch of replayed events, and the alert dedup gate
                # absorbs those without duplicating anything.
                self._persist_bookmark(conn, bookmark)

            if not drained_any:
                pipeline.heartbeat(f'WINEVT:{self.channel}')

            # Sleep on the kernel signal, not a timer, so events are picked up as
            # soon as Windows publishes them. The timeout only exists so the stop
            # flag is checked regularly.
            win32event.WaitForSingleObjectEx(self._signal, 2000, True)

    def _persist_bookmark(self, conn, bookmark) -> None:
        try:
            saved = win32evtlog.EvtRender(bookmark, win32evtlog.EvtRenderBookmark)
            db.save_checkpoint(conn, self._checkpoint_name, saved)
        except Exception as exc:
            print(f'[!] Failed to checkpoint {self.channel}: {exc}')


_collectors: list[ChannelCollector] = []


def start_event_log_collectors(handler) -> list[ChannelCollector]:
    """Start a collector thread per configured channel."""
    global _collectors
    _collectors = []

    if not WINEVT_AVAILABLE:
        print(f'[!] Windows Event Log collection unavailable: {WINEVT_IMPORT_ERROR}')
        return []

    for spec in config.WINEVT_CHANNELS:
        if not spec.get('enabled', True):
            continue
        collector = ChannelCollector(
            channel=spec['channel'],
            event_ids=spec.get('event_ids', []),
            handler=handler,
            required=spec.get('required', True),
        )
        _collectors.append(collector)
        threading.Thread(target=collector.run, daemon=True,
                         name=f'winevt-{spec["channel"]}').start()

    return _collectors


def collector_stats() -> list[dict]:
    return [c.stats() for c in _collectors]
