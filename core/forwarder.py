"""Agent-side event forwarder (Phase 5, DEPLOYMENT_ROLE == 'agent' only).

core/detect.py's _route_event() hands normalized events here instead of to the
local rule engine when running as an agent - see that module for why (agents
watch, they don't decide; rules and correlation stay server-side only).

Two things this buys, both discussed and agreed before building this:

1. **Survives a network outage.** Events are appended to a durable file
   (`agent_buffer.jsonl`) before anything is sent anywhere. If the server is
   unreachable, submit() still succeeds and the background sender thread
   catches up once connectivity returns - collection never blocks on network
   health, mirroring how core/pipeline.py never blocks detection on the
   database or a notification sink.

2. **Tamper-evidence, not tamper-prevention.** Each buffered line commits to
   the previous line's hash (a small hash chain, like CloudTrail log-file
   validation or systemd's forward-secure sealing). Deleting or editing a
   buffered event out from under this file breaks the chain at that point,
   which is detectable - not preventable. Real tamper *prevention* (kernel-
   level anti-tamper, protected processes) was explicitly ruled out as
   disproportionate for a solo-dev tool; this is the achievable middle
   ground.

Not built here: agent-as-a-Windows-service packaging (deferred - the Phase 3
service.py pattern applies mechanically whenever that's wanted) and TLS (this
POSTs plain HTTP - SERVER_URL is documented as LAN-only, never the open
internet, until a future pass adds it).
"""

import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import config  # type: ignore

BUFFER_PATH = os.path.join(config.BASE_DIR, 'agent_buffer.jsonl')
STATE_PATH = os.path.join(config.BASE_DIR, 'agent_buffer_state.json')
GENESIS_HASH = '0' * 64


def _json_safe(event: dict) -> dict:
    """Copy an event dict with its datetime 'time' field made JSON-serializable."""
    safe = dict(event)
    when = safe.get('time')
    if isinstance(when, datetime):
        safe['time'] = when.astimezone(timezone.utc).isoformat()
    return safe


def _line_hash(seq: int, event_json: dict, prev_hash: str) -> str:
    payload = json.dumps({'seq': seq, 'event': event_json, 'prev_hash': prev_hash},
                         sort_keys=True, default=str)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


class EventForwarder:
    def __init__(self):
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

        self.next_seq = 1
        self.last_hash = GENESIS_HASH
        self.synced_seq = 0
        # What the first line still in the buffer file should chain back to.
        # Starts at genesis, and moves forward each time compaction drops
        # already-synced lines - without it, verification would start from
        # genesis against a compacted file and report every intact buffer as
        # tampered.
        self.chain_anchor = GENESIS_HASH

        self.sent = 0
        self.send_errors = 0
        self.tamper_warnings = 0

        self._load_state()
        self._verify_chain_on_startup()

    # -- persistence ---------------------------------------------------

    def _load_state(self) -> None:
        try:
            with open(STATE_PATH, 'r', encoding='utf-8') as f:
                state = json.load(f)
            self.next_seq = int(state.get('next_seq', 1))
            self.last_hash = state.get('last_hash', GENESIS_HASH)
            self.synced_seq = int(state.get('synced_seq', 0))
            self.chain_anchor = state.get('chain_anchor', GENESIS_HASH)
        except (OSError, ValueError, json.JSONDecodeError):
            pass  # first run - defaults above stand

    def _save_state(self) -> None:
        state = {'next_seq': self.next_seq, 'last_hash': self.last_hash,
                 'synced_seq': self.synced_seq, 'chain_anchor': self.chain_anchor}
        try:
            with open(STATE_PATH, 'w', encoding='utf-8') as f:
                json.dump(state, f)
        except OSError as exc:
            print(f'[!] Could not persist forwarder state: {exc}')

    def _verify_chain_on_startup(self) -> None:
        """Best-effort: recompute the chain over whatever is on disk and warn
        loudly if a link doesn't match. Detection only - see module docstring
        for why this can't also prevent the tampering."""
        if not os.path.exists(BUFFER_PATH):
            return
        prev = self.chain_anchor
        try:
            with open(BUFFER_PATH, 'r', encoding='utf-8') as f:
                for line_no, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        self.tamper_warnings += 1
                        print(f'[!] agent_buffer.jsonl line {line_no} is not valid JSON - '
                              f'buffer may have been tampered with or truncated.')
                        continue
                    expected = _line_hash(record.get('seq'), record.get('event'), prev)
                    if record.get('prev_hash') != prev or record.get('hash') != expected:
                        self.tamper_warnings += 1
                        print(f'[!] agent_buffer.jsonl hash chain broken at line {line_no} '
                              f'(seq {record.get("seq")}) - buffered events may have been '
                              f'edited or deleted out of order.')
                    prev = record.get('hash', prev)
        except OSError as exc:
            print(f'[!] Could not verify agent buffer on startup: {exc}')

    def _compact(self) -> None:
        """Drop lines the server has already acknowledged, so the file stays
        bounded in the steady state instead of growing forever.

        Moves chain_anchor forward to whatever the first surviving line chains
        back to, so the shortened file still verifies - the chain is only ever
        checked from the anchor, never from genesis, once lines have been
        dropped.
        """
        if not os.path.exists(BUFFER_PATH):
            return
        tmp_path = BUFFER_PATH + '.compact'
        new_anchor = None
        try:
            with open(BUFFER_PATH, 'r', encoding='utf-8') as src, \
                 open(tmp_path, 'w', encoding='utf-8') as dst:
                for line in src:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        record = json.loads(stripped)
                    except json.JSONDecodeError:
                        continue
                    if record.get('seq', 0) > self.synced_seq:
                        if new_anchor is None:
                            new_anchor = record.get('prev_hash', self.chain_anchor)
                        dst.write(line if line.endswith('\n') else line + '\n')
            os.replace(tmp_path, BUFFER_PATH)
            # Nothing survived: the next line written will chain onto the most
            # recent hash, so that becomes the anchor.
            self.chain_anchor = new_anchor if new_anchor is not None else self.last_hash
        except OSError as exc:
            print(f'[!] Could not compact agent buffer: {exc}')

    # -- public API ------------------------------------------------------

    def submit(self, event: dict) -> None:
        """Durably buffer one event. Never blocks on the network, never raises."""
        event_json = _json_safe(event)
        with self._lock:
            seq = self.next_seq
            line_hash = _line_hash(seq, event_json, self.last_hash)
            record = {'seq': seq, 'event': event_json, 'prev_hash': self.last_hash,
                      'hash': line_hash}
            try:
                with open(BUFFER_PATH, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(record) + '\n')
            except OSError as exc:
                print(f'[!] Could not buffer event for forwarding: {exc}')
                return
            self.next_seq += 1
            self.last_hash = line_hash
            self._save_state()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._send_loop, name='forwarder',
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def stats(self) -> dict:
        with self._lock:
            pending = self.next_seq - 1 - self.synced_seq
        return {'sent': self.sent, 'send_errors': self.send_errors,
                'pending': pending, 'tamper_warnings': self.tamper_warnings}

    # -- sender ------------------------------------------------------------

    def _pending_batch(self) -> list[dict]:
        if not os.path.exists(BUFFER_PATH):
            return []
        batch = []
        try:
            with open(BUFFER_PATH, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record.get('seq', 0) > self.synced_seq:
                        batch.append(record)
                        # Stay under the server's AGENT_INGEST_BATCH_LIMIT so a
                        # batch is never rejected for being oversized.
                        if len(batch) >= config.AGENT_INGEST_BATCH_LIMIT:
                            break
        except OSError:
            return []
        return batch

    def _post(self, events: list[dict]) -> bool:
        url = f'{config.SERVER_URL.rstrip("/")}/api/ingest'
        body = json.dumps({'events': events}).encode('utf-8')
        req = urllib.request.Request(url, data=body, method='POST', headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {config.AGENT_TOKEN}',
        })
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f'[!] Could not reach server at {config.SERVER_URL}: {exc}')
            return False

    def _send_loop(self) -> None:
        consecutive_failures = 0
        while not self._stop.is_set():
            batch = self._pending_batch()
            events = [record['event'] for record in batch]
            # Sent even when empty - this is the agent's heartbeat, see the
            # module and config.AGENT_HEARTBEAT_SECONDS docstrings.
            if self._post(events):
                consecutive_failures = 0
                if batch:
                    with self._lock:
                        self.synced_seq = batch[-1]['seq']
                        self.sent += len(batch)
                        # Compact first: it moves chain_anchor forward, and that
                        # has to land in the same saved state as synced_seq or a
                        # crash between the two leaves them disagreeing.
                        self._compact()
                        self._save_state()
            else:
                consecutive_failures += 1
                self.send_errors += 1

            wait = config.AGENT_HEARTBEAT_SECONDS
            if consecutive_failures:
                wait = min(config.AGENT_HEARTBEAT_SECONDS * consecutive_failures, 60)
            self._stop.wait(wait)


forwarder = EventForwarder()
