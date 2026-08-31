"""Authentication log parser.

Parses an OpenSSH/syslog-style auth log into normalized events and hands them to
the rule engine. This module no longer decides what is suspicious - thresholds,
severities and exclusions all live in rules/authlog.yaml. What stays here is
parsing, plus the small amount of state a rule cannot compute from a single line:
how many times an IP failed recently, which is what turns "a login succeeded"
into "a brute force worked."
"""

import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

import config  # type: ignore
from core.detect import process_authlog  # type: ignore
from core.pipeline import pipeline  # type: ignore

MODULE = 'LOG_MONITOR'

# How far back a failure still counts as "recent" when a login succeeds.
RECENT_FAILURE_WINDOW = timedelta(minutes=10)

_recent_failures: dict[str, deque] = defaultdict(deque)
_last_prune = datetime.now()

AUTH_PATTERN = re.compile(
    r'([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})'      # syslog timestamp
    r'.*?(Failed|Accepted)\s+password\s+for\s+'
    r'(?:invalid\s+user\s+)?(\S+)\s+from\s+'
    r'([0-9a-fA-F:.]+)'                              # IPv4 or IPv6
)


def _prune(now: datetime) -> None:
    """Bound the failure-tracking state.

    Without this the dictionary grows for every IP ever seen - invisible on a
    workstation, an unbounded leak in a service running for months against an
    internet-facing log.
    """
    global _last_prune
    if now - _last_prune < timedelta(minutes=5):
        return
    _last_prune = now
    cutoff = now - RECENT_FAILURE_WINDOW
    for ip in list(_recent_failures):
        bucket = _recent_failures[ip]
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if not bucket:
            del _recent_failures[ip]


def _count_recent_failures(ip: str, now: datetime) -> int:
    bucket = _recent_failures[ip]
    cutoff = now - RECENT_FAILURE_WINDOW
    while bucket and bucket[0] < cutoff:
        bucket.popleft()
    return len(bucket)


def parse_log_line(line: str) -> None:
    """Parse one log line into a normalized event for the rule engine."""
    match = AUTH_PATTERN.search(line)
    if not match:
        return

    log_time_str, status, user, ip = match.groups()
    now = datetime.now()
    _prune(now)

    # Syslog timestamps carry no year, so assume the current one. Only the hour
    # is used for detection, so a year boundary is harmless.
    try:
        log_time = datetime.strptime(f'{now.year} {log_time_str}', '%Y %b %d %H:%M:%S')
    except ValueError:
        return

    if status == 'Failed':
        _recent_failures[ip].append(now)
        recent = _count_recent_failures(ip, now)
    else:
        # Count failures *before* this success, so the number describes what led
        # up to it. Then clear them: the account is in, and leaving the failures
        # would re-flag every subsequent login from this IP.
        recent = _count_recent_failures(ip, now)
        _recent_failures.pop(ip, None)

    process_authlog(status=status, user=user, ip=ip, hour=log_time.hour,
                    recent_failures=recent, line=line)


def start_log_monitor(log_file: str | None = None) -> None:
    """Tail the configured log file, following it across rotation.

    Log files get rotated out from under a tail. Detecting truncation and
    reopening is what keeps the monitor working past the first rotation instead
    of silently reading nothing forever.
    """
    log_file = log_file or config.LOG_FILE_PATH

    while not os.path.exists(log_file):
        print(f'[*] Log monitor waiting for {log_file} to appear...')
        pipeline.heartbeat(MODULE)
        time.sleep(5)

    print(f'[*] Starting Log Monitor -> {log_file}')
    handle = open(log_file, 'r', errors='replace')
    handle.seek(0, os.SEEK_END)

    try:
        while True:
            line = handle.readline()
            if line:
                pipeline.heartbeat(MODULE)
                try:
                    parse_log_line(line.strip())
                except Exception as exc:
                    print(f'[!] Failed to parse log line: {exc}')
                continue

            pipeline.heartbeat(MODULE)
            time.sleep(0.5)

            try:
                if os.stat(log_file).st_size < handle.tell():
                    print('[*] Log file truncated or rotated - reopening')
                    handle.close()
                    handle = open(log_file, 'r', errors='replace')
            except FileNotFoundError:
                print('[*] Log file disappeared - waiting for it to return')
                handle.close()
                while not os.path.exists(log_file):
                    pipeline.heartbeat(MODULE)
                    time.sleep(5)
                handle = open(log_file, 'r', errors='replace')
    finally:
        handle.close()
