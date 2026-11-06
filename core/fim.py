"""File Integrity Monitor.

Watches a small set of directories for files being created, modified or deleted,
by comparing SHA-256 hashes against a stored baseline.

Scope discipline matters more here than anywhere else in the tool. Integrity
monitoring only carries signal for files that are *supposed* to never change - a
hosts file, a deployed web root, a config directory. Pointed at somewhere with
legitimate churn it produces pure noise, because "this file changed" means
nothing when the answer is always "yes, I changed it." Watched paths and ignore
patterns are both configurable, and the dashboard reports the effective scope so
what is under watch is visible without reading this file.
"""

import fnmatch
import os
import time
import hashlib

import config  # type: ignore
from core import db  # type: ignore
from core.detect import process_fim  # type: ignore
from core.pipeline import pipeline  # type: ignore

MODULE = 'FIM'


def _watched_directories() -> list[str]:
    dirs = getattr(config, 'FIM_DIRECTORIES', None)
    if dirs:
        return list(dirs)
    # Tolerate the older single-directory setting so an existing config keeps working.
    legacy = getattr(config, 'FIM_DIRECTORY', None)
    return [legacy] if legacy else []


def _is_ignored(filename: str) -> bool:
    # Case-insensitive: Windows filenames are, so 'THUMBS.DB' and 'x.TMP' are
    # the same files the patterns were written for.
    lowered = filename.lower()
    return any(fnmatch.fnmatch(lowered, pattern.lower())
               for pattern in getattr(config, 'FIM_IGNORE_PATTERNS', []))


def _baseline_checkpoint(directory: str) -> str:
    return f'fim_baseline:{os.path.normcase(os.path.abspath(directory))}'


def _like_prefix(prefix: str) -> str:
    """A LIKE pattern matching paths under `prefix` literally - '_' and '%'
    are wildcards in LIKE, and '_' is common in directory names."""
    escaped = prefix.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    return escaped + '%'


def get_file_hash(filepath: str) -> str | None:
    """SHA-256 of a file, or None if it cannot be read.

    Returning None for unreadable files is deliberate: a file deleted or locked
    mid-scan is normal, not an integrity event, and must not raise an alert.
    """
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, PermissionError):
        return None


def _snapshot(directory: str) -> dict[str, str]:
    """Current hashes for every non-ignored file under a directory."""
    snapshot = {}
    for root, _dirs, files in os.walk(directory):
        for filename in files:
            if _is_ignored(filename):
                continue
            path = os.path.join(root, filename)
            file_hash = get_file_hash(path)
            if file_hash:
                snapshot[path] = file_hash
    return snapshot


def scan_directory(conn, directory: str) -> None:
    """Compare a directory against its stored baseline and alert on differences."""
    if not os.path.isdir(directory):
        return

    c = conn.cursor()
    prefix = os.path.join(directory, '')
    c.execute("SELECT file_path, file_hash FROM fim_baselines WHERE file_path LIKE ? ESCAPE '\\'",
              (_like_prefix(prefix),))
    # LIKE is case-insensitive for ASCII, so re-check the prefix exactly.
    baselines = {row['file_path']: row['file_hash'] for row in c.fetchall()
                 if row['file_path'].startswith(prefix)}

    current = _snapshot(directory)

    # First sight of a directory establishes the baseline silently. Without this,
    # installing the tool would alert once per pre-existing file - hundreds of
    # meaningless "file created" alerts that teach an operator to ignore the tool.
    #
    # "First sight" is recorded explicitly as a checkpoint rather than inferred
    # from "no baseline rows yet": a directory that starts out empty (or is
    # emptied later) also has no rows, and inferring would silently absorb the
    # next file dropped into it - exactly the event worth alerting on.
    # Existing installs that predate the checkpoint count as established if
    # they already have rows.
    checkpoint = _baseline_checkpoint(directory)
    if not baselines and db.load_checkpoint(conn, checkpoint) is None:
        for path, file_hash in current.items():
            c.execute('INSERT OR REPLACE INTO fim_baselines (file_path, file_hash) VALUES (?, ?)',
                      (path, file_hash))
        conn.commit()
        db.save_checkpoint(conn, checkpoint, db.utc_iso())
        print(f'[*] FIM baseline established for {directory} ({len(current)} files)')
        return
    if db.load_checkpoint(conn, checkpoint) is None:
        db.save_checkpoint(conn, checkpoint, db.utc_iso())

    for path, file_hash in current.items():
        if path not in baselines:
            process_fim('created', path, directory)
            c.execute('INSERT OR REPLACE INTO fim_baselines (file_path, file_hash) VALUES (?, ?)',
                      (path, file_hash))
        elif baselines[path] != file_hash:
            process_fim('modified', path, directory)
            c.execute('UPDATE fim_baselines SET file_hash = ?, '
                      'last_updated = CURRENT_TIMESTAMP WHERE file_path = ?',
                      (file_hash, path))

    for path in baselines:
        if path not in current:
            process_fim('deleted', path, directory)
            c.execute('DELETE FROM fim_baselines WHERE file_path = ?', (path,))

    conn.commit()


def get_monitoring_scope() -> list[dict]:
    """What the FIM is actually watching, for display on the dashboard."""
    # Counts files without hashing them - this runs on every /api/health poll
    # (every 3s per open dashboard), and re-hashing the whole watched tree that
    # often is pure wasted I/O.
    scope = []
    for directory in _watched_directories():
        exists = os.path.isdir(directory)
        count = 0
        if exists:
            for _root, _dirs, files in os.walk(directory):
                count += sum(1 for name in files if not _is_ignored(name))
        scope.append({'path': directory, 'exists': exists, 'file_count': count})
    return scope


def start_fim_monitor(interval: int | None = None) -> None:
    interval = interval or config.FIM_SCAN_INTERVAL
    directories = _watched_directories()
    if not directories:
        print('[!] FIM has no directories configured - module idle')
        return

    print(f'[*] Starting File Integrity Monitor -> {", ".join(directories)}')
    conn = db.get_connection()
    try:
        while True:
            pipeline.heartbeat(MODULE)
            for directory in directories:
                try:
                    scan_directory(conn, directory)
                except Exception as exc:
                    print(f'[!] FIM scan of {directory} failed: {exc}')
            time.sleep(interval)
    finally:
        conn.close()
