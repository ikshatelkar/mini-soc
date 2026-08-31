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
    return any(fnmatch.fnmatch(filename, pattern)
               for pattern in getattr(config, 'FIM_IGNORE_PATTERNS', []))


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
    c.execute('SELECT file_path, file_hash FROM fim_baselines WHERE file_path LIKE ?',
              (prefix + '%',))
    baselines = {row['file_path']: row['file_hash'] for row in c.fetchall()}

    current = _snapshot(directory)

    # First sight of a directory establishes the baseline silently. Without this,
    # installing the tool would alert once per pre-existing file - hundreds of
    # meaningless "file created" alerts that teach an operator to ignore the tool.
    if not baselines:
        for path, file_hash in current.items():
            c.execute('INSERT OR REPLACE INTO fim_baselines (file_path, file_hash) VALUES (?, ?)',
                      (path, file_hash))
        conn.commit()
        print(f'[*] FIM baseline established for {directory} ({len(current)} files)')
        return

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
    scope = []
    for directory in _watched_directories():
        exists = os.path.isdir(directory)
        scope.append({
            'path': directory,
            'exists': exists,
            'file_count': len(_snapshot(directory)) if exists else 0,
        })
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
