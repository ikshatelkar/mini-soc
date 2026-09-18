"""Storage layer.

Two rules hold this together:

1. **Writes are concentrated and paced.** All alert inserts go through the
   pipeline's writer thread on a single long-lived connection. The enrichment
   and retention workers also write, but infrequently and in small batches, so
   at most three writers ever contend. WAL keeps readers from blocking them, and
   a busy timeout makes contending writers wait instead of raising - together
   that is what keeps `database is locked` from appearing under real event
   volume. Readers (Flask request handlers) open short-lived connections.

2. **No blocking work in here.** Geolocation used to happen inside the alert
   insert, which meant a 3-second HTTP timeout could stall detection. Rows are
   now written immediately with `geo_status = 'pending'` and filled in later by
   the enrichment worker.
"""

import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from core.events import Alert, HOSTNAME, SEVERITY_ORDER  # type: ignore

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'mini_soc.db')

# Columns added after the initial release. Existing databases are upgraded in
# place rather than rebuilt, so an operator upgrading the tool keeps their
# alert history.
_MIGRATION_COLUMNS = [
    ('fingerprint',      'TEXT'),
    ('last_seen',        'DATETIME'),
    ('occurrence_count', 'INTEGER DEFAULT 1'),
    ('host',             'TEXT'),
    ('source_ip',        'TEXT'),
    ('rule_id',          'TEXT'),
    ('technique',        'TEXT'),
    ('entities',         'TEXT'),
    ('raw',              'TEXT'),
    ('geo_country',      'TEXT'),
    ('geo_city',         'TEXT'),
    ('geo_isp',          'TEXT'),
    ('geo_lat',          'REAL'),
    ('geo_lon',          'REAL'),
    ('geo_status',       'TEXT'),
    # Alert lifecycle: an alert starts 'open' and stays that way until a human
    # marks it handled or dismisses it. This is what lets the dashboard show
    # "what still needs your attention" instead of an ever-growing raw list.
    ('status',           "TEXT DEFAULT 'open'"),
    ('resolved_at',      'DATETIME'),
    ('resolution_note',  'TEXT'),
]

ALERT_STATUSES = {'open', 'acknowledged', 'dismissed'}


def utc_iso(dt: datetime | None = None) -> str:
    """UTC timestamp as an ISO string. Everything stored is UTC; the browser
    converts to local time for display."""
    dt = dt or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec='seconds')


def get_connection() -> sqlite3.Connection:
    """Open a connection. Safe to call per-request; WAL makes concurrent reads
    cheap. `timeout` makes a writer contending on the lock wait rather than
    immediately raising."""
    conn = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    # NORMAL trades a fsync per commit for OS-level durability. A power loss can
    # cost the last few alerts; in exchange writes are fast enough to keep up
    # with real event rates. FULL would make the writer the bottleneck.
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def init_db() -> None:
    conn = get_connection()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT,
            timestamp DATETIME,
            last_seen DATETIME,
            occurrence_count INTEGER DEFAULT 1,
            host TEXT,
            module TEXT,
            alert_type TEXT,
            severity TEXT,
            description TEXT,
            source_ip TEXT,
            rule_id TEXT,
            technique TEXT,
            entities TEXT,
            raw TEXT,
            geo_country TEXT,
            geo_city TEXT,
            geo_isp TEXT,
            geo_lat REAL,
            geo_lon REAL,
            geo_status TEXT,
            status TEXT DEFAULT 'open',
            resolved_at DATETIME,
            resolution_note TEXT
        )
    ''')

    existing = {row[1] for row in c.execute('PRAGMA table_info(alerts)').fetchall()}
    for col_name, col_type in _MIGRATION_COLUMNS:
        if col_name not in existing:
            c.execute(f'ALTER TABLE alerts ADD COLUMN {col_name} {col_type}')

    c.execute('''
        CREATE TABLE IF NOT EXISTS fim_baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE,
            file_hash TEXT,
            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Opaque resume points for event sources, keyed by source name. Windows Event
    # Log bookmarks live here: without a durable checkpoint a restart either
    # replays the whole channel as fresh alerts or skips whatever arrived while
    # the service was down.
    c.execute('''
        CREATE TABLE IF NOT EXISTS checkpoints (
            name TEXT PRIMARY KEY,
            value TEXT,
            updated_at DATETIME
        )
    ''')

    # Geolocation results persist across restarts so a restart does not re-spend
    # the provider's rate-limit budget on IPs already resolved.
    c.execute('''
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip TEXT PRIMARY KEY,
            country TEXT,
            city TEXT,
            isp TEXT,
            lat REAL,
            lon REAL,
            status TEXT,
            resolved_at DATETIME
        )
    ''')

    # Dashboard login. Deliberately just one admin account for now - see
    # core/auth.py. UNIQUE on username rather than a fixed single-row design so
    # a future multi-admin pass doesn't need a schema change. session_token
    # holds the one currently-valid session for this admin - logging in
    # anywhere overwrites it, which is what makes a session cookie issued
    # elsewhere stop working the moment a new login happens.
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            session_token TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    existing_admin_cols = {row[1] for row in c.execute('PRAGMA table_info(admin_users)').fetchall()}
    if 'session_token' not in existing_admin_cols:
        c.execute('ALTER TABLE admin_users ADD COLUMN session_token TEXT')

    # Admin-assigned employee name per computer, for the Employees page. This
    # is the only person<->machine mapping this tool keeps - alerts only ever
    # carry a host, never a person, so attributing activity to "who" needs an
    # explicit, admin-maintained mapping rather than anything inferred from
    # the data.
    c.execute('''
        CREATE TABLE IF NOT EXISTS computers (
            host TEXT PRIMARY KEY,
            employee_name TEXT,
            updated_at DATETIME
        )
    ''')

    # Enrolled Phase 5 agents (see core/forwarder.py, agent.py). token_hash is a
    # plain sha256 digest rather than a salted password hash - these are
    # generated as high-entropy random tokens, not human passwords, so a
    # deterministic hash that can be looked up by equality is the right tool;
    # the plaintext token is shown to the admin exactly once and never stored.
    c.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            token_hash TEXT UNIQUE,
            enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME
        )
    ''')

    # The dashboard sorts by time, the dedup gate looks up by fingerprint, and
    # the enrichment worker scans for pending rows. Without these, each of those
    # is a full table scan that gets slower every day the tool runs.
    for stmt in [
        'CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)',
        'CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint, last_seen DESC)',
        'CREATE INDEX IF NOT EXISTS idx_alerts_geo_status ON alerts(geo_status)',
        'CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)',
        'CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)',
        'CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, severity)',
    ]:
        c.execute(stmt)

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Writes (writer thread only)
# ---------------------------------------------------------------------------

def insert_or_aggregate(conn: sqlite3.Connection, alert: Alert,
                        dedup_window_seconds: int) -> tuple[str, int]:
    """Store an alert, collapsing it into a recent identical one if present.

    Returns ('inserted', row_id) for genuinely new conditions and
    ('aggregated', row_id) when an existing row's counter was bumped instead.
    The caller uses that to decide whether to notify - recurrences should update
    the dashboard silently, not fire another popup.
    """
    c = conn.cursor()
    fingerprint = alert.fingerprint()
    now = alert.timestamp
    now_iso = utc_iso(now)
    cutoff_iso = utc_iso(now - timedelta(seconds=dedup_window_seconds))

    c.execute(
        'SELECT id FROM alerts WHERE fingerprint = ? AND last_seen >= ? '
        'ORDER BY last_seen DESC LIMIT 1',
        (fingerprint, cutoff_iso),
    )
    row = c.fetchone()
    if row is not None:
        # A recurrence of something already marked handled reopens it. Silently
        # bumping the count on a row someone dismissed would hide that the same
        # condition is still happening - the honest behavior is to put it back
        # in front of them.
        c.execute(
            "UPDATE alerts SET occurrence_count = occurrence_count + 1, "
            "last_seen = ?, description = ?, "
            "status = CASE WHEN status != 'open' THEN 'open' ELSE status END, "
            "resolved_at = CASE WHEN status != 'open' THEN NULL ELSE resolved_at END "
            "WHERE id = ?",
            (now_iso, alert.description, row['id']),
        )
        conn.commit()
        return 'aggregated', row['id']

    # Resolve geolocation from cache if we already know this IP, so the common
    # case costs no network call and no queue slot.
    geo = None
    geo_status = 'skipped'
    if alert.source_ip:
        cached = get_cached_geo(conn, alert.source_ip)
        if cached is None:
            geo_status = 'pending'
        elif cached['status'] == 'success':
            geo, geo_status = cached, 'done'
        else:
            geo_status = 'skipped'

    c.execute('''
        INSERT INTO alerts (
            fingerprint, timestamp, last_seen, occurrence_count, host,
            module, alert_type, severity, description, source_ip,
            rule_id, technique, entities, raw,
            geo_country, geo_city, geo_isp, geo_lat, geo_lon, geo_status
        ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        fingerprint, now_iso, now_iso, alert.host,
        alert.module, alert.alert_type, alert.severity, alert.description,
        alert.source_ip, alert.rule_id, alert.technique,
        json.dumps(alert.entities) if alert.entities else None, alert.raw,
        geo['country'] if geo else None,
        geo['city'] if geo else None,
        geo['isp'] if geo else None,
        geo['lat'] if geo else None,
        geo['lon'] if geo else None,
        geo_status,
    ))
    conn.commit()
    return 'inserted', c.lastrowid


def prune_old_alerts(conn: sqlite3.Connection, retention_days: int,
                     max_alerts: int) -> int:
    """Delete alerts past the retention window, then enforce the row ceiling
    oldest-first. Returns how many rows were removed."""
    c = conn.cursor()
    cutoff = utc_iso(datetime.now(timezone.utc) - timedelta(days=retention_days))
    c.execute('DELETE FROM alerts WHERE timestamp < ?', (cutoff,))
    removed = c.rowcount or 0

    c.execute('SELECT COUNT(*) FROM alerts')
    total = c.fetchone()[0]
    if total > max_alerts:
        c.execute(
            'DELETE FROM alerts WHERE id IN ('
            '  SELECT id FROM alerts ORDER BY timestamp ASC LIMIT ?'
            ')',
            (total - max_alerts,),
        )
        removed += c.rowcount or 0

    conn.commit()
    return removed


# ---------------------------------------------------------------------------
# Alert lifecycle
# ---------------------------------------------------------------------------
#
# An alert starts 'open'. A human moves it to 'acknowledged' (seen, being
# handled or already fixed) or 'dismissed' (not a real problem - a known
# scanner, an intentional off-hours job). Both are terminal until the
# fingerprint recurs, at which point insert_or_aggregate reopens it - see the
# comment there for why silence on recurrence would be dishonest.
#
# This is what turns the dashboard from "here is everything that ever
# happened" into "here is what still needs a decision," which is the
# difference a small deployment without a dedicated analyst actually needs.

class AlertNotFoundError(LookupError):
    pass


def set_alert_status(conn: sqlite3.Connection, alert_id: int, status: str,
                     note: str | None = None) -> dict:
    """Move one alert to 'acknowledged' or 'dismissed'. Returns the updated row."""
    if status not in ALERT_STATUSES:
        raise ValueError(f"status must be one of {sorted(ALERT_STATUSES)}, got '{status}'")

    c = conn.cursor()
    resolved_at = utc_iso() if status != 'open' else None
    c.execute(
        'UPDATE alerts SET status = ?, resolved_at = ?, resolution_note = ? WHERE id = ?',
        (status, resolved_at, note, alert_id),
    )
    if c.rowcount == 0:
        raise AlertNotFoundError(f'no alert with id {alert_id}')
    conn.commit()

    c.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,))
    return dict(c.fetchone())


def bulk_set_status(conn: sqlite3.Connection, status: str, *, module: str | None = None,
                    max_severity: str | None = None) -> int:
    """Acknowledge/dismiss every currently-open alert matching a filter.

    Exists for the "handled, thanks" case on a quiet informational rule that
    keeps producing open rows an operator has no intention of triaging one by
    one - without this, the only alternative is muting the rule entirely and
    losing the record.
    """
    if status not in ALERT_STATUSES:
        raise ValueError(f"status must be one of {sorted(ALERT_STATUSES)}, got '{status}'")
    c = conn.cursor()
    clauses = ["status = 'open'"]
    params: list = []
    if module:
        clauses.append('module = ?')
        params.append(module)
    if max_severity:
        # Ordered as stored severities compare lexically wrong (HIGH < LOW), so
        # this uses an explicit CASE rank rather than a string comparison.
        clauses.append('''
            CASE severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4
                          WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END
            <= CASE ? WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4
                      WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END
        ''')
        params.append(max_severity)

    resolved_at = utc_iso()
    c.execute(
        f"UPDATE alerts SET status = ?, resolved_at = ? WHERE {' AND '.join(clauses)}",
        [status, resolved_at, *params],
    )
    conn.commit()
    return c.rowcount or 0


def get_needs_attention(limit: int = 25) -> list[dict]:
    """Open alerts at HIGH or CRITICAL severity, newest first.

    This is the dashboard's headline list - deliberately excludes MEDIUM/LOW/INFO
    even though they're open, because the point of this query is "what actually
    needs a decision right now," not "everything unresolved."
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        SELECT * FROM alerts
        WHERE status = 'open' AND severity IN ('HIGH', 'CRITICAL')
        ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 ELSE 1 END, last_seen DESC
        LIMIT ?
    ''', (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for row in rows:
        if row.get('entities'):
            try:
                row['entities'] = json.loads(row['entities'])
            except (TypeError, ValueError):
                row['entities'] = {}
    return rows


def get_lifecycle_counts() -> dict:
    """Counts behind the KPI row and the sidebar's per-status badges."""
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        SELECT status,
               SUM(CASE WHEN severity IN ('HIGH','CRITICAL') THEN 1 ELSE 0 END) AS urgent,
               COUNT(*) AS total
        FROM alerts GROUP BY status
    ''')
    by_status = {r['status']: {'urgent': r['urgent'], 'total': r['total']} for r in c.fetchall()}
    conn.close()
    open_stats = by_status.get('open', {'urgent': 0, 'total': 0})
    acknowledged_total = by_status.get('acknowledged', {'total': 0})['total']
    dismissed_total = by_status.get('dismissed', {'total': 0})['total']
    return {
        'needs_attention': open_stats['urgent'],
        'open_total': open_stats['total'],
        # Kept for the existing "Handled" KPI stat tile, which has always
        # meant "everything not open" (acknowledged + dismissed combined) -
        # the sidebar badges below need the two split apart instead.
        'handled_total': acknowledged_total + dismissed_total,
        'acknowledged_total': acknowledged_total,
        'dismissed_total': dismissed_total,
        'total': open_stats['total'] + acknowledged_total + dismissed_total,
    }


# ---------------------------------------------------------------------------
# Checkpoints
# ---------------------------------------------------------------------------

def save_checkpoint(conn: sqlite3.Connection, name: str, value: str) -> None:
    conn.execute('''
        INSERT INTO checkpoints (name, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET value=excluded.value,
                                        updated_at=excluded.updated_at
    ''', (name, value, utc_iso()))
    conn.commit()


def load_checkpoint(conn: sqlite3.Connection, name: str) -> str | None:
    row = conn.execute('SELECT value FROM checkpoints WHERE name = ?', (name,)).fetchone()
    return row['value'] if row else None


# ---------------------------------------------------------------------------
# Dashboard login
# ---------------------------------------------------------------------------
#
# Password hashing lives in core/auth.py, not here - this module only stores
# and retrieves the hash, it never sees a plaintext password.

def admin_exists() -> bool:
    """Whether the one-time /setup flow has already created an account."""
    conn = get_connection()
    row = conn.execute('SELECT 1 FROM admin_users LIMIT 1').fetchone()
    conn.close()
    return row is not None


def create_admin_user(username: str, password_hash: str) -> None:
    conn = get_connection()
    conn.execute(
        'INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
        (username, password_hash),
    )
    conn.commit()
    conn.close()


def get_admin_user(username: str) -> dict | None:
    conn = get_connection()
    row = conn.execute(
        'SELECT * FROM admin_users WHERE username = ?', (username,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_admin_user_by_id(admin_id: int) -> dict | None:
    conn = get_connection()
    row = conn.execute(
        'SELECT * FROM admin_users WHERE id = ?', (admin_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def set_admin_session_token(admin_id: int, token: str | None) -> None:
    """Stamp the one currently-valid session token for this admin (or clear it
    on logout). See core/auth.py for how this enforces a single active
    session."""
    conn = get_connection()
    conn.execute('UPDATE admin_users SET session_token = ? WHERE id = ?', (token, admin_id))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Phase 5 agents
# ---------------------------------------------------------------------------

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def create_agent(name: str) -> tuple[int, str]:
    """Enroll a new agent. Returns (agent_id, plaintext_token) - the token is
    shown to the admin exactly once here; only its hash is ever persisted."""
    token = secrets.token_hex(32)
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        'INSERT INTO agents (name, token_hash) VALUES (?, ?)',
        (name, _hash_token(token)),
    )
    agent_id = c.lastrowid
    conn.commit()
    conn.close()
    return agent_id, token


def get_agent_by_token(token: str) -> dict | None:
    conn = get_connection()
    row = conn.execute(
        'SELECT * FROM agents WHERE token_hash = ?', (_hash_token(token),),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def touch_agent_last_seen(agent_id: int) -> None:
    conn = get_connection()
    conn.execute('UPDATE agents SET last_seen = ? WHERE id = ?', (utc_iso(), agent_id))
    conn.commit()
    conn.close()


def list_agents() -> list[dict]:
    conn = get_connection()
    rows = [dict(r) for r in conn.execute('SELECT * FROM agents ORDER BY enrolled_at DESC')]
    conn.close()
    return rows


def delete_agent(agent_id: int) -> bool:
    """Revoke an agent's access. Returns False if no such agent existed."""
    conn = get_connection()
    c = conn.cursor()
    c.execute('DELETE FROM agents WHERE id = ?', (agent_id,))
    removed = c.rowcount > 0
    conn.commit()
    conn.close()
    return removed


# ---------------------------------------------------------------------------
# Geolocation cache and enrichment
# ---------------------------------------------------------------------------

def get_cached_geo(conn: sqlite3.Connection, ip: str, ttl_days: int = 30) -> dict | None:
    """Cached geolocation for an IP, or None if absent/expired."""
    c = conn.cursor()
    cutoff = utc_iso(datetime.now(timezone.utc) - timedelta(days=ttl_days))
    c.execute('SELECT * FROM geo_cache WHERE ip = ? AND resolved_at >= ?', (ip, cutoff))
    row = c.fetchone()
    return dict(row) if row else None


def cache_geo(conn: sqlite3.Connection, ip: str, geo: dict | None, status: str) -> None:
    c = conn.cursor()
    c.execute('''
        INSERT INTO geo_cache (ip, country, city, isp, lat, lon, status, resolved_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            country=excluded.country, city=excluded.city, isp=excluded.isp,
            lat=excluded.lat, lon=excluded.lon, status=excluded.status,
            resolved_at=excluded.resolved_at
    ''', (
        ip,
        geo.get('country') if geo else None,
        geo.get('city') if geo else None,
        geo.get('isp') if geo else None,
        geo.get('lat') if geo else None,
        geo.get('lon') if geo else None,
        status,
        utc_iso(),
    ))
    conn.commit()


def get_pending_geo_ips(conn: sqlite3.Connection, limit: int = 50) -> list[str]:
    """Distinct IPs on alerts still awaiting enrichment. Because this is derived
    from durable rows rather than an in-memory queue, work survives a restart."""
    c = conn.cursor()
    c.execute(
        "SELECT DISTINCT source_ip FROM alerts "
        "WHERE geo_status = 'pending' AND source_ip IS NOT NULL LIMIT ?",
        (limit,),
    )
    return [row['source_ip'] for row in c.fetchall()]


def apply_geo_to_alerts(conn: sqlite3.Connection, ip: str, geo: dict | None,
                        status: str) -> int:
    """Backfill every pending alert for an IP once it has been resolved."""
    c = conn.cursor()
    if geo:
        c.execute('''
            UPDATE alerts SET geo_country = ?, geo_city = ?, geo_isp = ?,
                              geo_lat = ?, geo_lon = ?, geo_status = ?
            WHERE source_ip = ? AND geo_status = 'pending'
        ''', (geo.get('country'), geo.get('city'), geo.get('isp'),
              geo.get('lat'), geo.get('lon'), status, ip))
    else:
        c.execute(
            "UPDATE alerts SET geo_status = ? WHERE source_ip = ? AND geo_status = 'pending'",
            (status, ip),
        )
    conn.commit()
    return c.rowcount or 0


# ---------------------------------------------------------------------------
# Reads (dashboard)
# ---------------------------------------------------------------------------

# Worst-first ordering used by both the 24h activity feed and the All Alerts
# page: CRITICAL=0 ... INFO=4, so `ORDER BY {this}, last_seen DESC` always
# puts the most urgent severity on top and, within a severity, the newest
# occurrence on top - a fresh MEDIUM alert then surfaces above older MEDIUMs
# instead of getting lost in a purely chronological list, without a fresh LOW
# ever outranking a standing HIGH/CRITICAL. Built from SEVERITY_ORDER rather
# than hardcoded so the two stay in sync.
_SEVERITY_SQL_RANK = {sev: i for i, sev in enumerate(reversed(SEVERITY_ORDER))}
_SEVERITY_RANK_SQL = 'CASE severity ' + ' '.join(
    f"WHEN '{sev}' THEN {rank}" for sev, rank in _SEVERITY_SQL_RANK.items()
) + ' ELSE 99 END'


def _hydrate_entities(rows: list[dict]) -> list[dict]:
    for row in rows:
        if row.get('entities'):
            try:
                row['entities'] = json.loads(row['entities'])
            except (TypeError, ValueError):
                row['entities'] = {}
    return rows


def get_recent_alerts(limit: int = 200, status: str | None = None, hours: int = 24) -> list[dict]:
    """The main dashboard's Activity Log: only the last `hours` of activity,
    worst severity first and newest-within-that-severity next (see
    _SEVERITY_RANK_SQL). Alerts older than the window still exist and are
    still counted everywhere else - they just roll off this feed onto the
    All Alerts page (get_all_alerts) instead of disappearing.

    `status='open'` narrows to the active view; omitting it shows every
    lifecycle state within the window.
    """
    conn = get_connection()
    c = conn.cursor()
    # last_seen is stored via utc_iso() ('T' separator, +00:00 offset), which
    # SQLite's own datetime('now', ...) does not produce (space separator, no
    # offset) - comparing the two lexicographically silently misorders rows,
    # so the cutoff is built in Python using the same format instead.
    cutoff = utc_iso(datetime.now(timezone.utc) - timedelta(hours=hours))
    if status:
        c.execute(f'''
            SELECT * FROM alerts
            WHERE last_seen >= ? AND status = ?
            ORDER BY {_SEVERITY_RANK_SQL}, last_seen DESC, id DESC
            LIMIT ?
        ''', (cutoff, status, limit))
    else:
        c.execute(f'''
            SELECT * FROM alerts
            WHERE last_seen >= ?
            ORDER BY {_SEVERITY_RANK_SQL}, last_seen DESC, id DESC
            LIMIT ?
        ''', (cutoff, limit))
    rows = _hydrate_entities([dict(r) for r in c.fetchall()])
    conn.close()
    return rows


def get_all_alerts(*, severity: str | None = None, module: str | None = None,
                    status: str | None = None, since: str | None = None,
                    until: str | None = None, search: str | None = None,
                    host: str | None = None, limit: int = 100, offset: int = 0) -> dict:
    """Full alert history for the All Alerts page: worst severity first,
    newest first within a severity (see _SEVERITY_RANK_SQL) - no time window,
    unlike get_recent_alerts. `since`/`until` are ISO datetime strings
    compared against last_seen. `host` backs the Employees page's per-computer
    alert list. Returns the page plus a total count so the frontend can
    render pagination without a second round trip.
    """
    conn = get_connection()
    c = conn.cursor()
    where: list[str] = []
    params: list = []
    if severity:
        where.append('severity = ?')
        params.append(severity.upper())
    if module:
        where.append('module = ?')
        params.append(module)
    if host:
        where.append('host = ?')
        params.append(host)
    if status:
        where.append('status = ?')
        params.append(status)
    if since:
        where.append('last_seen >= ?')
        params.append(since)
    if until:
        where.append('last_seen <= ?')
        params.append(until)
    if search:
        where.append('(description LIKE ? OR source_ip LIKE ?)')
        like = f'%{search}%'
        params.extend([like, like])
    clause = f"WHERE {' AND '.join(where)}" if where else ''

    total = c.execute(f'SELECT COUNT(*) FROM alerts {clause}', params).fetchone()[0]
    c.execute(f'''
        SELECT * FROM alerts {clause}
        ORDER BY {_SEVERITY_RANK_SQL}, last_seen DESC, id DESC
        LIMIT ? OFFSET ?
    ''', (*params, limit, offset))
    rows = _hydrate_entities([dict(r) for r in c.fetchall()])
    conn.close()
    return {'alerts': rows, 'total': total, 'limit': limit, 'offset': offset}


# ---------------------------------------------------------------------------
# Employees (computer -> employee name)
# ---------------------------------------------------------------------------

def set_employee_name(host: str, employee_name: str | None) -> None:
    """Assign (or clear, with employee_name=None) the employee name shown
    for this host on the Employees page."""
    conn = get_connection()
    conn.execute('''
        INSERT INTO computers (host, employee_name, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(host) DO UPDATE SET employee_name = excluded.employee_name,
                                         updated_at = excluded.updated_at
    ''', (host, employee_name, utc_iso()))
    conn.commit()
    conn.close()


def get_employees_overview() -> list[dict]:
    """One row per computer this SOC knows about, each with its
    admin-assigned employee name (if set) and a rollup of its alerts.

    "Known about" includes hosts with zero alerts yet - an enrolled worker
    or this local machine should be nameable before its first alert ever
    fires, not only after.
    """
    conn = get_connection()
    c = conn.cursor()

    rollups: dict[str, dict] = {}
    for row in c.execute('''
        SELECT host,
               COUNT(*) AS total,
               SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_count,
               SUM(CASE WHEN status = 'open' AND severity IN ('HIGH', 'CRITICAL')
                   THEN 1 ELSE 0 END) AS urgent_count,
               MAX(last_seen) AS most_recent
        FROM alerts
        WHERE host IS NOT NULL AND host != ''
        GROUP BY host
    '''):
        rollups[row['host']] = dict(row)

    employee_names = {row['host']: row['employee_name']
                       for row in c.execute('SELECT host, employee_name FROM computers')}
    agent_hosts = {row['name'] for row in c.execute('SELECT name FROM agents')}
    conn.close()

    all_hosts = set(rollups) | agent_hosts | set(employee_names) | {HOSTNAME}

    overview = [{
        'host': host,
        'employee_name': employee_names.get(host),
        'total': rollups.get(host, {}).get('total', 0),
        'open_count': rollups.get(host, {}).get('open_count', 0),
        'urgent_count': rollups.get(host, {}).get('urgent_count', 0),
        'most_recent': rollups.get(host, {}).get('most_recent'),
    } for host in all_hosts]
    overview.sort(key=lambda o: o['most_recent'] or '', reverse=True)
    return overview


def get_alert_stats() -> dict:
    """Aggregate counts for the dashboard charts.

    Done as SQL GROUP BY rather than loading the whole alerts table into pandas -
    the old approach re-read every row every three seconds, so the dashboard got
    slower for as long as the tool kept running.
    """
    conn = get_connection()
    c = conn.cursor()

    c.execute('SELECT module, SUM(occurrence_count) AS n FROM alerts GROUP BY module')
    modules = {r['module']: r['n'] for r in c.fetchall() if r['module']}

    c.execute('SELECT severity, SUM(occurrence_count) AS n FROM alerts GROUP BY severity')
    severities = {r['severity']: r['n'] for r in c.fetchall() if r['severity']}

    c.execute('SELECT COUNT(*) AS rows, COALESCE(SUM(occurrence_count), 0) AS events FROM alerts')
    totals = c.fetchone()

    c.execute("SELECT COUNT(DISTINCT source_ip) AS n FROM alerts WHERE geo_lat IS NOT NULL")
    mapped_origins = c.fetchone()['n']

    conn.close()
    return {
        'modules': modules,
        'severities': severities,
        'total_alerts': totals['rows'],
        'total_events': totals['events'],
        'mapped_origins': mapped_origins,
    }


def get_geomap_points(limit: int = 200) -> list[dict]:
    """One point per source IP for the world map.

    Severity is taken as the *worst* severity seen from that IP rather than an
    arbitrary row's - a bare GROUP BY would let SQLite pick any matching row, so
    a host's marker colour could flip between polls.
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        SELECT source_ip,
               MAX(geo_country) AS geo_country,
               MAX(geo_city)    AS geo_city,
               MAX(geo_isp)     AS geo_isp,
               AVG(geo_lat)     AS geo_lat,
               AVG(geo_lon)     AS geo_lon,
               SUM(occurrence_count) AS hit_count,
               MAX(CASE severity
                     WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4
                     WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 2
                     ELSE 1 END) AS severity_rank
        FROM alerts
        WHERE geo_lat IS NOT NULL AND geo_lon IS NOT NULL
        GROUP BY source_ip
        ORDER BY hit_count DESC
        LIMIT ?
    ''', (limit,))
    rank_to_severity = {5: 'CRITICAL', 4: 'HIGH', 3: 'MEDIUM', 2: 'LOW', 1: 'INFO'}
    rows = []
    for r in c.fetchall():
        row = dict(r)
        row['severity'] = rank_to_severity.get(row.pop('severity_rank'), 'INFO')
        rows.append(row)
    conn.close()
    return rows


def export_alerts_to_csv() -> str:
    """Export alerts to CSV.

    Columns are named explicitly and the header is generated from the cursor
    description, so adding a column to the schema can no longer shift the data
    out from under the headers.
    """
    import csv

    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        SELECT id, timestamp, last_seen, occurrence_count, host, module,
               alert_type, severity, description, source_ip, rule_id, technique,
               entities, raw, geo_country, geo_city, geo_isp, geo_lat, geo_lon,
               status, resolved_at, resolution_note
        FROM alerts ORDER BY timestamp DESC
    ''')
    headers = [d[0] for d in c.description]
    rows = c.fetchall()

    export_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'alerts_export.csv')
    with open(export_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    conn.close()
    return export_path


if __name__ == '__main__':
    init_db()
    print(f'Database initialized at {DB_PATH}')
