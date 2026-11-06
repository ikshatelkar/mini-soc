import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from flask import (  # type: ignore
    Flask, Response, jsonify, redirect, render_template, request, session, url_for,
)

import config  # type: ignore
from core.auth import (  # type: ignore
    clear_attempts, ensure_secret_key, get_csrf_token, hash_password, is_locked_out,
    issue_session_token, login_required, record_failed_attempt, validate_csrf_token,
    verify_login,
)
from core.db import (  # type: ignore
    AdminAlreadyExistsError, AlertNotFoundError, admin_exists, bulk_set_status, connection,
    create_admin_user, create_agent, delete_agent, export_alerts_csv, get_agent_by_token,
    get_all_alerts, get_alert_stats, get_employees_overview, get_geomap_points,
    get_lifecycle_counts, get_needs_attention, get_recent_alerts, init_db, list_agents,
    parse_iso_utc,
    set_admin_session_token, set_alert_status, set_employee_name, touch_agent_last_seen,
)
from core.detect import engine, load_ruleset, process_winevt  # type: ignore
from core.dummy_log_generator import run_generator  # type: ignore
from core.fim import get_monitoring_scope, start_fim_monitor  # type: ignore
from core.log_parser import start_log_monitor  # type: ignore
from core.network_monitor import monitor_status, start_network_monitor  # type: ignore
from core.notify import meets_notification_floor  # type: ignore
from core.pipeline import pipeline  # type: ignore
from core.winevt import collector_stats, start_event_log_collectors  # type: ignore

app = Flask(__name__)
app.secret_key = ensure_secret_key()
app.permanent_session_lifetime = timedelta(hours=config.SESSION_LIFETIME_HOURS)
app.jinja_env.globals['csrf_token'] = get_csrf_token
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=config.FORCE_SECURE_COOKIES,
)

# Paths that legitimately receive a state-changing request without a browser
# session cookie at all, so there is no CSRF token to check:
#  - /api/ingest: agent bearer-token auth (core/db.py's agents table), never
#    a cookie holder.
#  - /api/notifications/pending: GET-only already, exempt via the safe-method
#    check below, not listed here.
_CSRF_EXEMPT_PATHS = {'/api/ingest'}


@app.before_request
def _enforce_csrf():
    """Reject any state-changing request that doesn't echo back this
    session's CSRF token - see core/auth.py for how the token is minted and
    checked. Runs before login_required, so an unauthenticated POST/DELETE
    still gets rejected here rather than leaking whether a route exists."""
    if request.method in ('GET', 'HEAD', 'OPTIONS') or request.path in _CSRF_EXEMPT_PATHS:
        return None
    candidate = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
    if not validate_csrf_token(candidate):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'invalid or missing CSRF token'}), 400
        return 'Invalid or expired form submission. Go back and try again.', 400
    return None


@app.after_request
def _security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    return response


def _json_body() -> dict:
    """The request's JSON object, or {} for a missing/invalid body or any
    non-object JSON value (a list, a string) - so handlers can call .get()
    without a stray payload turning into a 500."""
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


def _safe_next(next_path: str | None) -> str | None:
    """`next_path` if it is a same-site path, else None.

    Starting with a single '/' is not enough on its own: browsers treat
    '/\\evil.com' like '//evil.com' (protocol-relative, off-site), and strip
    tabs/newlines before resolving, so '/\\t/evil.com' collapses to
    '//evil.com' too.
    """
    if not next_path or not next_path.startswith('/'):
        return None
    if '\\' in next_path or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in next_path):
        return None
    if next_path.startswith('//'):
        return None
    return next_path


def _utc_aware(when: datetime) -> datetime:
    """Treat a naive datetime as UTC. Mixing naive and aware datetimes raises
    TypeError on comparison, which is what the correlator and agent-status
    checks do with these."""
    return when.replace(tzinfo=timezone.utc) if when.tzinfo is None else when


def start_background_services() -> None:
    """Initialize storage and start the pipeline plus all detection modules."""
    print('[*] Initializing Mini SOC Services...')
    init_db()
    # Rules load before any collector starts, so no telemetry arrives before
    # there is something to evaluate it against.
    load_ruleset()
    pipeline.start()

    if config.USE_DUMMY_DATA:
        threading.Thread(target=run_generator, args=(config.DUMMY_LOG_INTERVAL,),
                         daemon=True, name='dummy-generator').start()
    else:
        print('[*] Running in Production Mode (no synthetic logs generated)')

    threading.Thread(target=start_fim_monitor, daemon=True, name='fim').start()
    threading.Thread(target=start_log_monitor, daemon=True, name='log-monitor').start()
    threading.Thread(target=start_network_monitor, daemon=True, name='network-monitor').start()

    if config.WINEVT_ENABLED:
        start_event_log_collectors(process_winevt)


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """One-time admin account creation. Always redirects to /login once an
    account exists, regardless of session state - so this can never be used
    later to add a second, unapproved admin."""
    if admin_exists():
        return redirect(url_for('login'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        if not username or not password:
            error = 'Username and password are required.'
        elif len(password) < 8:
            error = 'Password must be at least 8 characters.'
        elif password != confirm:
            error = 'Passwords do not match.'
        else:
            try:
                create_admin_user(username, hash_password(password))
            except AdminAlreadyExistsError:
                pass  # lost a race with another /setup submission - that one wins
            return redirect(url_for('login'))
    return render_template('setup.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if not admin_exists():
        return redirect(url_for('setup'))
    if session.get('admin_id') is not None:
        return redirect(url_for('index'))

    error = None
    # Set by login_required when it clears a session it found stale because
    # this admin logged in somewhere else - see core/auth.py's
    # session_is_current(). Told apart from a plain "not logged in" so it
    # doesn't look like a random, unexplained logout.
    notice = ('This account was signed in somewhere else, so this session was '
              'signed out.') if request.args.get('reason') == 'elsewhere' else None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if is_locked_out(username):
            error = 'Too many failed attempts. Try again in a few minutes.'
        else:
            user = verify_login(username, password)
            if user is None:
                record_failed_attempt(username)
                error = 'Incorrect username or password.'
            else:
                clear_attempts(username)
                session.clear()
                session.permanent = True
                session['admin_id'] = user['id']
                session['admin_username'] = user['username']
                # Overwrites the admin's stored token, so any session cookie
                # issued by a previous login - this browser or another one -
                # stops authenticating on its very next request.
                session['session_token'] = issue_session_token(user['id'])
                # Only ever redirect somewhere inside this app - an unchecked
                # `next` value could otherwise send a fresh login to an
                # attacker-controlled URL. See _safe_next().
                return redirect(_safe_next(request.args.get('next')) or url_for('index'))
    return render_template('login.html', error=error, notice=notice)


@app.route('/logout', methods=['POST'])
def logout():
    admin_id = session.get('admin_id')
    if admin_id is not None:
        # Clears the stored token outright rather than leaving the old one in
        # place, so a captured-but-not-yet-used cookie can't sign back in
        # after an explicit logout either.
        set_admin_session_token(admin_id, None)
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    return render_template('index.html', active_page='home')


_ALL_ALERTS_VIEWS = {
    'open': ('active', 'Active Alerts', 'Still open, worst severity first'),
    'acknowledged': ('handled', 'Handled Alerts', 'Handled, worst severity first'),
    'dismissed': ('dismissed', 'Dismissed Alerts', 'Dismissed, worst severity first'),
}


@app.route('/alerts')
@login_required
def all_alerts_page():
    """One page backs all four "go to a new page" toggles (All Alerts,
    Active, Handled, Dismissed) - they're the same filtered view, reached via
    ?status=, so the heading below just reflects whichever one was clicked.
    """
    active_page, heading, subtitle = _ALL_ALERTS_VIEWS.get(
        request.args.get('status'), ('all', 'All Alerts', 'Full history, worst severity first'))
    return render_template('all_alerts.html', active_page=active_page, heading=heading, subtitle=subtitle)


@app.route('/map')
@login_required
def map_page():
    return render_template('map.html', active_page='map')


@app.route('/employees')
@login_required
def employees_page():
    return render_template('employees.html', active_page='employees')


@app.route('/api/alerts')
@login_required
def api_alerts():
    """The dashboard's Activity Log: last 24h only, worst severity first -
    see get_recent_alerts(). Optionally filtered by lifecycle status via
    ?status=open etc. Full, unbounded history lives at /api/alerts/all."""
    status = request.args.get('status')
    if status and status not in ('open', 'acknowledged', 'dismissed'):
        return jsonify({'error': f"invalid status '{status}'"}), 400
    return jsonify(get_recent_alerts(status=status))


_VALID_SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')


@app.route('/api/alerts/all')
@login_required
def api_alerts_all():
    """The All Alerts page: full history, worst severity first, with the
    filter/pagination options its toolbar exposes - see get_all_alerts()."""
    status = request.args.get('status')
    if status and status not in ('open', 'acknowledged', 'dismissed'):
        return jsonify({'error': f"invalid status '{status}'"}), 400
    severity = request.args.get('severity')
    if severity and severity.upper() not in _VALID_SEVERITIES:
        return jsonify({'error': f"invalid severity '{severity}'"}), 400
    # Clamped on both ends: SQLite treats a negative LIMIT as "no limit", so an
    # unclamped ?limit=-1 would return the entire table in one response.
    limit = max(1, min(request.args.get('limit', 100, type=int), 500))
    offset = max(request.args.get('offset', 0, type=int), 0)
    since, until = request.args.get('since'), request.args.get('until')
    try:
        since = parse_iso_utc(since) if since else None
        until = parse_iso_utc(until) if until else None
    except ValueError:
        return jsonify({'error': "'since'/'until' must be ISO 8601 datetimes"}), 400
    return jsonify(get_all_alerts(
        severity=severity, module=request.args.get('module'), status=status,
        since=since, until=until,
        search=request.args.get('search'), host=request.args.get('host'),
        limit=limit, offset=offset,
    ))


@app.route('/api/employees', methods=['GET', 'POST'])
@login_required
def api_employees():
    """GET: one row per known computer with its assigned employee name and
    alert rollup, for the Employees page. POST: assign/clear the employee
    name for one host - see core/db.py's set_employee_name()."""
    if request.method == 'POST':
        body = _json_body()
        host = body.get('host')
        employee_name = body.get('employee_name')
        if not isinstance(host, str) or not host.strip():
            return jsonify({'error': 'host is required'}), 400
        if employee_name is not None and not isinstance(employee_name, str):
            return jsonify({'error': 'employee_name must be a string'}), 400
        host = host.strip()
        employee_name = (employee_name or '').strip() or None
        set_employee_name(host, employee_name)
        return jsonify({'host': host, 'employee_name': employee_name})
    return jsonify(get_employees_overview())


@app.route('/api/alerts/needs-attention')
@login_required
def api_alerts_needs_attention():
    """Open HIGH/CRITICAL alerts - the dashboard's headline list.

    A separate endpoint rather than a query filter on /api/alerts because this
    one has its own ordering (critical first) and is polled more eagerly by the
    hero section.
    """
    return jsonify(get_needs_attention())


def _change_alert_status(alert_id: int, status: str, note=None):
    if note is not None and not isinstance(note, str):
        note = str(note)
    try:
        with connection() as conn:
            return jsonify(set_alert_status(conn, alert_id, status, note=note))
    except AlertNotFoundError as exc:
        return jsonify({'error': str(exc)}), 404


@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@login_required
def api_alert_acknowledge(alert_id):
    return _change_alert_status(alert_id, 'acknowledged', _json_body().get('note'))


@app.route('/api/alerts/<int:alert_id>/dismiss', methods=['POST'])
@login_required
def api_alert_dismiss(alert_id):
    return _change_alert_status(alert_id, 'dismissed', _json_body().get('note'))


@app.route('/api/alerts/<int:alert_id>/reopen', methods=['POST'])
@login_required
def api_alert_reopen(alert_id):
    """Undo an acknowledge/dismiss - mistakes should be one click to fix."""
    return _change_alert_status(alert_id, 'open')


@app.route('/api/alerts/bulk-resolve', methods=['POST'])
@login_required
def api_alerts_bulk_resolve():
    """Resolve every open alert matching a filter in one action.

    For the case where a whole category is known-fine and re-clicking each row
    would just teach someone to stop using the button. Tuning the rule itself
    (rules/exceptions.yaml) is still the right fix for a *permanent* false
    positive - this is for clearing a backlog, not replacing that.
    """
    body = _json_body()
    status = body.get('status', 'acknowledged')
    if status not in ('acknowledged', 'dismissed'):
        return jsonify({'error': "status must be 'acknowledged' or 'dismissed'"}), 400
    max_severity = body.get('max_severity')
    # An unrecognised ceiling would silently rank as the lowest severity and
    # resolve far less than intended - reject it instead.
    if max_severity is not None and (not isinstance(max_severity, str)
                                     or max_severity.upper() not in _VALID_SEVERITIES):
        return jsonify({'error': f'max_severity must be one of {list(_VALID_SEVERITIES)}'}), 400
    module = body.get('module')
    if module is not None and not isinstance(module, str):
        return jsonify({'error': 'module must be a string'}), 400
    with connection() as conn:
        count = bulk_set_status(conn, status, module=module, max_severity=max_severity)
    return jsonify({'updated': count, 'status': status})


@app.route('/api/notifications/pending')
def api_notifications_pending():
    """New alerts worth a popup, for the notifier companion to poll.

    The notifier runs in the user's desktop session rather than inside the
    Windows Service (which cannot show UI - see the module notes in
    notifier.py), so it discovers new alerts by polling this rather than
    receiving them in-process. Filtering happens here, server-side, via the
    exact same meets_notification_floor() the in-process desktop dispatcher
    uses - so the notifier can never drift out of sync with what the engine
    itself considers notify-worthy.

    Not behind @login_required: notifier.py calls this with a bare
    urllib.request and no cookie jar, so it can never hold a browser session.
    Instead this accepts unauthenticated calls only from the local machine
    itself (config.WEB_HOST is already 127.0.0.1-only today, so this changes
    nothing about what's reachable now) and still requires a real session for
    anyone else - the moment the dashboard is ever bound to a LAN interface,
    a remote caller can no longer read alerts through this endpoint.
    """
    # "Local" = loopback, or this machine's own configured address: when the
    # dashboard is bound to one specific LAN IP, the notifier on this machine
    # has to dial that IP, and the connection then comes *from* that IP.
    local_addrs = {'127.0.0.1', '::1'}
    if config.WEB_HOST not in ('0.0.0.0', '::', ''):
        local_addrs.add(config.WEB_HOST)
    if request.remote_addr not in local_addrs and session.get('admin_id') is None:
        return jsonify({'error': 'authentication required'}), 401

    since_id = request.args.get('since_id', 0, type=int)
    if since_id < 0:
        # Bootstrap for a notifier with no saved position (first run, or its
        # state file was lost): hand back only the current high-water mark,
        # so it starts from "now" instead of replaying the entire alert
        # history as popups 100 at a time.
        with connection() as conn:
            max_id = conn.execute('SELECT COALESCE(MAX(id), 0) FROM alerts').fetchone()[0]
        return jsonify({'alerts': [], 'max_id': max_id})

    with connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM alerts WHERE id > ? ORDER BY id ASC LIMIT 100', (since_id,))
        rows = [dict(r) for r in c.fetchall()]

    pending = [r for r in rows if meets_notification_floor(r['module'], r['severity'])]
    max_id = rows[-1]['id'] if rows else since_id
    return jsonify({'alerts': pending, 'max_id': max_id})


@app.route('/api/stats')
@login_required
def api_stats():
    stats = get_alert_stats()
    stats['lifecycle'] = get_lifecycle_counts()
    return jsonify(stats)


@app.route('/api/geomap')
@login_required
def api_geomap():
    return jsonify(get_geomap_points())


@app.route('/api/health')
@login_required
def api_health():
    """Operational status: is detection keeping up, is anything stuck, what's
    being watched. This is what an unattended service needs exposed so a
    problem shows up before the dashboard goes quiet."""
    channels = collector_stats()
    degraded = [c for c in channels if c['status'] not in ('running', 'not_available')]

    return jsonify({
        # 'degraded' when a telemetry source we expect to have is unavailable, so
        # a partially-blind deployment is visible instead of looking healthy.
        'status': 'degraded' if degraded else 'ok',
        'pipeline': pipeline.stats(),
        'detection': engine.stats(),
        'event_log_channels': channels,
        'network_monitor': monitor_status(),
        'fim_scope': get_monitoring_scope(),
        'config': {
            'use_dummy_data': config.USE_DUMMY_DATA,
            'retention_days': config.RETENTION_DAYS,
            'geo_enrichment_enabled': config.GEO_ENRICHMENT_ENABLED,
            'winevt_enabled': config.WINEVT_ENABLED,
            'notify_min_severity': config.NOTIFY_MIN_SEVERITY,
        },
    })


@app.route('/api/rules')
@login_required
def api_rules():
    """Loaded detection rules, exceptions and ATT&CK coverage.

    Makes the tool answer "what do we actually detect?" about itself, and
    surfaces rules that failed to load - a silently skipped rule is a blind spot
    that would otherwise be invisible.
    """
    return jsonify({
        'summary': engine.stats(),
        'rules': engine.rule_summaries(),
        'exceptions': engine.exception_summaries(),
    })


@app.route('/api/rules/reload', methods=['POST'])
@login_required
def api_rules_reload():
    """Re-read the rules directory without restarting.

    Tuning a threshold or adding an exception should not require taking
    monitoring offline, which is exactly when you would miss something.
    """
    stats = load_ruleset()
    return jsonify({'reloaded': True, 'summary': stats})


@app.route('/api/export')
@login_required
def api_export():
    return Response(
        export_alerts_csv(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=alerts_export.csv',
                 'Cache-Control': 'no-store'},
    )


# ---------------------------------------------------------------------------
# Phase 5: multi-host (agent enrollment + ingestion)
# ---------------------------------------------------------------------------

def _agent_status(agent: dict) -> str:
    """'online' within 2 heartbeat intervals of last check-in, else 'offline' -
    the coarse dead-man's-switch signal agreed for this pass: not tamper
    prevention, but an unexplained silence is visible on the dashboard."""
    if not agent['last_seen']:
        return 'never connected'
    try:
        last_seen = _utc_aware(datetime.fromisoformat(agent['last_seen']))
    except (TypeError, ValueError):
        return 'offline'
    threshold = timedelta(seconds=2 * config.AGENT_HEARTBEAT_SECONDS)
    return 'online' if (datetime.now(timezone.utc) - last_seen) <= threshold else 'offline'


@app.route('/api/agents', methods=['GET', 'POST'])
@login_required
def api_agents():
    """Enroll (POST) or list (GET) worker agents. Admin-only, like every other
    dashboard route - the token this returns is what lets a worker forward
    events at all, so only the signed-in admin should ever mint one."""
    if request.method == 'POST':
        name = _json_body().get('name')
        name = name.strip() if isinstance(name, str) else ''
        if not name:
            return jsonify({'error': 'name is required'}), 400
        try:
            agent_id, token = create_agent(name)
        except sqlite3.IntegrityError:
            return jsonify({'error': f"an agent named '{name}' already exists"}), 409
        # The only time this token is ever returned - core/db.py stores just its
        # hash, so losing this response means re-enrolling, not a lockout risk.
        return jsonify({'agent_id': agent_id, 'name': name, 'token': token}), 201

    agents = []
    for agent in list_agents():
        row = {k: v for k, v in agent.items() if k != 'token_hash'}
        row['status'] = _agent_status(agent)
        agents.append(row)
    return jsonify(agents)


@app.route('/api/agents/<int:agent_id>', methods=['DELETE'])
@login_required
def api_agent_delete(agent_id):
    """Revoke an agent's access. Its token stops working on the very next
    /api/ingest call - decommissioning or suspecting a worker is compromised
    should not require touching that machine at all."""
    if not delete_agent(agent_id):
        return jsonify({'error': f'no agent with id {agent_id}'}), 404
    return jsonify({'deleted': agent_id})


@app.route('/api/ingest', methods=['POST'])
def api_ingest():
    """Where an agent's forwarded events land - see core/forwarder.py.

    Not behind @login_required: an agent is a machine with a bearer token
    (core/db.py's agents table), never a browser holding the admin's session
    cookie. Doubles as the agent's heartbeat - a call with an empty `events`
    list still updates last_seen, which is what lets /api/agents show
    'offline' when a worker goes quiet unexpectedly.
    """
    auth_header = request.headers.get('Authorization', '')
    token = auth_header[len('Bearer '):] if auth_header.startswith('Bearer ') else ''
    agent = get_agent_by_token(token) if token else None
    if agent is None:
        return jsonify({'error': 'invalid or missing agent token'}), 401
    touch_agent_last_seen(agent['id'])

    body = request.get_json(silent=True)
    if body is None:
        body = {}
    if not isinstance(body, dict):
        return jsonify({'error': 'body must be a JSON object'}), 400
    events = body.get('events') or []
    if not isinstance(events, list):
        return jsonify({'error': "'events' must be a list"}), 400
    if len(events) > config.AGENT_INGEST_BATCH_LIMIT:
        return jsonify({
            'error': f'batch of {len(events)} exceeds AGENT_INGEST_BATCH_LIMIT '
                    f'({config.AGENT_INGEST_BATCH_LIMIT})',
        }), 400

    processed = 0
    for event in events:
        if not isinstance(event, dict):
            continue
        try:
            # Missing/garbage time: use arrival time rather than dropping the
            # event or letting a None reach the correlator's window arithmetic.
            when = event.get('time')
            try:
                event['time'] = _utc_aware(datetime.fromisoformat(when))
            except (TypeError, ValueError):
                event['time'] = datetime.now(timezone.utc)

            # Attribution comes from the authenticated agent, never from the
            # payload. The token proves *which enrolled worker* is talking;
            # the body is attacker-controlled if a token is ever stolen, so
            # trusting its 'host' would let one worker file alerts against
            # another machine - forging activity onto a colleague's PC, or
            # burying its own by attributing it elsewhere.
            #
            # The machine's self-reported hostname is kept separately rather
            # than discarded: it is genuinely useful for triage, and it
            # legitimately differs from the agent name (the admin labels a
            # worker at enrollment, e.g. 'FRONT-DESK-PC', which need not match
            # what Windows calls itself). A difference here is normal, not a
            # signal - which is exactly why it cannot be the trusted field.
            reported_hostname = event.get('host')
            event['host'] = agent['name']
            if reported_hostname:
                event['reported_hostname'] = reported_hostname

            engine.process(event)
            processed += 1
        except Exception as exc:
            # One malformed event from a forwarding agent should not take down
            # ingestion for the rest of its batch, mirroring the writer loop's
            # per-alert isolation in core/pipeline.py.
            print(f"[!] Failed to process event forwarded by agent "
                 f"'{agent['name']}': {exc}")
    return jsonify({'received': processed})


if __name__ == '__main__':
    # Waitress rather than Flask's built-in server: the latter prints its own
    # warning against unattended use, and waitress is the free, standard choice
    # for actually doing that on Windows (gunicorn needs fork(), which Windows
    # doesn't have). service.py runs the same call for the background-service
    # path, so manual runs and the service behave identically.
    import waitress  # type: ignore
    start_background_services()
    waitress.serve(app, host=config.WEB_HOST, port=config.WEB_PORT)
