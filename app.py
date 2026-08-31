import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from flask import (  # type: ignore
    Flask, jsonify, redirect, render_template, request, send_file, session, url_for,
)

import config  # type: ignore
from core.auth import (  # type: ignore
    clear_attempts, ensure_secret_key, hash_password, is_locked_out, login_required,
    record_failed_attempt, verify_login,
)
from core.db import (  # type: ignore
    AlertNotFoundError, admin_exists, bulk_set_status, create_admin_user, create_agent,
    delete_agent, export_alerts_to_csv, get_agent_by_token, get_alert_stats,
    get_connection, get_geomap_points, get_lifecycle_counts, get_needs_attention,
    get_recent_alerts, init_db, list_agents, set_alert_status, touch_agent_last_seen,
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
            create_admin_user(username, hash_password(password))
            return redirect(url_for('login'))
    return render_template('setup.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if not admin_exists():
        return redirect(url_for('setup'))
    if session.get('admin_id') is not None:
        return redirect(url_for('index'))

    error = None
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
                next_path = request.args.get('next', '')
                # Only ever redirect somewhere inside this app - an unchecked
                # `next` value could otherwise send a fresh login to an
                # attacker-controlled URL.
                dest = next_path if next_path.startswith('/') and not next_path.startswith('//') else url_for('index')
                return redirect(dest)
    return render_template('login.html', error=error)


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/api/alerts')
@login_required
def api_alerts():
    """Alerts, optionally filtered by lifecycle status via ?status=open etc.
    Omit the filter for the full history view."""
    status = request.args.get('status')
    if status and status not in ('open', 'acknowledged', 'dismissed'):
        return jsonify({'error': f"invalid status '{status}'"}), 400
    return jsonify(get_recent_alerts(status=status))


@app.route('/api/alerts/needs-attention')
@login_required
def api_alerts_needs_attention():
    """Open HIGH/CRITICAL alerts - the dashboard's headline list.

    A separate endpoint rather than a query filter on /api/alerts because this
    one has its own ordering (critical first) and is polled more eagerly by the
    hero section.
    """
    return jsonify(get_needs_attention())


@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@login_required
def api_alert_acknowledge(alert_id):
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(set_alert_status(get_connection(), alert_id, 'acknowledged',
                                        note=body.get('note')))
    except AlertNotFoundError as exc:
        return jsonify({'error': str(exc)}), 404


@app.route('/api/alerts/<int:alert_id>/dismiss', methods=['POST'])
@login_required
def api_alert_dismiss(alert_id):
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(set_alert_status(get_connection(), alert_id, 'dismissed',
                                        note=body.get('note')))
    except AlertNotFoundError as exc:
        return jsonify({'error': str(exc)}), 404


@app.route('/api/alerts/<int:alert_id>/reopen', methods=['POST'])
@login_required
def api_alert_reopen(alert_id):
    """Undo an acknowledge/dismiss - mistakes should be one click to fix."""
    try:
        return jsonify(set_alert_status(get_connection(), alert_id, 'open'))
    except AlertNotFoundError as exc:
        return jsonify({'error': str(exc)}), 404


@app.route('/api/alerts/bulk-resolve', methods=['POST'])
@login_required
def api_alerts_bulk_resolve():
    """Resolve every open alert matching a filter in one action.

    For the case where a whole category is known-fine and re-clicking each row
    would just teach someone to stop using the button. Tuning the rule itself
    (rules/exceptions.yaml) is still the right fix for a *permanent* false
    positive - this is for clearing a backlog, not replacing that.
    """
    body = request.get_json(silent=True) or {}
    status = body.get('status', 'acknowledged')
    if status not in ('acknowledged', 'dismissed'):
        return jsonify({'error': "status must be 'acknowledged' or 'dismissed'"}), 400
    count = bulk_set_status(get_connection(), status,
                            module=body.get('module'),
                            max_severity=body.get('max_severity'))
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
    if request.remote_addr != '127.0.0.1' and session.get('admin_id') is None:
        return jsonify({'error': 'authentication required'}), 401

    since_id = request.args.get('since_id', 0, type=int)
    conn = get_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM alerts WHERE id > ? ORDER BY id ASC LIMIT 100', (since_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()

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
    csv_path = export_alerts_to_csv()
    return send_file(csv_path, as_attachment=True)


# ---------------------------------------------------------------------------
# Phase 5: multi-host (agent enrollment + ingestion)
# ---------------------------------------------------------------------------

def _agent_status(agent: dict) -> str:
    """'online' within 2 heartbeat intervals of last check-in, else 'offline' -
    the coarse dead-man's-switch signal agreed for this pass: not tamper
    prevention, but an unexplained silence is visible on the dashboard."""
    if not agent['last_seen']:
        return 'never connected'
    last_seen = datetime.fromisoformat(agent['last_seen'])
    threshold = timedelta(seconds=2 * config.AGENT_HEARTBEAT_SECONDS)
    return 'online' if (datetime.now(timezone.utc) - last_seen) <= threshold else 'offline'


@app.route('/api/agents', methods=['GET', 'POST'])
@login_required
def api_agents():
    """Enroll (POST) or list (GET) worker agents. Admin-only, like every other
    dashboard route - the token this returns is what lets a worker forward
    events at all, so only the signed-in admin should ever mint one."""
    if request.method == 'POST':
        body = request.get_json(silent=True) or {}
        name = (body.get('name') or '').strip()
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

    body = request.get_json(silent=True) or {}
    events = body.get('events') or []
    if len(events) > config.AGENT_INGEST_BATCH_LIMIT:
        return jsonify({
            'error': f'batch of {len(events)} exceeds AGENT_INGEST_BATCH_LIMIT '
                    f'({config.AGENT_INGEST_BATCH_LIMIT})',
        }), 400

    processed = 0
    for event in events:
        try:
            when = event.get('time')
            if isinstance(when, str):
                event['time'] = datetime.fromisoformat(when)
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
