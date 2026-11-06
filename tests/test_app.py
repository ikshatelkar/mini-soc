"""HTTP-level tests for app.py: auth, CSRF, alert APIs, agents and ingest."""

from datetime import datetime, timedelta, timezone

import pytest

import config
from core import db
from core.events import Alert
from tests.conftest import ADMIN_PASS, ADMIN_USER, csrf_from, post_json


def seed_alert(**kw):
    defaults = dict(module='FIM', alert_type='t', severity='HIGH', description='d', host='H')
    defaults.update(kw)
    conn = db.get_connection()
    _, alert_id = db.insert_or_aggregate(conn, Alert(**defaults), 300)
    conn.close()
    return alert_id


# -- setup / login -------------------------------------------------------------

def test_fresh_install_redirects_to_setup(client):
    assert client.get('/login').headers['Location'].endswith('/setup')
    assert client.get('/').status_code == 302


def test_setup_validation_and_creation(client):
    client.get('/setup')
    token = csrf_from(client)
    resp = client.post('/setup', data={'username': 'a', 'password': 'short', 'confirm': 'short',
                                       'csrf_token': token})
    assert b'at least 8' in resp.data
    resp = client.post('/setup', data={'username': 'a', 'password': 'longenough1',
                                       'confirm': 'different1', 'csrf_token': token})
    assert b'do not match' in resp.data
    resp = client.post('/setup', data={'username': 'a', 'password': 'longenough1',
                                       'confirm': 'longenough1', 'csrf_token': token})
    assert resp.status_code == 302 and db.admin_exists()
    # setup is closed for good afterwards
    assert client.get('/setup').headers['Location'].endswith('/login')


def test_post_without_csrf_rejected(client):
    assert client.post('/setup', data={'username': 'a'}).status_code == 400
    assert client.post('/api/alerts/1/acknowledge').status_code == 400


def test_login_and_logout(logged_in):
    assert logged_in.get('/').status_code == 200
    assert logged_in.get('/api/stats').status_code == 200
    token = csrf_from(logged_in)
    assert logged_in.post('/logout', data={'csrf_token': token}).status_code == 302
    assert logged_in.get('/api/stats').status_code == 401


def test_wrong_password_and_lockout(client):
    from core.auth import hash_password
    db.create_admin_user(ADMIN_USER, hash_password(ADMIN_PASS))
    client.get('/login')
    token = csrf_from(client)
    for _ in range(config.LOGIN_MAX_ATTEMPTS):
        resp = client.post('/login', data={'username': ADMIN_USER, 'password': 'nope',
                                           'csrf_token': token})
        assert b'Incorrect' in resp.data
    resp = client.post('/login', data={'username': ADMIN_USER, 'password': ADMIN_PASS,
                                       'csrf_token': token})
    assert b'Too many failed attempts' in resp.data


@pytest.mark.parametrize('next_url,expected', [
    ('/alerts', '/alerts'),
    ('//evil.com', '/'),
    ('/\\evil.com', '/'),
    ('https://evil.com', '/'),
    ('/\t/evil.com', '/'),
])
def test_login_next_redirect_is_local_only(client, next_url, expected):
    from core.auth import hash_password
    db.create_admin_user(ADMIN_USER, hash_password(ADMIN_PASS))
    client.get('/login')
    token = csrf_from(client)
    resp = client.post('/login', query_string={'next': next_url},
                       data={'username': ADMIN_USER, 'password': ADMIN_PASS, 'csrf_token': token})
    assert resp.status_code == 302
    assert resp.headers['Location'] == expected


def test_login_elsewhere_supersedes_session(app_module, logged_in):
    other = app_module.app.test_client()
    other.get('/login')
    token = csrf_from(other)
    other.post('/login', data={'username': ADMIN_USER, 'password': ADMIN_PASS, 'csrf_token': token})
    resp = logged_in.get('/api/stats')
    assert resp.status_code == 401 and resp.get_json()['reason'] == 'session_superseded'
    assert other.get('/api/stats').status_code == 200


def test_security_headers(client):
    resp = client.get('/login')
    assert resp.headers['X-Frame-Options'] == 'DENY'
    assert resp.headers['X-Content-Type-Options'] == 'nosniff'


# -- alert APIs -----------------------------------------------------------------

def test_alert_lifecycle_endpoints(logged_in):
    alert_id = seed_alert()
    resp = post_json(logged_in, f'/api/alerts/{alert_id}/acknowledge', {'note': 'ok'})
    assert resp.status_code == 200 and resp.get_json()['status'] == 'acknowledged'
    assert post_json(logged_in, f'/api/alerts/{alert_id}/reopen').get_json()['status'] == 'open'
    assert post_json(logged_in, f'/api/alerts/{alert_id}/dismiss').get_json()['status'] == 'dismissed'
    assert post_json(logged_in, '/api/alerts/999/dismiss').status_code == 404


def test_lifecycle_endpoints_tolerate_non_object_json(logged_in):
    alert_id = seed_alert()
    resp = post_json(logged_in, f'/api/alerts/{alert_id}/acknowledge', ['not', 'a', 'dict'])
    assert resp.status_code == 200


def test_bulk_resolve(logged_in):
    seed_alert(severity='LOW', alert_type='a')
    seed_alert(severity='CRITICAL', alert_type='b')
    resp = post_json(logged_in, '/api/alerts/bulk-resolve', {'status': 'dismissed', 'max_severity': 'MEDIUM'})
    assert resp.get_json() == {'updated': 1, 'status': 'dismissed'}
    assert post_json(logged_in, '/api/alerts/bulk-resolve', {'status': 'open'}).status_code == 400
    assert post_json(logged_in, '/api/alerts/bulk-resolve', {'max_severity': 'BOGUS'}).status_code == 400


def test_alert_listing_validation(logged_in):
    seed_alert()
    assert len(logged_in.get('/api/alerts').get_json()) == 1
    assert logged_in.get('/api/alerts?status=bogus').status_code == 400
    assert logged_in.get('/api/alerts/all?severity=bogus').status_code == 400
    assert logged_in.get('/api/alerts/all?since=not-a-date').status_code == 400
    data = logged_in.get('/api/alerts/all?severity=high').get_json()
    assert data['total'] == 1


def test_alert_listing_clamps_limit(logged_in):
    for i in range(3):
        seed_alert(alert_type=str(i))
    data = logged_in.get('/api/alerts/all?limit=-1').get_json()
    assert data['limit'] >= 1 and len(data['alerts']) <= data['limit']
    assert logged_in.get('/api/alerts/all?limit=100000').get_json()['limit'] == 500


def test_needs_attention_stats_geomap_health_rules(logged_in):
    seed_alert(severity='CRITICAL')
    assert len(logged_in.get('/api/alerts/needs-attention').get_json()) == 1
    stats = logged_in.get('/api/stats').get_json()
    assert stats['lifecycle']['needs_attention'] == 1
    assert logged_in.get('/api/geomap').get_json() == []
    health = logged_in.get('/api/health').get_json()
    assert health['status'] in ('ok', 'degraded') and 'pipeline' in health
    from core.detect import load_ruleset
    load_ruleset()
    rules = logged_in.get('/api/rules').get_json()
    assert rules['summary']['rules_loaded'] > 0
    assert post_json(logged_in, '/api/rules/reload').get_json()['reloaded'] is True


def test_export_csv(logged_in):
    seed_alert(description='=1+1')
    resp = logged_in.get('/api/export')
    assert resp.status_code == 200
    body = resp.data.decode('utf-8')
    assert body.startswith('id,')
    assert "'=1+1" in body
    assert 'attachment' in resp.headers['Content-Disposition']


def test_employees_api(logged_in):
    assert post_json(logged_in, '/api/employees', {'host': ''}).status_code == 400
    assert post_json(logged_in, '/api/employees', ['x']).status_code == 400
    resp = post_json(logged_in, '/api/employees', {'host': 'PC-9', 'employee_name': ' Bob '})
    assert resp.get_json() == {'host': 'PC-9', 'employee_name': 'Bob'}
    hosts = {r['host']: r for r in logged_in.get('/api/employees').get_json()}
    assert hosts['PC-9']['employee_name'] == 'Bob'


def test_api_requires_login(client):
    for path in ['/api/alerts', '/api/alerts/all', '/api/stats', '/api/health', '/api/agents',
                 '/api/employees', '/api/export', '/api/rules', '/api/geomap']:
        assert client.get(path).status_code == 401, path


# -- notifications ----------------------------------------------------------------

def test_notifications_pending_local_only(client):
    seed_alert(severity='HIGH', alert_type='a')
    seed_alert(severity='INFO', alert_type='b')
    resp = client.get('/api/notifications/pending?since_id=0')
    data = resp.get_json()
    assert [a['severity'] for a in data['alerts']] == ['HIGH']
    assert data['max_id'] == 2
    remote = client.get('/api/notifications/pending', environ_base={'REMOTE_ADDR': '10.0.0.9'})
    assert remote.status_code == 401


def test_notifications_pending_bootstrap_returns_latest_id(client):
    for i in range(3):
        seed_alert(alert_type=str(i))
    data = client.get('/api/notifications/pending?since_id=-1').get_json()
    assert data == {'alerts': [], 'max_id': 3}


# -- agents + ingest -----------------------------------------------------------------

def enroll(client, name='WORKER-1'):
    resp = post_json(client, '/api/agents', {'name': name})
    assert resp.status_code == 201
    return resp.get_json()['token']


def test_agent_enrollment_listing_and_revocation(logged_in):
    token = enroll(logged_in)
    assert post_json(logged_in, '/api/agents', {'name': 'WORKER-1'}).status_code == 409
    assert post_json(logged_in, '/api/agents', {'name': ' '}).status_code == 400
    agents = logged_in.get('/api/agents').get_json()
    assert agents[0]['status'] == 'never connected' and 'token_hash' not in agents[0]
    agent_id = agents[0]['id']
    assert post_json(logged_in, f'/api/agents/{agent_id}', method='DELETE').status_code == 200
    assert post_json(logged_in, f'/api/agents/{agent_id}', method='DELETE').status_code == 404
    resp = logged_in.post('/api/ingest', json={'events': []},
                          headers={'Authorization': f'Bearer {token}'})
    assert resp.status_code == 401


def test_ingest_heartbeat_marks_online(logged_in, client):
    token = enroll(logged_in)
    resp = client.post('/api/ingest', json={'events': []}, headers={'Authorization': f'Bearer {token}'})
    assert resp.get_json() == {'received': 0}
    assert logged_in.get('/api/agents').get_json()[0]['status'] == 'online'


def test_ingest_rejects_bad_auth_and_bodies(logged_in, client):
    token = enroll(logged_in)
    auth = {'Authorization': f'Bearer {token}'}
    assert client.post('/api/ingest', json={'events': []}).status_code == 401
    assert client.post('/api/ingest', json={'events': []},
                       headers={'Authorization': 'Bearer nope'}).status_code == 401
    assert client.post('/api/ingest', json=['x'], headers=auth).status_code == 400
    assert client.post('/api/ingest', json={'events': 'abc'}, headers=auth).status_code == 400
    too_many = {'events': [{}] * (config.AGENT_INGEST_BATCH_LIMIT + 1)}
    assert client.post('/api/ingest', json=too_many, headers=auth).status_code == 400


def test_ingest_attributes_host_from_token_and_handles_naive_times(logged_in, client, captured_alerts):
    from core.detect import load_ruleset
    load_ruleset()
    token = enroll(logged_in, 'FRONT-DESK')
    naive = datetime.now().replace(microsecond=0).isoformat()  # no offset
    event = {'source': 'fim', 'change_type': 'modified', 'time': naive, 'host': 'SPOOFED',
             'is_sensitive': False,
             'data': {'path': r'C:\w\a.txt', 'filename': 'a.txt', 'directory': r'C:\w'}}
    resp = client.post('/api/ingest', json={'events': [event, 'garbage', event]},
                       headers={'Authorization': f'Bearer {token}'})
    assert resp.get_json()['received'] == 2
    assert captured_alerts and all(a.host == 'FRONT-DESK' for a in captured_alerts)


def test_ingest_garbage_time_falls_back_to_arrival_time(logged_in, client, captured_alerts):
    from core.detect import load_ruleset
    load_ruleset()
    token = enroll(logged_in)
    event = {'source': 'fim', 'change_type': 'deleted', 'time': 'yesterday-ish',
             'data': {'path': 'x', 'filename': 'x', 'directory': 'd'}}
    resp = client.post('/api/ingest', json={'events': [event]},
                       headers={'Authorization': f'Bearer {token}'})
    assert resp.get_json()['received'] == 1
    assert captured_alerts


def test_notifications_accept_configured_bind_address(client, monkeypatch):
    monkeypatch.setattr(config, 'WEB_HOST', '192.168.1.10')
    ok = client.get('/api/notifications/pending', environ_base={'REMOTE_ADDR': '192.168.1.10'})
    assert ok.status_code == 200
    other = client.get('/api/notifications/pending', environ_base={'REMOTE_ADDR': '192.168.1.11'})
    assert other.status_code == 401


def test_agent_status_handles_naive_last_seen(app_module):
    stale = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(tzinfo=None).isoformat()
    assert app_module._agent_status({'last_seen': stale}) == 'offline'
    assert app_module._agent_status({'last_seen': None}) == 'never connected'
