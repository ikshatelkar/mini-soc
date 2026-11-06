"""Shared fixtures.

Every test gets its own throwaway SQLite database (core.db.DB_PATH is
monkeypatched), so nothing here ever touches the real mini_soc.db. Background
services are never started - tests drive modules directly.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import config  # noqa: E402

# Keep the suite hermetic regardless of the developer's config_local.py.
config.SECRET_KEY = config.__dict__.get('SECRET_KEY') or 'test-secret-key'
config.EMAIL_ENABLED = False
config.USE_DUMMY_DATA = False
config.GEO_ENRICHMENT_ENABLED = False
config.DESKTOP_NOTIFICATIONS_ENABLED = False

from core import db  # noqa: E402


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    path = str(tmp_path / 'test.db')
    monkeypatch.setattr(db, 'DB_PATH', path)
    db.init_db()
    return path


@pytest.fixture
def captured_alerts(monkeypatch):
    """Capture alerts the rule engine emits instead of queueing them."""
    from core import detect
    alerts = []
    monkeypatch.setattr(detect, 'submit', alerts.append)
    return alerts


@pytest.fixture
def app_module(temp_db):
    import app as app_module
    from core import auth
    app_module.app.config['TESTING'] = True
    auth._failed_attempts.clear()
    return app_module


@pytest.fixture
def client(app_module):
    return app_module.app.test_client()


def csrf_from(client) -> str:
    with client.session_transaction() as sess:
        token = sess.get('csrf_token')
        if not token:
            token = 'test-csrf-token'
            sess['csrf_token'] = token
    return token


ADMIN_USER = 'admin'
ADMIN_PASS = 'correct-horse-battery'


@pytest.fixture
def logged_in(client):
    from core.auth import hash_password
    db.create_admin_user(ADMIN_USER, hash_password(ADMIN_PASS))
    client.get('/login')
    token = csrf_from(client)
    resp = client.post('/login', data={'username': ADMIN_USER, 'password': ADMIN_PASS,
                                       'csrf_token': token})
    assert resp.status_code == 302
    return client


def post_json(client, path, body=None, method='POST'):
    token = csrf_from(client)
    return client.open(path, method=method, json=body if body is not None else {},
                       headers={'X-CSRFToken': token})
