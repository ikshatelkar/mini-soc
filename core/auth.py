"""Dashboard login: password hashing, session gate, and brute-force lockout.

core/db.py owns storage (admin_exists/create_admin_user/get_admin_user) and
never sees a plaintext password; this module owns hashing, verification, and
the decision of who's let into a request.
"""

import os
import secrets
import time
from functools import wraps

from flask import jsonify, redirect, request, session, url_for  # type: ignore
from werkzeug.security import check_password_hash, generate_password_hash  # type: ignore

import config  # type: ignore
from core.db import get_admin_user, get_admin_user_by_id, set_admin_session_token  # type: ignore

_CONFIG_LOCAL_PATH = os.path.join(config.BASE_DIR, 'config_local.py')


def ensure_secret_key() -> str:
    """Return a persistent Flask session-signing key, generating and saving one
    on first run.

    A fresh random key every process start would silently log everyone out on
    every restart, so this is generated once and appended to config_local.py -
    the same gitignored, local-only file email credentials already live in.
    """
    existing = getattr(config, 'SECRET_KEY', None)
    if existing:
        return existing

    key = secrets.token_hex(32)
    with open(_CONFIG_LOCAL_PATH, 'a', encoding='utf-8') as f:
        f.write(
            '\n# Auto-generated on first run - signs dashboard login session '
            'cookies. Do not share.\n'
            f'SECRET_KEY = {key!r}\n'
        )
    config.SECRET_KEY = key  # this process already imported config_local; apply directly
    return key


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_login(username: str, password: str) -> dict | None:
    """The admin row on success, None on a bad username or password. Callers
    should check is_locked_out() before calling this so a lockout isn't
    bypassed by a slow/careful attacker."""
    user = get_admin_user(username)
    if user is None or not check_password_hash(user['password_hash'], password):
        return None
    return user


# ---------------------------------------------------------------------------
# Single active session
# ---------------------------------------------------------------------------
#
# Only one issued session token is ever valid per admin, tracked in the
# admin_users row rather than as a list of sessions - there is exactly one
# admin account, so "the current token" is all that's needed. Logging in
# anywhere (a different browser, a different machine) mints a new token and
# overwrites the stored one, which makes every previously issued session
# cookie stop authenticating on its very next request.

def issue_session_token(admin_id: int) -> str:
    token = secrets.token_hex(32)
    set_admin_session_token(admin_id, token)
    return token


def session_is_current(admin_id: int, token: str | None) -> bool:
    if not token:
        return False
    user = get_admin_user_by_id(admin_id)
    return bool(user and user.get('session_token')
                and secrets.compare_digest(user['session_token'], token))


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------
#
# Hand-rolled rather than a new dependency (Flask-WTF etc.) - same reasoning
# as the rest of this module. A token lives in the signed session cookie
# (Flask session is already itsdangerous-signed) and must be echoed back by
# every state-changing request, either as a hidden form field or an
# X-CSRFToken header for fetch() calls. app.py's before_request hook is what
# actually enforces this; the functions below just mint and check the token.

def get_csrf_token() -> str:
    """The current session's CSRF token, generating one on first use. Safe to
    call from a template on every GET that renders a form."""
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_hex(32)
        session['csrf_token'] = token
    return token


def validate_csrf_token(candidate: str | None) -> bool:
    expected = session.get('csrf_token')
    return bool(expected) and bool(candidate) and secrets.compare_digest(expected, candidate)


# ---------------------------------------------------------------------------
# Brute-force lockout
# ---------------------------------------------------------------------------
#
# In-memory, keyed by username rather than IP - the dashboard has exactly one
# account, so this is equivalent for the single-admin case and simpler than
# tracking source addresses. Same lightweight style as the geo lookup rate
# limiting in core/ip_tracer.py: a dict of timestamps, no new dependency.

_failed_attempts: dict[str, list[float]] = {}


def _recent_attempts(username: str) -> list[float]:
    cutoff = time.time() - config.LOGIN_LOCKOUT_MINUTES * 60
    attempts = [t for t in _failed_attempts.get(username, []) if t > cutoff]
    _failed_attempts[username] = attempts
    return attempts


def is_locked_out(username: str) -> bool:
    return len(_recent_attempts(username.lower())) >= config.LOGIN_MAX_ATTEMPTS


def record_failed_attempt(username: str) -> None:
    key = username.lower()
    _recent_attempts(key)
    _failed_attempts[key].append(time.time())


def clear_attempts(username: str) -> None:
    _failed_attempts.pop(username.lower(), None)


# ---------------------------------------------------------------------------
# Route protection
# ---------------------------------------------------------------------------

def login_required(view):
    """Gate a route on an active session that is also still the *current*
    one for this admin. Browser routes redirect to /login; /api/* routes get
    a plain 401 so the frontend's fetch() calls can tell the difference from
    a real data response instead of parsing an HTML page.

    A session with a valid admin_id but a stale session_token means this
    admin has logged in somewhere else since - see session_is_current(). That
    is reported distinctly (reason=elsewhere) so the login page can tell the
    person why they were signed out, instead of it looking like a random
    logout.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        admin_id = session.get('admin_id')
        if admin_id is not None and session_is_current(admin_id, session.get('session_token')):
            return view(*args, **kwargs)
        superseded = admin_id is not None
        session.clear()
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'authentication required',
                'reason': 'session_superseded' if superseded else 'not_authenticated',
            }), 401
        return redirect(url_for('login', next=request.path, reason='elsewhere' if superseded else None))
    return wrapped
