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
from core.db import get_admin_user  # type: ignore

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
    """Gate a route on an active session. Browser routes redirect to /login;
    /api/* routes get a plain 401 so the frontend's fetch() calls can tell the
    difference from a real data response instead of parsing an HTML page."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get('admin_id') is not None:
            return view(*args, **kwargs)
        if request.path.startswith('/api/'):
            return jsonify({'error': 'authentication required'}), 401
        return redirect(url_for('login', next=request.path))
    return wrapped
