import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Deployment role
# ---------------------------------------------------------------------------
#
# 'standalone' (default): today's single-host behavior, unchanged - collectors,
# rule engine, storage and dashboard all in one process.
# 'server': runs the dashboard, rule engine and storage, and additionally
# accepts events forwarded by enrolled agents (see /api/ingest in app.py).
# Usually paired with WEB_HOST set to a LAN-reachable interface in
# config_local.py - 127.0.0.1 here is fine as the default, since a real server
# deployment already has to override it locally.
# 'agent': runs only the collectors (core/fim.py, core/log_parser.py,
# core/network_monitor.py, core/winevt.py) via agent.py. Never loads rules,
# never runs the rule engine, never stores alerts locally - it forwards raw
# events to SERVER_URL instead. Those three values (SERVER_URL, AGENT_TOKEN,
# AGENT_NAME) are agent-only secrets and belong in that machine's own
# config_local.py, never in this file.
DEPLOYMENT_ROLE = 'standalone'

# How often an agent checks in with the server, event or not - see
# core/forwarder.py. Doubles as the heartbeat: an idle agent with nothing to
# report still calls /api/ingest with an empty batch on this interval, so
# last_seen keeps moving and "agent went silent" stays a meaningful signal.
AGENT_HEARTBEAT_SECONDS = 20

# A batch larger than this is rejected rather than processed inline - caps how
# long a single ingest request can block the handling thread.
AGENT_INGEST_BATCH_LIMIT = 500

# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------

# Set to True to generate synthetic attack traffic for demos and testing rules.
# Off by default: a security tool's first impression should be an honest "here
# is what's actually happening on your machine," not a dashboard full of
# invented attacks from Pyongyang that look indistinguishable from real ones.
# Turn this on deliberately when you want to see the detections work.
USE_DUMMY_DATA = False

# Directories watched by the File Integrity Monitor.
#
# Only point this at files that are NOT supposed to change. Integrity monitoring
# carries no signal for directories you actively work in - if a file legitimately
# changes 50 times a day, "this file changed" tells you nothing. Good real targets
# are things like the hosts file or a deployed web root; your own documents and
# source folders are bad targets.
FIM_DIRECTORIES = [
    os.path.join(BASE_DIR, 'test_dir'),
]

# Filename patterns inside the watched directories that never raise alerts.
FIM_IGNORE_PATTERNS = [
    '*.tmp', '*.temp', '*.swp', '*.lock', '~$*',
    '*.log', '*.pyc', 'Thumbs.db', 'desktop.ini',
]

# Files whose modification or deletion is escalated a severity level. Used by the
# is_sensitive field in rules/filesystem.yaml.
FIM_SENSITIVE_PATTERNS = [
    'hosts', '*.key', '*.pem', '*.pfx', '*.crt',
    '*.conf', '*.config', '*.ini', 'web.config',
    'authorized_keys', 'sshd_config', '*.sys', '*.dll', '*.exe',
]

# The log file watched for suspicious authentication activity.
LOG_FILE_PATH = os.path.join(BASE_DIR, 'logs', 'dummy_auth.log')

# ---------------------------------------------------------------------------
# Windows Event Log collection
# ---------------------------------------------------------------------------

# Reads what Windows already records about logons, accounts and services. This is
# the real telemetry source - unlike the synthetic log above, these are actual
# events from this machine.
#
# Privilege note: the Security channel requires administrator rights. Run
# unelevated and it is skipped with a clear reason on /api/health while every
# other channel keeps working. The System channel needs no elevation and still
# catches service-installation persistence.
WINEVT_ENABLED = True

WINEVT_CHANNELS = [
    {
        'channel': 'Security',
        'enabled': True,
        'required': True,
        # 4625 failed logon, 4624 success, 4672 admin session, 4720/4726 account
        # created/deleted, 4732/4728 group membership, 1102 audit log cleared,
        # 4698 scheduled task created.
        'event_ids': [4625, 4624, 4672, 4720, 4726, 4732, 4728, 1102, 4698],
    },
    {
        'channel': 'System',
        'enabled': True,
        'required': True,
        # 7045 service installed, 7040 start type changed, 104 event log cleared.
        'event_ids': [7045, 7040, 104],
    },
    {
        # Only exists if Sysmon is installed. Marked not-required so its absence
        # is reported as informational rather than as a fault.
        'channel': 'Microsoft-Windows-Sysmon/Operational',
        'enabled': True,
        'required': False,
        'event_ids': [1, 3, 11, 13],
    },
]

# Failed logons for one account from one source within this window.
WINEVT_BRUTE_FORCE_THRESHOLD = 5
WINEVT_BRUTE_FORCE_WINDOW_SECONDS = 300

# Distinct accounts targeted from a single source within the same window. A low
# number of failures spread across many accounts is password spraying, which a
# per-account threshold alone cannot see.
WINEVT_PASSWORD_SPRAY_THRESHOLD = 5

# Local-time hours considered normal working hours, used by off-hours detections.
BUSINESS_HOURS = (6, 22)

# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

# Detections live in YAML here rather than in Python, so thresholds, severities
# and exclusions can be tuned without touching code. Files named exceptions*.yaml
# hold the global allowlist; everything else holds rules.
#
# A rule that fails to parse is skipped and reported on /api/rules - one typo
# never stops the service or silently disables the other rules.
RULES_DIR = os.path.join(BASE_DIR, 'rules')

# ---------------------------------------------------------------------------
# Alert pipeline
# ---------------------------------------------------------------------------

# Detection modules never write to the database directly - they hand alerts to a
# bounded queue drained by a single writer thread. If detection outruns the writer
# the queue fills and the overflow is counted rather than silently lost; the count
# is visible on /api/health.
ALERT_QUEUE_SIZE = 10000

# Repeat alerts sharing the same fingerprint (module + type + source) inside this
# window do not create new rows or fire new notifications. Instead the existing
# alert's occurrence count and last-seen time are updated. This is what stops the
# dashboard and your desktop from being buried by one noisy condition.
ALERT_DEDUP_WINDOW_SECONDS = 300

# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------

# Alerts older than this are pruned. A real deployment generates far more events
# than a test run, so without this the database grows without bound.
RETENTION_DAYS = 30

# Hard ceiling on stored alerts, enforced oldest-first, as a backstop against a
# flood filling the disk before the age-based prune runs.
RETENTION_MAX_ALERTS = 500000

# How often the pruning pass runs.
RETENTION_INTERVAL_SECONDS = 3600

# ---------------------------------------------------------------------------
# Enrichment (IP geolocation)
# ---------------------------------------------------------------------------

# Geolocation happens on a background worker, never inside the alert write path -
# a blocking HTTP call there would stall detection.
GEO_ENRICHMENT_ENABLED = True

# ip-api.com's free tier allows 45 requests/minute and bans on sustained abuse.
# We stay under it deliberately; lookups beyond the budget wait rather than fail.
GEO_LOOKUPS_PER_MINUTE = 40
GEO_REQUEST_TIMEOUT_SECONDS = 5

# Successful lookups are cached in the database, so restarts do not re-spend the
# rate-limit budget on IPs already resolved.
GEO_CACHE_TTL_DAYS = 30

# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

# Desktop popup + sound. Only fires for alerts at or above the severity floor,
# and only for alerts that survived the dedup gate.
DESKTOP_NOTIFICATIONS_ENABLED = True
NOTIFY_MIN_SEVERITY = 'MEDIUM'

# Synthetic demo traffic (USE_DUMMY_DATA) exists to populate the dashboard for
# testing, not to alarm you - the generator invents a login every 1-8 seconds,
# and most of them will legitimately be "off-hours" for whoever is awake to
# watch it run. That combination sits near the notification cap indefinitely,
# which reads as the tool spamming you even though nothing malfunctioned.
#
# So while USE_DUMMY_DATA is on, the AUTHLOG module (which is what the
# generator feeds) is held to a stricter floor: only alerts at or above this
# severity - the ones dramatic enough to prove the tool works, like a brute
# force that actually succeeded - still pop up. Everything else from the
# generator is still recorded and charted, just silently. This override never
# applies to real telemetry (winevt/fim/network), which always uses
# NOTIFY_MIN_SEVERITY above.
DUMMY_DATA_NOTIFY_MIN_SEVERITY = 'CRITICAL'

# Absolute ceiling on desktop notifications per minute, regardless of dedup.
# Distinct alerts firing at once can still overwhelm you; this is the last guard.
NOTIFY_MAX_PER_MINUTE = 6

# ---------------------------------------------------------------------------
# Email alerts
# ---------------------------------------------------------------------------
#
# Defaults here are all "off" - real values (SMTP host/credentials/recipient)
# live in config_local.py, which is gitignored so a password never ends up
# committed. Copy config_local.example.py to config_local.py and fill it in.

EMAIL_ENABLED = False
EMAIL_SMTP_HOST = ''
EMAIL_SMTP_PORT = 465
EMAIL_USERNAME = ''
EMAIL_APP_PASSWORD = ''
EMAIL_TO = ''

# A critical alert (a break-in that actually succeeded, defenses disabled,
# logs cleared) emails immediately, in addition to the regular digest below -
# a popup only reaches you if you're at the machine, so anything at or above
# this severity closes that gap for when you're not.
EMAIL_IMMEDIATE_MIN_SEVERITY = 'CRITICAL'

# Everything else accumulates into a periodic summary instead of one email per
# alert, which would just recreate the popup-spam problem in your inbox.
EMAIL_DIGEST_INTERVAL_HOURS = 4

# ---------------------------------------------------------------------------
# Monitor intervals (seconds)
# ---------------------------------------------------------------------------

FIM_SCAN_INTERVAL = 30
NETWORK_SCAN_INTERVAL = 10
DUMMY_LOG_INTERVAL = 3

# ---------------------------------------------------------------------------
# Web server
# ---------------------------------------------------------------------------

WEB_HOST = '127.0.0.1'
WEB_PORT = 5000

# Flask's debug mode exposes an interactive console that allows arbitrary code
# execution to anyone who can reach the port. It must stay off in anything that
# runs unattended - which is the whole point of this tool.
WEB_DEBUG = False

# ---------------------------------------------------------------------------
# Dashboard login
# ---------------------------------------------------------------------------
#
# Single admin account, session-cookie based - see core/auth.py. SECRET_KEY is
# not set here; it is generated once on first run and persisted to
# config_local.py, the same way email credentials are kept local-only.

SESSION_LIFETIME_HOURS = 12

# A username is locked out after this many failed attempts within the window
# below - protects the one admin account against a password-guessing script
# without needing an external dependency.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 5

# Marks the session cookie Secure (browser will only ever send it over HTTPS).
# Stays False while the dashboard is plain HTTP on 127.0.0.1 - a Secure cookie
# on plain HTTP is simply never sent back, which would break login outright.
# Flip to True once Phase 5's TLS work lands.
FORCE_SECURE_COOKIES = False

# ---------------------------------------------------------------------------
# Local overrides (secrets)
# ---------------------------------------------------------------------------
#
# config_local.py is gitignored and holds real email credentials; it does not
# exist until you copy it from config_local.example.py. Its absence is normal
# on a fresh checkout, not an error - email alerts simply stay off until it's
# created.
try:
    from config_local import *  # noqa: F401,F403
except ImportError:
    pass
