"""Forwarder, notification dispatchers, email digest, notifier companion, geo."""

import json
import time
from datetime import datetime, timedelta, timezone

import pytest

import config
from core import db, email_alerts, forwarder as forwarder_mod, ip_tracer, notify
from core.events import Alert


# -- forwarder ------------------------------------------------------------------

@pytest.fixture
def fwd(tmp_path, monkeypatch):
    monkeypatch.setattr(forwarder_mod, 'BUFFER_PATH', str(tmp_path / 'buf.jsonl'))
    monkeypatch.setattr(forwarder_mod, 'STATE_PATH', str(tmp_path / 'state.json'))
    return forwarder_mod


def test_forwarder_buffers_and_chains(fwd):
    f = fwd.EventForwarder()
    f.submit({'source': 'fim', 'time': datetime.now(timezone.utc)})
    f.submit({'source': 'fim', 'weird': b'bytes', 'when': datetime.now(timezone.utc)})
    assert f.stats()['pending'] == 2
    reloaded = fwd.EventForwarder()
    assert reloaded.tamper_warnings == 0 and reloaded.next_seq == 3


def test_forwarder_detects_tampering(fwd):
    f = fwd.EventForwarder()
    for i in range(3):
        f.submit({'source': 'fim', 'n': i})
    with open(fwd.BUFFER_PATH, encoding='utf-8') as fh:
        lines = fh.readlines()
    del lines[1]
    with open(fwd.BUFFER_PATH, 'w', encoding='utf-8') as fh:
        fh.writelines(lines)
    assert fwd.EventForwarder().tamper_warnings >= 1


def test_forwarder_compaction_keeps_chain_verifiable(fwd, monkeypatch):
    f = fwd.EventForwarder()
    for i in range(4):
        f.submit({'source': 'fim', 'n': i})
    sent = []
    monkeypatch.setattr(config, 'SERVER_URL', 'http://x', raising=False)
    monkeypatch.setattr(config, 'AGENT_INGEST_BATCH_LIMIT', 2)
    monkeypatch.setattr(f, '_post', lambda events: sent.append(events) or True)
    monkeypatch.setattr(f._stop, 'wait', lambda t: f._stop.set())
    f._send_loop()
    assert len(sent[0]) == 2 and f.synced_seq == 2
    f.submit({'source': 'fim', 'n': 'after'})
    again = fwd.EventForwarder()
    assert again.tamper_warnings == 0
    assert again.stats()['pending'] == 3


# -- notification dispatcher ----------------------------------------------------------

class RecordingSink(notify.NotificationSink):
    name = 'rec'

    def __init__(self):
        self.sent = []

    def send(self, alert):
        self.sent.append(alert)


def alert(sev='HIGH', module='FIM'):
    return Alert(module=module, alert_type='t', severity=sev, description='d')


def test_dispatcher_severity_floor_and_rate_limit():
    sink = RecordingSink()
    d = notify.NotificationDispatcher([sink], min_severity='MEDIUM', max_per_minute=2,
                                      module_floors={'AUTHLOG': 'CRITICAL'})
    d.start()
    d.submit(alert('LOW'))
    d.submit(alert('HIGH', module='AUTHLOG'))
    for _ in range(4):
        d.submit(alert('HIGH'))
    deadline = time.time() + 3
    while d._queue.qsize() and time.time() < deadline:
        time.sleep(0.05)
    time.sleep(0.2)
    d.stop()
    assert len(sink.sent) == 2
    assert d.suppressed_by_severity == 2 and d.suppressed_by_rate == 2


def test_meets_notification_floor(monkeypatch):
    monkeypatch.setattr(config, 'USE_DUMMY_DATA', True)
    assert not notify.meets_notification_floor('AUTHLOG', 'HIGH')
    assert notify.meets_notification_floor('FIM', 'HIGH')


# -- email -----------------------------------------------------------------------

@pytest.fixture
def email_on(monkeypatch):
    monkeypatch.setattr(config, 'EMAIL_ENABLED', True)
    monkeypatch.setattr(config, 'EMAIL_SMTP_HOST', 'smtp.example')
    monkeypatch.setattr(config, 'EMAIL_USERNAME', 'u')
    monkeypatch.setattr(config, 'EMAIL_APP_PASSWORD', 'p')
    monkeypatch.setattr(config, 'EMAIL_TO', 't')
    sent = []
    monkeypatch.setattr(email_alerts, '_send', lambda subject, body: sent.append((subject, body)))
    return sent


def test_send_immediate(email_on):
    assert not email_alerts.send_immediate(alert('HIGH'))
    assert email_alerts.send_immediate(alert('CRITICAL'))
    assert 'CRITICAL' in email_on[0][0]


def test_digest_first_run_then_due(temp_db, email_on, monkeypatch):
    conn = db.get_connection()
    assert not email_alerts.send_digest_if_due(conn)  # starts the clock
    past = db.utc_iso(datetime.now(timezone.utc) - timedelta(hours=config.EMAIL_DIGEST_INTERVAL_HOURS + 1))
    db.save_checkpoint(conn, email_alerts.DIGEST_CHECKPOINT_NAME, past)
    for sev in ['LOW', 'CRITICAL', 'MEDIUM', 'HIGH']:
        db.insert_or_aggregate(conn, Alert(module='FIM', alert_type=sev, severity=sev, description=sev), 300)
    conn.execute('UPDATE alerts SET occurrence_count = NULL WHERE severity = ?', ('LOW',))
    conn.commit()
    assert email_alerts.send_digest_if_due(conn)
    subject, body = email_on[0]
    assert '1 critical, 1 high' in subject
    order = [line.split(']')[0][1:] for line in body.splitlines() if line.startswith('[')]
    assert order == ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    assert not email_alerts.send_digest_if_due(conn)  # not due again yet
    conn.close()


def test_digest_empty_window(temp_db, email_on):
    subject, body = email_alerts._format_digest([], 'a', 'b')
    assert 'All quiet' in subject


# -- notifier companion --------------------------------------------------------------

def test_notifier_dashboard_url_for_wildcard_host(monkeypatch):
    import notifier
    monkeypatch.setattr(config, 'WEB_HOST', '0.0.0.0')
    assert notifier._dashboard_url() == f'http://127.0.0.1:{config.WEB_PORT}'
    monkeypatch.setattr(config, 'WEB_HOST', '127.0.0.1')
    assert notifier._dashboard_url() == f'http://127.0.0.1:{config.WEB_PORT}'
    monkeypatch.setattr(config, 'WEB_HOST', '192.168.1.10')
    assert notifier._dashboard_url() == f'http://192.168.1.10:{config.WEB_PORT}'
    monkeypatch.setattr(config, 'WEB_HOST', '::')
    assert notifier._dashboard_url() == f'http://[::1]:{config.WEB_PORT}'


def test_notifier_batches_popups(monkeypatch):
    import notifier
    shown = []
    monkeypatch.setattr(notifier, '_show_popup', lambda title, msg: shown.append(title))
    notifier._deliver([{'severity': 'LOW', 'description': 'a'}])
    notifier._deliver([{'severity': s, 'description': s} for s in ['LOW', 'CRITICAL', 'HIGH', 'INFO']])
    notifier._deliver([{'severity': 'HIGH', 'description': None}])
    assert shown == ['Mini SOC: LOW', 'Mini SOC: 4 new alerts', 'Mini SOC: HIGH']


def test_notifier_first_run_skips_history(tmp_path, monkeypatch):
    import notifier
    monkeypatch.setattr(notifier, 'STATE_FILE', str(tmp_path / 'state.json'))
    assert notifier._load_last_seen_id() is None


# -- geo --------------------------------------------------------------------------------

def test_geolocate_skips_private_addresses():
    assert ip_tracer.geolocate_ip('192.168.1.1') == (None, 'private')
    assert ip_tracer.geolocate_ip('') == (None, 'private')
    assert ip_tracer.is_geolocatable('8.8.8.8')


def test_rate_limiter_spacing():
    limiter = ip_tracer.RateLimiter(per_minute=1200)  # 50ms apart
    start = time.monotonic()
    for _ in range(3):
        limiter.acquire()
    assert time.monotonic() - start >= 0.09
