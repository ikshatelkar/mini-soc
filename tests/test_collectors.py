"""FIM, auth-log parser and network monitor, with the rule engine stubbed out."""

import os
from collections import namedtuple
from datetime import datetime, timedelta

import pytest

from core import db, fim, log_parser, network_monitor


# -- FIM -------------------------------------------------------------------------

@pytest.fixture
def fim_events(monkeypatch):
    events = []
    monkeypatch.setattr(fim, 'process_fim', lambda change, path, d: events.append((change, os.path.basename(path))))
    return events


def scan(directory):
    conn = db.get_connection()
    try:
        fim.scan_directory(conn, str(directory))
    finally:
        conn.close()


def test_fim_baseline_then_changes(temp_db, tmp_path, fim_events):
    watched = tmp_path / 'watched'
    watched.mkdir()
    (watched / 'a.txt').write_text('one')
    (watched / 'b.txt').write_text('two')
    (watched / 'ignored.tmp').write_text('x')
    scan(watched)
    assert fim_events == []  # first scan is a silent baseline

    (watched / 'a.txt').write_text('changed')
    (watched / 'b.txt').unlink()
    (watched / 'c.exe').write_text('new')
    (watched / 'more.tmp').write_text('y')
    scan(watched)
    assert sorted(fim_events) == [('created', 'c.exe'), ('deleted', 'b.txt'), ('modified', 'a.txt')]

    fim_events.clear()
    scan(watched)
    assert fim_events == []


def test_fim_alerts_on_first_file_in_initially_empty_directory(temp_db, tmp_path, fim_events):
    watched = tmp_path / 'empty'
    watched.mkdir()
    scan(watched)
    (watched / 'dropped.exe').write_text('payload')
    scan(watched)
    assert fim_events == [('created', 'dropped.exe')]


def test_fim_alerts_after_directory_emptied(temp_db, tmp_path, fim_events):
    watched = tmp_path / 'w'
    watched.mkdir()
    (watched / 'only.txt').write_text('x')
    scan(watched)
    (watched / 'only.txt').unlink()
    scan(watched)
    (watched / 'new.txt').write_text('y')
    scan(watched)
    assert fim_events == [('deleted', 'only.txt'), ('created', 'new.txt')]


def test_fim_sibling_directory_baselines_do_not_leak(temp_db, tmp_path, fim_events):
    """'_' is a LIKE wildcard; test_dir must not pick up testXdir's baselines."""
    a = tmp_path / 'test_dir'
    b = tmp_path / 'testXdir'
    a.mkdir()
    b.mkdir()
    (a / 'a.txt').write_text('a')
    (b / 'b.txt').write_text('b')
    scan(b)
    scan(a)
    scan(a)
    assert fim_events == []


def test_fim_ignore_patterns_case_insensitive():
    assert fim._is_ignored('THUMBS.DB')
    assert fim._is_ignored('x.TMP')
    assert not fim._is_ignored('notes.txt')


def test_fim_monitoring_scope(tmp_path, monkeypatch):
    (tmp_path / 'a.txt').write_text('a')
    monkeypatch.setattr(fim.config, 'FIM_DIRECTORIES', [str(tmp_path), str(tmp_path / 'missing')])
    scope = fim.get_monitoring_scope()
    assert scope[0]['exists'] and scope[0]['file_count'] == 1
    assert scope[1] == {'path': str(tmp_path / 'missing'), 'exists': False, 'file_count': 0}


def test_get_file_hash_unreadable(tmp_path):
    assert fim.get_file_hash(str(tmp_path / 'nope')) is None


# -- auth log parser ----------------------------------------------------------------

@pytest.fixture
def auth_events(monkeypatch):
    events = []
    monkeypatch.setattr(log_parser, 'process_authlog', lambda **kw: events.append(kw))
    log_parser._recent_failures.clear()
    return events


def test_parse_failed_and_accepted(auth_events):
    for _ in range(3):
        log_parser.parse_log_line('Nov  6 03:12:00 srv sshd[1]: Failed password for invalid user '
                                  'bob from 203.0.113.5 port 22 ssh2')
    log_parser.parse_log_line('Nov 6 03:13:00 srv sshd[1]: Accepted password for bob from '
                              '203.0.113.5 port 22 ssh2')
    assert [e['status'] for e in auth_events] == ['Failed'] * 3 + ['Accepted']
    assert auth_events[-1]['recent_failures'] == 3
    assert auth_events[-1]['hour'] == 3
    assert auth_events[0]['user'] == 'bob'
    # failures cleared after success
    assert '203.0.113.5' not in log_parser._recent_failures


def test_parse_ipv6_and_garbage(auth_events):
    log_parser.parse_log_line('Jan 1 10:00:00 h sshd: Failed password for root from 2001:db8::1 port 1')
    log_parser.parse_log_line('totally unrelated line')
    assert len(auth_events) == 1 and auth_events[0]['ip'] == '2001:db8::1'


def test_parse_feb29_in_non_leap_year_does_not_crash(auth_events):
    log_parser.parse_log_line('Feb 29 10:00:00 h sshd: Failed password for x from 1.2.3.4 port 1')


def test_prune_bounds_state():
    log_parser._recent_failures.clear()
    old = datetime.now() - timedelta(hours=1)
    log_parser._recent_failures['1.1.1.1'].append(old)
    log_parser._last_prune = old
    log_parser._prune(datetime.now())
    assert '1.1.1.1' not in log_parser._recent_failures


# -- network monitor -------------------------------------------------------------------

Addr = namedtuple('Addr', 'ip port')
Conn = namedtuple('Conn', 'status laddr raddr pid')


class FakePsutil:
    CONN_LISTEN = 'LISTEN'
    CONN_ESTABLISHED = 'ESTABLISHED'

    class AccessDenied(Exception):
        pass

    def __init__(self):
        self.connections = []
        self.raise_denied = False

    def net_connections(self, kind):
        if self.raise_denied:
            raise self.AccessDenied()
        return self.connections

    class Process:
        def __init__(self, pid):
            self.pid = pid

        def name(self):
            return 'evil.exe'


@pytest.fixture
def fake_net(monkeypatch):
    fake = FakePsutil()
    events = []
    monkeypatch.setattr(network_monitor, 'psutil', fake)
    monkeypatch.setattr(network_monitor, 'PSUTIL_AVAILABLE', True)
    monkeypatch.setattr(network_monitor, 'process_network',
                        lambda kind, data, **kw: events.append((kind, data, kw)))
    network_monitor._reported.clear()
    network_monitor._status.update(status='not_started', detail=None)
    return fake, events


def test_network_listener_egress_and_close(fake_net):
    fake, events = fake_net
    fake.connections = [
        Conn('LISTEN', Addr('0.0.0.0', 4444), None, 10),
        Conn('LISTEN', Addr('127.0.0.1', 5000), None, 11),
        Conn('ESTABLISHED', Addr('10.0.0.2', 50000), Addr('198.51.100.1', 6667), 12),
    ]
    network_monitor.scan_connections()
    kinds = sorted(e[0] for e in events)
    assert kinds == ['egress', 'listener']
    listener = [e for e in events if e[0] == 'listener'][0]
    assert listener[2]['network_exposed'] is True
    # same state -> no repeat alerts
    events.clear()
    network_monitor.scan_connections()
    assert events == []
    # listener gone -> one closed event
    fake.connections = fake.connections[1:]
    network_monitor.scan_connections()
    assert [e[0] for e in events] == ['closed']
    assert network_monitor.monitor_status()['status'] == 'running'


def test_network_access_denied_does_not_fake_closures(fake_net):
    fake, events = fake_net
    fake.connections = [Conn('LISTEN', Addr('0.0.0.0', 4444), None, 10)]
    network_monitor.scan_connections()
    events.clear()
    fake.raise_denied = True
    network_monitor.scan_connections()
    assert events == []
    assert network_monitor.monitor_status()['status'] == 'degraded'
    fake.raise_denied = False
    network_monitor.scan_connections()
    status = network_monitor.monitor_status()
    assert status['status'] == 'running' and status['detail'] is None
