from datetime import datetime, timedelta, timezone

import pytest

from core import db
from core.events import Alert, meets_threshold, severity_rank


def make_alert(**kw):
    defaults = dict(module='FIM', alert_type='File Modified', severity='HIGH',
                    description='changed', host='H1')
    defaults.update(kw)
    return Alert(**defaults)


def insert(conn, **kw):
    return db.insert_or_aggregate(conn, make_alert(**kw), 300)


def test_severity_helpers():
    assert severity_rank('critical') == 4
    assert severity_rank(None) == -1
    assert meets_threshold('HIGH', 'MEDIUM')
    assert not meets_threshold('LOW', 'MEDIUM')


def test_fingerprint_stability():
    a = make_alert(dedup_subject='x')
    b = make_alert(dedup_subject='x', description='other')
    c = make_alert(dedup_subject='y')
    assert a.fingerprint() == b.fingerprint() != c.fingerprint()


def test_insert_then_aggregate(temp_db):
    conn = db.get_connection()
    action1, id1 = insert(conn, dedup_subject='f')
    action2, id2 = insert(conn, dedup_subject='f', description='changed again')
    assert (action1, action2) == ('inserted', 'aggregated')
    assert id1 == id2
    row = conn.execute('SELECT * FROM alerts WHERE id=?', (id1,)).fetchone()
    assert row['occurrence_count'] == 2
    assert row['description'] == 'changed again'
    conn.close()


def test_aggregation_outside_window_inserts_new(temp_db):
    conn = db.get_connection()
    old = datetime.now(timezone.utc) - timedelta(hours=1)
    db.insert_or_aggregate(conn, make_alert(timestamp=old), 300)
    action, _ = insert(conn)
    assert action == 'inserted'
    conn.close()


def test_recurrence_reopens_resolved_alert_and_clears_resolution(temp_db):
    conn = db.get_connection()
    _, alert_id = insert(conn)
    db.set_alert_status(conn, alert_id, 'dismissed', note='known scanner')
    insert(conn)
    row = conn.execute('SELECT * FROM alerts WHERE id=?', (alert_id,)).fetchone()
    assert row['status'] == 'open'
    assert row['resolved_at'] is None
    assert row['resolution_note'] is None
    conn.close()


def test_aggregation_escalates_severity(temp_db):
    """A recurrence at a higher severity must not stay filed under the old, lower one."""
    conn = db.get_connection()
    _, alert_id = insert(conn, severity='MEDIUM')
    assert insert(conn, severity='CRITICAL')[0] == 'escalated'
    assert insert(conn, severity='LOW')[0] == 'aggregated'
    assert insert(conn, severity='CRITICAL')[0] == 'aggregated'
    row = conn.execute('SELECT severity FROM alerts WHERE id=?', (alert_id,)).fetchone()
    assert row['severity'] == 'CRITICAL'
    conn.close()


def test_set_alert_status(temp_db):
    conn = db.get_connection()
    _, alert_id = insert(conn)
    row = db.set_alert_status(conn, alert_id, 'acknowledged', note='done')
    assert row['status'] == 'acknowledged' and row['resolved_at'] and row['resolution_note'] == 'done'
    row = db.set_alert_status(conn, alert_id, 'open')
    assert row['status'] == 'open' and row['resolved_at'] is None
    with pytest.raises(db.AlertNotFoundError):
        db.set_alert_status(conn, 9999, 'open')
    with pytest.raises(ValueError):
        db.set_alert_status(conn, alert_id, 'bogus')
    conn.close()


def test_bulk_set_status_with_severity_ceiling(temp_db):
    conn = db.get_connection()
    for i, sev in enumerate(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']):
        insert(conn, severity=sev, dedup_subject=str(i))
    count = db.bulk_set_status(conn, 'acknowledged', max_severity='MEDIUM')
    assert count == 3
    remaining = {r['severity'] for r in conn.execute("SELECT severity FROM alerts WHERE status='open'")}
    assert remaining == {'CRITICAL', 'HIGH'}
    conn.close()


def test_needs_attention_and_lifecycle(temp_db):
    conn = db.get_connection()
    insert(conn, severity='HIGH', dedup_subject='1')
    insert(conn, severity='CRITICAL', dedup_subject='2')
    _, low_id = insert(conn, severity='LOW', dedup_subject='3')
    db.set_alert_status(conn, low_id, 'dismissed')
    conn.close()
    attention = db.get_needs_attention()
    assert [a['severity'] for a in attention] == ['CRITICAL', 'HIGH']
    counts = db.get_lifecycle_counts()
    assert counts == {'needs_attention': 2, 'open_total': 2, 'handled_total': 1,
                      'acknowledged_total': 0, 'dismissed_total': 1, 'total': 3}


def test_recent_alerts_ordering_and_window(temp_db):
    conn = db.get_connection()
    insert(conn, severity='LOW', dedup_subject='a')
    insert(conn, severity='CRITICAL', dedup_subject='b')
    db.insert_or_aggregate(conn, make_alert(severity='CRITICAL', dedup_subject='old',
                                            timestamp=datetime.now(timezone.utc) - timedelta(days=2)), 300)
    conn.close()
    rows = db.get_recent_alerts()
    assert [r['severity'] for r in rows] == ['CRITICAL', 'LOW']


def test_get_all_alerts_filters(temp_db):
    conn = db.get_connection()
    insert(conn, severity='HIGH', description='port 4444 open', host='A', dedup_subject='1')
    insert(conn, severity='LOW', description='new file', host='B', source_ip='8.8.8.8', dedup_subject='2')
    insert(conn, severity='LOW', description='100% literal', host='B', dedup_subject='3')
    conn.close()
    assert db.get_all_alerts()['total'] == 3
    assert db.get_all_alerts(severity='low')['total'] == 2
    assert db.get_all_alerts(host='A')['total'] == 1
    assert db.get_all_alerts(search='8.8.8')['total'] == 1
    # LIKE wildcards in user input are matched literally.
    assert db.get_all_alerts(search='%')['total'] == 1
    assert db.get_all_alerts(search='_')['total'] == 0
    page = db.get_all_alerts(limit=1, offset=1)
    assert len(page['alerts']) == 1 and page['total'] == 3


def test_get_all_alerts_date_range_handles_timezones(temp_db):
    conn = db.get_connection()
    insert(conn)
    conn.close()
    now = datetime.now(timezone.utc)
    since = (now - timedelta(minutes=1)).isoformat().replace('+00:00', 'Z')
    until = (now + timedelta(minutes=1)).isoformat().replace('+00:00', 'Z')
    assert db.get_all_alerts(since=since, until=until)['total'] == 1
    assert db.get_all_alerts(until=(now - timedelta(minutes=1)).isoformat())['total'] == 0


def test_prune_uses_last_activity(temp_db):
    conn = db.get_connection()
    old = datetime.now(timezone.utc) - timedelta(days=40)
    # first seen long ago but still recurring now -> must survive
    _, keep_id = db.insert_or_aggregate(conn, make_alert(timestamp=old, dedup_subject='k'), 300)
    conn.execute('UPDATE alerts SET last_seen=? WHERE id=?', (db.utc_iso(), keep_id))
    db.insert_or_aggregate(conn, make_alert(timestamp=old, dedup_subject='gone'), 300)
    conn.commit()
    removed = db.prune_old_alerts(conn, 30, 1000)
    assert removed == 1
    assert conn.execute('SELECT id FROM alerts').fetchall()[0]['id'] == keep_id
    conn.close()


def test_prune_row_ceiling(temp_db):
    conn = db.get_connection()
    for i in range(5):
        insert(conn, dedup_subject=str(i))
    assert db.prune_old_alerts(conn, 30, 2) == 3
    conn.close()


def test_geo_cache_and_backfill(temp_db):
    conn = db.get_connection()
    insert(conn, source_ip='8.8.8.8')
    assert db.get_pending_geo_ips(conn) == ['8.8.8.8']
    geo = {'country': 'US', 'city': 'X', 'isp': 'G', 'lat': 1.0, 'lon': 2.0}
    db.cache_geo(conn, '8.8.8.8', geo, 'success')
    assert db.apply_geo_to_alerts(conn, '8.8.8.8', geo, 'done') == 1
    assert db.get_pending_geo_ips(conn) == []
    # a later alert from the same IP resolves from cache immediately
    insert(conn, source_ip='8.8.8.8', dedup_subject='second')
    row = conn.execute('SELECT geo_status, geo_country FROM alerts ORDER BY id DESC LIMIT 1').fetchone()
    assert (row['geo_status'], row['geo_country']) == ('done', 'US')
    conn.close()
    points = db.get_geomap_points()
    assert points[0]['source_ip'] == '8.8.8.8' and points[0]['severity'] == 'HIGH'
    stats = db.get_alert_stats()
    assert stats['total_alerts'] == 2 and stats['mapped_origins'] == 1


def test_admin_and_agents(temp_db):
    assert not db.admin_exists()
    db.create_admin_user('root', 'hash')
    assert db.admin_exists()
    assert db.get_admin_user('root')['password_hash'] == 'hash'
    agent_id, token = db.create_agent('PC-1')
    assert db.get_agent_by_token(token)['id'] == agent_id
    assert db.get_agent_by_token('wrong') is None
    assert 'token_hash' in db.list_agents()[0]
    assert db.delete_agent(agent_id) and not db.delete_agent(agent_id)


def test_only_one_admin_can_ever_be_created(temp_db):
    db.create_admin_user('first', 'h')
    with pytest.raises(Exception):
        db.create_admin_user('second', 'h')
    conn = db.get_connection()
    assert conn.execute('SELECT COUNT(*) FROM admin_users').fetchone()[0] == 1
    conn.close()


def test_employees_overview(temp_db):
    conn = db.get_connection()
    insert(conn, host='PC-A', severity='CRITICAL')
    conn.close()
    db.create_agent('PC-B')
    db.set_employee_name('PC-A', 'Alice')
    rows = {r['host']: r for r in db.get_employees_overview()}
    assert rows['PC-A']['employee_name'] == 'Alice'
    assert rows['PC-A']['urgent_count'] == 1
    assert rows['PC-B']['total'] == 0


def test_checkpoints(temp_db):
    conn = db.get_connection()
    assert db.load_checkpoint(conn, 'x') is None
    db.save_checkpoint(conn, 'x', '1')
    db.save_checkpoint(conn, 'x', '2')
    assert db.load_checkpoint(conn, 'x') == '2'
    conn.close()


def test_init_db_migrates_old_schema(tmp_path, monkeypatch):
    import sqlite3
    path = str(tmp_path / 'old.db')
    raw = sqlite3.connect(path)
    raw.execute('CREATE TABLE alerts (id INTEGER PRIMARY KEY, timestamp DATETIME, module TEXT, '
                'alert_type TEXT, severity TEXT, description TEXT)')
    raw.execute("INSERT INTO alerts (timestamp, module, alert_type, severity, description) "
                "VALUES ('2026-01-01', 'FIM', 't', 'LOW', 'd')")
    raw.commit()
    raw.close()
    monkeypatch.setattr(db, 'DB_PATH', path)
    db.init_db()
    db.init_db()  # idempotent
    conn = db.get_connection()
    cols = {r[1] for r in conn.execute('PRAGMA table_info(alerts)')}
    assert {'status', 'fingerprint', 'geo_status'} <= cols
    assert conn.execute('SELECT status FROM alerts').fetchone()[0] == 'open'
    conn.close()


def test_csv_export_neutralises_formulas(temp_db):
    import csv
    conn = db.get_connection()
    insert(conn, description='=HYPERLINK("http://evil","x")')
    insert(conn, description='+cmd|calc', dedup_subject='2')
    insert(conn, description='normal text', dedup_subject='3')
    conn.close()
    content = db.export_alerts_csv()
    rows = list(csv.DictReader(content.splitlines()))
    descriptions = sorted(r['description'] for r in rows)
    assert all(not d.startswith(('=', '+', '-', '@')) for d in descriptions)
    assert "'=HYPERLINK(\"http://evil\",\"x\")" in descriptions
    assert 'normal text' in descriptions
