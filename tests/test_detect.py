"""Normalization helpers and end-to-end evaluation against the shipped rules."""

from datetime import datetime, timezone

import pytest

from core import detect
from core.winevt import parse_event_xml


@pytest.fixture(autouse=True)
def shipped_rules():
    detect.load_ruleset()
    yield


@pytest.mark.parametrize('value,expected', [
    (None, None), ('', None), ('-', None), ('::', None), ('0.0.0.0', None),
    ('127.0.0.1', None), ('::1', None), ('not-an-ip', None),
    ('192.168.1.50', '192.168.1.50'), (' 8.8.8.8 ', '8.8.8.8'),
])
def test_clean_ip(value, expected):
    assert detect.clean_ip(value) == expected


@pytest.mark.parametrize('account,expected', [
    (None, True), ('SYSTEM', True), ('WORKSTATION$', True), ('-', True),
    ('alice', False), ('Administrator', False),
])
def test_is_noise_account(account, expected):
    assert detect.is_noise_account(account) is expected


def test_is_defensive_service():
    assert detect.is_defensive_service('WinDefend')
    assert detect.is_defensive_service('Microsoft Defender Antivirus Service')
    assert not detect.is_defensive_service('Print Spooler')
    assert not detect.is_defensive_service(None)


def test_build_winevt_event_derived_fields():
    event = detect.build_winevt_event({
        'channel': 'Security', 'event_id': 4625, 'computer': 'PC1',
        'time_created': datetime(2026, 1, 1, 12, tzinfo=timezone.utc),
        'data': {'IpAddress': '10.0.0.5', 'LogonType': '10', 'TargetUserName': 'bob',
                 'MemberName': 'CN=Bob Smith,OU=Users,DC=corp'},
    })
    assert event['source_ip'] == '10.0.0.5'
    assert event['origin'] == '10.0.0.5'
    assert event['is_remote_logon'] is True
    assert event['logon_type_name'] == 'RemoteInteractive (RDP)'
    assert event['member'] == 'Bob Smith'
    assert event['host'] == 'PC1'


def test_build_winevt_event_bad_logon_type():
    event = detect.build_winevt_event({'data': {'LogonType': 'abc'}})
    assert event['logon_type_name'] == 'type 0'


def test_fim_sensitive_flag():
    assert detect.build_fim_event('modified', r'C:\x\HOSTS', r'C:\x')['is_sensitive']
    assert not detect.build_fim_event('modified', r'C:\x\notes.txt', r'C:\x')['is_sensitive']


def _winevt(event_id, data, channel='Security'):
    return detect.build_winevt_event({'channel': channel, 'event_id': event_id,
                                      'computer': 'PC1', 'data': data})


def test_windows_brute_force_end_to_end(captured_alerts):
    for _ in range(5):
        detect.engine.process(_winevt(4625, {'TargetUserName': 'victim',
                                             'IpAddress': '203.0.113.9', 'LogonType': '3'}))
    alerts = [a for a in captured_alerts if a.rule_id == 'WIN-AUTH-BRUTE-FORCE']
    assert len(alerts) == 1
    assert alerts[0].severity == 'CRITICAL'  # remote logon escalation
    assert alerts[0].host == 'PC1'


def test_noise_account_is_not_brute_forced(captured_alerts):
    for _ in range(10):
        detect.engine.process(_winevt(4625, {'TargetUserName': 'PC1$', 'IpAddress': '203.0.113.9'}))
    assert not [a for a in captured_alerts if a.rule_id == 'WIN-AUTH-BRUTE-FORCE']


def test_audit_log_cleared_names_the_actor(captured_alerts):
    """1102 stores SubjectUserName under UserData, not EventData."""
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><Provider Name="Microsoft-Windows-Eventlog"/><EventID>1102</EventID>'
        '<EventRecordID>77</EventRecordID><Channel>Security</Channel><Computer>PC1</Computer>'
        '<TimeCreated SystemTime="2026-01-01T10:00:00.1234567Z"/></System>'
        '<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
        '<SubjectUserSid>S-1-5-21</SubjectUserSid><SubjectUserName>mallory</SubjectUserName>'
        '<SubjectDomainName>CORP</SubjectDomainName></LogFileCleared></UserData></Event>'
    )
    parsed = parse_event_xml(xml)
    assert parsed['data'].get('SubjectUserName') == 'mallory'
    detect.process_winevt(parsed)
    cleared = [a for a in captured_alerts if a.rule_id == 'WIN-AUDIT-LOG-CLEARED']
    assert cleared and 'mallory' in cleared[0].description


def test_parse_event_xml_eventdata_and_time():
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><EventID Qualifiers="16384">7045</EventID><Channel>System</Channel>'
        '<TimeCreated SystemTime="2026-03-04T05:06:07.123456789Z"/></System>'
        '<EventData><Data Name="ServiceName">evil</Data><Data>positional</Data></EventData></Event>'
    )
    parsed = parse_event_xml(xml)
    assert parsed['event_id'] == 7045
    assert parsed['data'] == {'ServiceName': 'evil', '_1': 'positional'}
    assert parsed['time_created'] == datetime(2026, 3, 4, 5, 6, 7, 123456, tzinfo=timezone.utc)


def test_suspicious_service_install_is_critical(captured_alerts):
    detect.engine.process(_winevt(7045, {'ServiceName': 'updater',
                                         'ImagePath': r'C:\Users\Public\x.exe'}, channel='System'))
    alert = [a for a in captured_alerts if a.rule_id == 'WIN-SERVICE-INSTALLED'][0]
    assert alert.severity == 'CRITICAL'


def test_authlog_success_after_failures(captured_alerts):
    detect.process_authlog('Accepted', 'root', '198.51.100.7', 12, 4, 'line')
    ids = {a.rule_id for a in captured_alerts}
    assert {'AUTH-SUCCESS-AFTER-FAILURES', 'AUTH-ROOT-LOGIN'} <= ids


def test_authlog_brute_force_reports_failure_count(captured_alerts):
    for _ in range(5):
        detect.process_authlog('Failed', 'admin', '198.51.100.8', 12, 0, 'line')
    alert = [a for a in captured_alerts if a.rule_id == 'AUTH-BRUTE-FORCE'][0]
    assert alert.entities.get('failure_count') == 5


def test_network_listener_exposed(captured_alerts):
    detect.process_network('listener', {'port': 4444, 'pid': 1, 'process': 'nc.exe',
                                        'bind_address': '0.0.0.0'},
                           port_description='Metasploit', network_exposed=True)
    assert captured_alerts[0].severity == 'CRITICAL'
