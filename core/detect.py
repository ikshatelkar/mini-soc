"""Detection service: normalizes telemetry into events and runs the rule engine.

Every detection module now emits a *normalized event* here instead of composing
an alert itself. This is the layering a real SIEM uses, and it buys two things:

  * one place where rules are evaluated, so a rule works the same regardless of
    which collector produced the event;
  * derived fields computed once, centrally, so YAML rules stay readable. A rule
    can say `is_off_hours: true` rather than restating timezone arithmetic, and
    `is_noise_account: true` rather than enumerating machine-account suffixes in
    every rule that needs them.

Normalized event shape:

    source        'winevt' | 'fim' | 'network' | 'authlog'
    time          timezone-aware UTC datetime
    source_ip     routable public IP if the event carried one, else None
    origin        best identifier of where the activity came from
    data          source-specific fields (dotted-path addressable from YAML)
    raw           original payload for analyst triage
    <derived>     the is_* / *_name helpers documented in the rule files
"""

from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timezone

import config  # type: ignore
from core.events import HOSTNAME, Alert  # type: ignore
from core.pipeline import submit  # type: ignore
from core.ruleengine import RuleEngine  # type: ignore
from core.ruleloader import describe_load, load_rules  # type: ignore

# ---------------------------------------------------------------------------
# Derived-field helpers
# ---------------------------------------------------------------------------

LOGON_TYPE_NAMES = {
    2: 'Interactive (console)', 3: 'Network', 4: 'Batch', 5: 'Service',
    7: 'Unlock', 8: 'NetworkCleartext', 9: 'NewCredentials',
    10: 'RemoteInteractive (RDP)', 11: 'CachedInteractive',
}

REMOTE_LOGON_TYPES = {3, 8, 10}

# Well-known non-human accounts. Windows generates constant benign logon churn
# for these; without filtering, a workstation produces hundreds of alerts an hour
# from the OS talking to itself.
NOISE_ACCOUNTS = {
    'system', 'local service', 'network service', 'anonymous logon',
    'local system', '-', '', 'dwm-1', 'dwm-2', 'dwm-3', 'umfd-0', 'umfd-1',
}

# Services whose disabling is a recognised attack step (T1562.001).
DEFENSIVE_SERVICES = {
    'windefend', 'wdnissvc', 'wdfilter', 'wdboot', 'sense',
    'securityhealthservice', 'mpssvc', 'bfe', 'eventlog',
    'sysmon', 'sysmon64', 'wscsvc', 'sgrmbroker', 'mbamservice',
}

DEFENSIVE_KEYWORDS = (
    'defender', 'antivirus', 'anti-virus', 'firewall', 'event log',
    'security center', 'security health', 'sysmon', 'endpoint protection',
    'base filtering', 'malwarebytes', 'crowdstrike', 'sentinelone',
)


def is_noise_account(account: str | None) -> bool:
    if account is None:
        return True
    lowered = account.strip().lower()
    # Trailing '$' marks a computer account.
    return lowered.endswith('$') or lowered in NOISE_ACCOUNTS


def is_defensive_service(name: str | None) -> bool:
    if not name:
        return False
    lowered = name.strip().lower()
    if lowered in DEFENSIVE_SERVICES:
        return True
    return any(keyword in lowered for keyword in DEFENSIVE_KEYWORDS)


def is_off_hours(when: datetime) -> bool:
    start, end = config.BUSINESS_HOURS
    return not (start <= when.astimezone().hour < end)


def clean_ip(value: str | None) -> str | None:
    """Return the address if it identifies a real remote party, else None.

    Deliberately *not* the same test as "can this be geolocated". Private
    addresses cannot be located on a map but absolutely matter: a brute force
    from 192.168.1.50 is lateral movement from an already-compromised machine on
    your own network, which is worse news than the same attack from the internet.
    Dropping the address because a map pin is unavailable would throw away the
    single most useful field in the alert.

    Only genuinely meaningless values are discarded: Windows' '-' placeholder,
    loopback, and the unspecified address. Whether a lookup is worthwhile is
    decided later by the enrichment worker, which skips non-routable addresses
    without spending rate-limit budget on them.
    """
    if not value:
        return None
    candidate = value.strip()
    if candidate in ('-', '', '::', '0.0.0.0'):
        return None
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        # Not an IP at all (Windows sometimes writes a hostname here).
        return None
    if parsed.is_loopback or parsed.is_unspecified:
        return None
    return candidate


# ---------------------------------------------------------------------------
# Event construction
# ---------------------------------------------------------------------------

def build_winevt_event(event: dict) -> dict:
    """Normalize a Windows Event Log event and attach derived fields."""
    data = dict(event.get('data') or {})
    when = event.get('time_created') or datetime.now(timezone.utc)

    raw_ip = data.get('IpAddress')
    source_ip = clean_ip(raw_ip)
    workstation = (data.get('WorkstationName') or '').strip()

    try:
        logon_type = int(data.get('LogonType') or 0)
    except (TypeError, ValueError):
        logon_type = 0

    # 4732/4728 identify the added member by name or, failing that, by SID.
    member = data.get('MemberName') or data.get('MemberSid')
    if member and member.startswith('CN='):
        # Distinguished names are unreadable in an alert; keep the common name.
        member = member.split(',', 1)[0][3:]

    # 7040's fields are positional: param1 is the service display name.
    service_name = data.get('param1') or data.get('ServiceName')

    account = (data.get('TargetUserName') or data.get('SubjectUserName'))

    return {
        'source': 'winevt',
        'channel': event.get('channel'),
        'event_id': event.get('event_id'),
        'record_id': event.get('record_id'),
        'time': when,
        'host': event.get('computer') or HOSTNAME,
        'provider': event.get('provider'),
        'source_ip': source_ip,
        'origin': source_ip or workstation or 'local',
        'data': data,
        'raw': event.get('raw_xml'),
        # Derived fields referenced by the YAML rules.
        'logon_type_name': LOGON_TYPE_NAMES.get(logon_type, f'type {logon_type}'),
        'is_remote_logon': logon_type in REMOTE_LOGON_TYPES,
        'is_off_hours': is_off_hours(when),
        'is_noise_account': is_noise_account(account),
        'is_defensive_service': is_defensive_service(service_name),
        'service_name': service_name,
        'member': member,
    }


def build_fim_event(change_type: str, path: str, directory: str) -> dict:
    filename = os.path.basename(path)
    sensitive = any(
        _fnmatch_ci(filename, pattern)
        for pattern in getattr(config, 'FIM_SENSITIVE_PATTERNS', [])
    )
    return {
        'source': 'fim',
        'time': datetime.now(timezone.utc),
        'host': HOSTNAME,
        'source_ip': None,
        'origin': 'local',
        'change_type': change_type,
        'is_sensitive': sensitive,
        'data': {'path': path, 'filename': filename, 'directory': directory},
        'raw': None,
    }


def build_network_event(kind: str, data: dict, *, port_description: str = '',
                        network_exposed: bool = False,
                        source_ip: str | None = None) -> dict:
    return {
        'source': 'network',
        'time': datetime.now(timezone.utc),
        'host': HOSTNAME,
        'source_ip': clean_ip(source_ip),
        'origin': source_ip or 'local',
        'kind': kind,
        'port_description': port_description,
        'network_exposed': network_exposed,
        'data': data,
        'raw': None,
    }


def build_authlog_event(status: str, user: str, ip: str | None, hour: int,
                        recent_failures: int, line: str) -> dict:
    when = datetime.now(timezone.utc)
    return {
        'source': 'authlog',
        'time': when,
        'host': HOSTNAME,
        'source_ip': clean_ip(ip),
        'origin': ip or 'local',
        'is_off_hours': not (config.BUSINESS_HOURS[0] <= hour < config.BUSINESS_HOURS[1]),
        'data': {'status': status, 'user': user, 'hour': hour,
                 'recent_failures': recent_failures, 'ip': ip},
        'raw': line,
    }


def _fnmatch_ci(name: str, pattern: str) -> bool:
    import fnmatch
    return fnmatch.fnmatch(name.lower(), pattern.lower())


# ---------------------------------------------------------------------------
# Engine wiring
# ---------------------------------------------------------------------------

def _emit_alert(rule, severity, message, source_ip, entities, dedup_subject, raw,
                host=None):
    """Turn a firing rule into an alert on the pipeline.

    `host` comes from the event that triggered the rule, not from this
    process's own hostname - in 'server' role the event may have been
    forwarded by an agent running on a different machine entirely, and the
    whole point of stamping a host is knowing *which* machine had the
    problem. Falls back to this process's own HOSTNAME only for the
    (should-never-happen) case of an event with no host field at all.
    """
    submit(Alert(
        module=rule.module,
        alert_type=rule.alert_type,
        severity=severity,
        description=message,
        source_ip=source_ip,
        rule_id=rule.id,
        technique=rule.technique,
        entities=entities,
        raw=raw,
        dedup_subject=dedup_subject,
        host=host or HOSTNAME,
    ))


engine = RuleEngine(emit=_emit_alert)


def load_ruleset(rules_dir: str | None = None) -> dict:
    """Load (or reload) rules from disk. Safe to call while running."""
    rules_dir = rules_dir or config.RULES_DIR
    rules, exceptions, errors = load_rules(rules_dir)
    engine.set_rules(rules, exceptions, errors)
    describe_load(rules, exceptions, errors)
    return engine.stats()


def _route_event(event: dict) -> None:
    """Decide who evaluates this event, based on this process's role.

    'agent': never runs the rule engine or carries rules - it only collects
    and forwards raw events to the server (core/forwarder.py). 'standalone'
    and 'server' both evaluate locally, exactly as every role did before
    Phase 5 - a 'server' additionally receives forwarded events through
    app.py's /api/ingest, which calls engine.process() directly for those.
    """
    if config.DEPLOYMENT_ROLE == 'agent':
        from core.forwarder import forwarder  # local import: agent-role only
        forwarder.submit(event)
    else:
        engine.process(event)


# Convenience entry points used by the collectors.

def process_winevt(event: dict) -> None:
    _route_event(build_winevt_event(event))


def process_fim(change_type: str, path: str, directory: str) -> None:
    _route_event(build_fim_event(change_type, path, directory))


def process_network(kind: str, data: dict, **kwargs) -> None:
    _route_event(build_network_event(kind, data, **kwargs))


def process_authlog(status: str, user: str, ip: str | None, hour: int,
                    recent_failures: int, line: str) -> None:
    _route_event(build_authlog_event(status, user, ip, hour, recent_failures, line))
