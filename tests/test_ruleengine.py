from datetime import datetime, timedelta, timezone

import pytest

import config
from core.ruleengine import Condition, Correlator, GlobalException, Rule, RuleEngine, RuleError
from core.ruleloader import load_rules


def make_engine():
    emitted = []
    engine = RuleEngine(emit=lambda **kw: emitted.append(kw))
    return engine, emitted


# -- conditions -------------------------------------------------------------

@pytest.mark.parametrize('spec,event,expected', [
    ({'field': 'a', 'equals': 'X'}, {'a': 'x'}, True),
    ({'field': 'a', 'equals': True}, {'a': True}, True),
    ({'field': 'a', 'not_equals': 'x'}, {}, True),
    ({'field': 'a', 'in': ['root', 'admin']}, {'a': 'ADMIN'}, True),
    ({'field': 'a', 'not_in': ['root']}, {'a': 'bob'}, True),
    ({'field': 'a', 'contains': 'shell'}, {'a': 'PowerShell.exe'}, True),
    ({'field': 'a', 'contains_any': ['x', 'enc']}, {'a': 'p -ENC abc'}, True),
    ({'field': 'a', 'glob': '*.exe'}, {'a': 'EVIL.EXE'}, True),
    ({'field': 'a', 'regex': r'^\d+$'}, {'a': 123}, True),
    ({'field': 'a', 'gte': 3}, {'a': '5'}, True),
    ({'field': 'a', 'lte': 3}, {'a': 'nan-ish'}, False),
    ({'field': 'a', 'exists': True}, {'a': None}, False),
    ({'field': 'a', 'exists': False}, {}, True),
    ({'field': 'd.x', 'equals': 1}, {'d': {'x': 1}}, True),
    ({'field': 'd.x.y', 'equals': 1}, {'d': {'x': 'str'}}, False),
])
def test_condition_operators(spec, event, expected):
    assert Condition(spec).matches(event) is expected


@pytest.mark.parametrize('spec', [
    {'equals': 1},
    {'field': 'a'},
    {'field': 'a', 'equals': 1, 'in': [1]},
    {'field': 'a', 'regex': '('},
    {'field': 'a', 'in': 'notalist'},
    {'field': 'a', 'gte': 'x'},
    'not a dict',
])
def test_condition_rejects_malformed(spec):
    with pytest.raises(RuleError):
        Condition(spec)


# -- rule validation ---------------------------------------------------------

def test_rule_requires_id_and_source():
    with pytest.raises(RuleError):
        Rule({'source': 'fim'})
    with pytest.raises(RuleError):
        Rule({'id': 'X'})


def test_rule_rejects_bad_severity_and_correlation():
    with pytest.raises(RuleError):
        Rule({'id': 'X', 'source': 'fim', 'severity': 'URGENT'})
    with pytest.raises(RuleError):
        Rule({'id': 'X', 'source': 'fim', 'correlate': {'type': 'magic'}})
    with pytest.raises(RuleError):
        Rule({'id': 'X', 'source': 'fim', 'correlate': {'type': 'distinct'}})


def test_numeric_rule_id_is_usable_with_exceptions():
    engine, emitted = make_engine()
    rule = Rule({'id': 123, 'source': 'fim'})
    exc = GlobalException({'rules': ['12*'], 'conditions': [{'field': 'x', 'equals': 1}]})
    engine.set_rules([rule], [exc])
    engine.process({'source': 'fim', 'x': 1})
    assert emitted == []
    assert exc.hits == 1


# -- evaluation --------------------------------------------------------------

def test_single_rule_fires_with_rendered_message_and_entities():
    engine, emitted = make_engine()
    rule = Rule({'id': 'R1', 'source': 'authlog', 'severity': 'high',
                 'match': {'data.status': 'Accepted'},
                 'message': 'login {data.user} from {source_ip} {missing.field}',
                 'entities': {'user': 'data.user'}, 'dedup': ['data.user']})
    engine.set_rules([rule], [])
    n = engine.process({'source': 'authlog', 'source_ip': '1.2.3.4', 'host': 'H',
                        'data': {'status': 'accepted', 'user': 'bob'}})
    assert n == 1
    alert = emitted[0]
    assert alert['severity'] == 'HIGH'
    assert alert['message'] == 'login bob from 1.2.3.4 <missing.field?>'
    assert alert['entities'] == {'user': 'bob'}
    assert alert['dedup_subject'] == 'bob'
    assert alert['host'] == 'H'


def test_match_list_and_mismatch():
    rule = Rule({'id': 'R', 'source': 'winevt', 'match': {'event_id': [4732, 4728]}})
    assert rule.matches_identity({'source': 'winevt', 'event_id': 4728})
    assert not rule.matches_identity({'source': 'winevt', 'event_id': 4624})
    assert not rule.matches_identity({'source': 'fim', 'event_id': 4728})


def test_threshold_correlation_fires_at_count_and_resets():
    engine, emitted = make_engine()
    rule = Rule({'id': 'BF', 'source': 'authlog',
                 'correlate': {'type': 'threshold', 'count': 3, 'window_seconds': 60,
                               'key': ['source_ip']},
                 'message': '{match_count} failures'})
    engine.set_rules([rule], [])
    t0 = datetime.now(timezone.utc)
    for i in range(3):
        engine.process({'source': 'authlog', 'source_ip': '9.9.9.9', 'time': t0 + timedelta(seconds=i)})
    assert len(emitted) == 1
    assert emitted[0]['message'] == '3 failures'
    # reset after fire: two more is not enough
    for i in range(2):
        engine.process({'source': 'authlog', 'source_ip': '9.9.9.9', 'time': t0 + timedelta(seconds=10 + i)})
    assert len(emitted) == 1


def test_threshold_window_expiry():
    engine, emitted = make_engine()
    rule = Rule({'id': 'BF', 'source': 'authlog',
                 'correlate': {'type': 'threshold', 'count': 2, 'window_seconds': 10}})
    engine.set_rules([rule], [])
    t0 = datetime.now(timezone.utc)
    engine.process({'source': 'authlog', 'time': t0})
    engine.process({'source': 'authlog', 'time': t0 + timedelta(seconds=30)})
    assert emitted == []


def test_distinct_correlation():
    engine, emitted = make_engine()
    rule = Rule({'id': 'SPRAY', 'source': 'authlog',
                 'correlate': {'type': 'distinct', 'distinct_field': 'data.user', 'count': 3,
                               'key': ['source_ip']},
                 'entities': {'accounts': 'distinct_count'}})
    engine.set_rules([rule], [])
    for user in ['a', 'A', 'b', 'c']:
        engine.process({'source': 'authlog', 'source_ip': '1.1.1.1', 'data': {'user': user}})
    assert len(emitted) == 1
    assert emitted[0]['entities']['distinct_count'] == 3


def test_entities_can_reference_correlation_values():
    """rules/authlog.yaml maps `failure_count: match_count` - the entity must be populated."""
    engine, emitted = make_engine()
    rule = Rule({'id': 'BF', 'source': 'authlog',
                 'correlate': {'type': 'threshold', 'count': 2},
                 'entities': {'failure_count': 'match_count'}})
    engine.set_rules([rule], [])
    engine.process({'source': 'authlog'})
    engine.process({'source': 'authlog'})
    assert emitted[0]['entities'].get('failure_count') == 2


def test_exclusion_runs_before_correlation():
    engine, emitted = make_engine()
    rule = Rule({'id': 'BF', 'source': 'winevt',
                 'correlate': {'type': 'threshold', 'count': 2},
                 'exclude': [{'field': 'is_noise_account', 'equals': True}]})
    engine.set_rules([rule], [])
    engine.process({'source': 'winevt', 'is_noise_account': True})
    engine.process({'source': 'winevt', 'is_noise_account': False})
    assert emitted == []
    assert rule.suppressed == 1


def test_global_exception_scoped_by_glob():
    engine, emitted = make_engine()
    r1 = Rule({'id': 'WIN-OFF-HOURS-X', 'source': 'winevt'})
    r2 = Rule({'id': 'WIN-OTHER', 'source': 'winevt'})
    exc = GlobalException({'rules': ['*OFF-HOURS*'],
                           'conditions': [{'field': 'user', 'equals': 'svc'}]})
    engine.set_rules([r1, r2], [exc])
    engine.process({'source': 'winevt', 'user': 'svc'})
    assert [e['rule'].id for e in emitted] == ['WIN-OTHER']


def test_severity_when_escalates():
    engine, emitted = make_engine()
    rule = Rule({'id': 'R', 'source': 'fim', 'severity': 'LOW',
                 'severity_when': [{'severity': 'CRITICAL',
                                    'conditions': [{'field': 'is_sensitive', 'equals': True}]}]})
    engine.set_rules([rule], [])
    engine.process({'source': 'fim', 'is_sensitive': True})
    engine.process({'source': 'fim', 'is_sensitive': False})
    assert [e['severity'] for e in emitted] == ['CRITICAL', 'LOW']


def test_broken_rule_does_not_stop_others():
    engine, emitted = make_engine()
    good = Rule({'id': 'GOOD', 'source': 'fim'})
    bad = Rule({'id': 'BAD', 'source': 'fim'})
    bad.render = lambda *a, **k: 1 / 0
    engine.set_rules([bad, good], [])
    assert engine.process({'source': 'fim'}) == 1


def test_disabled_rule_skipped():
    engine, emitted = make_engine()
    engine.set_rules([Rule({'id': 'R', 'source': 'fim', 'enabled': False})], [])
    engine.process({'source': 'fim'})
    assert emitted == []


def test_correlator_sweep_bounds_memory():
    c = Correlator()
    old = datetime.now(timezone.utc) - timedelta(hours=2)
    c.add_and_count('k', old, timedelta(seconds=60))
    c.add_and_count_distinct('d', 'v', old, timedelta(seconds=60))
    c._last_sweep = old
    c.sweep(datetime.now(timezone.utc), timedelta(seconds=60))
    assert c.stats() == {'threshold_keys': 0, 'distinct_keys': 0}


# -- loader against the real rules directory ---------------------------------

def test_shipped_rules_load_cleanly():
    rules, exceptions, errors = load_rules(config.RULES_DIR)
    assert errors == []
    assert len(rules) > 20
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))


def test_every_winevt_rule_event_id_is_collected():
    """A rule whose event ID is never subscribed to can never fire."""
    rules, _, _ = load_rules(config.RULES_DIR)
    collected = {}
    for spec in config.WINEVT_CHANNELS:
        collected.setdefault(spec['channel'], set()).update(spec['event_ids'])
    missing = []
    for rule in rules:
        if rule.source != 'winevt':
            continue
        channel = rule.match.get('channel')
        ids = rule.match.get('event_id')
        ids = ids if isinstance(ids, list) else [ids]
        for eid in ids:
            if eid not in collected.get(channel, set()):
                missing.append((rule.id, channel, eid))
    assert missing == []


def test_loader_reports_bad_files(tmp_path):
    (tmp_path / 'bad.yaml').write_text('rules: [\n', encoding='utf-8')
    (tmp_path / 'dup.yaml').write_text(
        'rules:\n  - {id: A, source: fim}\n  - {id: A, source: fim}\n  - {source: fim}\n',
        encoding='utf-8')
    (tmp_path / 'exceptions.yaml').write_text(
        'exceptions:\n  - {comment: x}\n', encoding='utf-8')
    rules, exceptions, errors = load_rules(str(tmp_path))
    assert [r.id for r in rules] == ['A']
    assert exceptions == []
    files = sorted(e['file'] for e in errors)
    assert files == ['bad.yaml', 'dup.yaml', 'dup.yaml', 'exceptions.yaml']


def test_loader_missing_dir(tmp_path):
    _, _, errors = load_rules(str(tmp_path / 'nope'))
    assert errors and 'does not exist' in errors[0]['error']
