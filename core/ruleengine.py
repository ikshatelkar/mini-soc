"""Declarative detection rule engine.

Detections used to be Python functions. They are now YAML documents evaluated by
this engine, which matters for three reasons:

  * **Tuning without code.** Changing a threshold, muting a noisy rule or
    adjusting a severity is a text edit, not a patch. Someone deploying this tool
    who is not a Python developer can still own their detections.
  * **Exceptions are first class.** Every real deployment eventually needs "stop
    alerting on this known-good thing." Without that escape hatch, operators mute
    the whole tool instead of the one rule, and then it protects nothing.
  * **Coverage is inspectable.** Rules carry their MITRE ATT&CK technique, so
    "what do we actually detect?" is a question the tool can answer about itself.

Deliberately not a general-purpose language. Rules are a fixed grammar -
field conditions plus one of three correlation strategies - because an
expressive DSL is where projects like this go to die. If a detection genuinely
cannot be expressed here, it belongs in Python.

Evaluation order for each event, per rule:
    match (cheap identity check) -> exclusions -> conditions -> correlation
Exclusions are checked before conditions and before correlation state is
touched, so an excluded event contributes nothing to a threshold count.
"""

from __future__ import annotations

import fnmatch
import re
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Field resolution
# ---------------------------------------------------------------------------

_MISSING = object()


def resolve_field(event: dict, path: str) -> Any:
    """Look up a dotted path such as 'data.TargetUserName' in an event."""
    current: Any = event
    for part in path.split('.'):
        if isinstance(current, dict):
            current = current.get(part, _MISSING)
        else:
            return _MISSING
        if current is _MISSING:
            return _MISSING
    return current


def _as_text(value: Any) -> str:
    return '' if value is None else str(value)


def _as_number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Conditions
# ---------------------------------------------------------------------------

class RuleError(ValueError):
    """Raised for a malformed rule. Carries a message aimed at whoever wrote it."""


# Every operator is case-insensitive for text. Security data is inconsistently
# cased - Windows reports the same account as 'Administrator', 'ADMINISTRATOR'
# and 'administrator' depending on the code path - and a rule that misses
# because of casing is worse than no rule.
OPERATORS = {
    'equals', 'not_equals', 'in', 'not_in', 'contains', 'contains_any',
    'not_contains', 'glob', 'glob_any', 'regex', 'gte', 'lte', 'exists',
}


class Condition:
    __slots__ = ('field', 'op', 'value', '_regex', '_lower_value', '_lower_list')

    def __init__(self, spec: dict):
        if not isinstance(spec, dict):
            raise RuleError(f'condition must be a mapping, got {type(spec).__name__}')

        field = spec.get('field')
        if not field or not isinstance(field, str):
            raise RuleError("condition needs a 'field' (e.g. field: data.TargetUserName)")
        self.field = field

        found = [key for key in spec if key in OPERATORS]
        if len(found) != 1:
            raise RuleError(
                f"condition on '{field}' needs exactly one operator from "
                f"{sorted(OPERATORS)}, found {found or 'none'}"
            )
        self.op = found[0]
        self.value = spec[self.op]

        self._regex = None
        self._lower_value = None
        self._lower_list = None

        if self.op == 'regex':
            try:
                self._regex = re.compile(str(self.value), re.IGNORECASE)
            except re.error as exc:
                raise RuleError(f"invalid regex on '{field}': {exc}") from exc
        elif self.op in ('in', 'not_in', 'contains_any', 'glob_any'):
            if not isinstance(self.value, (list, tuple)):
                raise RuleError(f"'{self.op}' on '{field}' requires a list")
            self._lower_list = [_as_text(v).lower() for v in self.value]
        elif self.op in ('equals', 'not_equals', 'contains', 'not_contains', 'glob'):
            self._lower_value = _as_text(self.value).lower()
        elif self.op in ('gte', 'lte'):
            if _as_number(self.value) is None:
                raise RuleError(f"'{self.op}' on '{field}' requires a number")

    def matches(self, event: dict) -> bool:
        actual = resolve_field(event, self.field)

        if self.op == 'exists':
            present = actual is not _MISSING and actual is not None
            return present is bool(self.value)

        if actual is _MISSING:
            # A missing field cannot satisfy a positive test, but *does* satisfy a
            # negative one - "not in this deny-list" is true when the field is
            # absent entirely.
            return self.op in ('not_equals', 'not_in', 'not_contains')

        text = _as_text(actual).lower()

        if self.op == 'equals':
            return text == self._lower_value
        if self.op == 'not_equals':
            return text != self._lower_value
        if self.op == 'in':
            return text in self._lower_list
        if self.op == 'not_in':
            return text not in self._lower_list
        if self.op == 'contains':
            return self._lower_value in text
        if self.op == 'not_contains':
            return self._lower_value not in text
        if self.op == 'contains_any':
            return any(v in text for v in self._lower_list)
        if self.op == 'glob':
            return fnmatch.fnmatch(text, self._lower_value)
        if self.op == 'glob_any':
            return any(fnmatch.fnmatch(text, v) for v in self._lower_list)
        if self.op == 'regex':
            return self._regex.search(_as_text(actual)) is not None
        if self.op in ('gte', 'lte'):
            number = _as_number(actual)
            if number is None:
                return False
            threshold = _as_number(self.value)
            return number >= threshold if self.op == 'gte' else number <= threshold

        return False


def _build_conditions(specs, label: str) -> list[Condition]:
    if specs is None:
        return []
    if not isinstance(specs, list):
        raise RuleError(f"'{label}' must be a list of conditions")
    return [Condition(spec) for spec in specs]


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

class Correlator:
    """Sliding-window state for threshold and distinct-count correlation.

    State is bounded by pruning on every access plus a periodic sweep, so a
    long-running service does not accumulate a bucket per account ever seen.
    """

    def __init__(self):
        self._counts: dict[str, deque] = defaultdict(deque)
        self._distinct: dict[str, dict[str, datetime]] = defaultdict(dict)
        self._lock = threading.Lock()
        self._last_sweep = datetime.now(timezone.utc)

    def add_and_count(self, key: str, when: datetime, window: timedelta) -> int:
        with self._lock:
            bucket = self._counts[key]
            bucket.append(when)
            cutoff = when - window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            return len(bucket)

    def add_and_count_distinct(self, key: str, value: str, when: datetime,
                               window: timedelta) -> int:
        with self._lock:
            seen = self._distinct[key]
            seen[value] = when
            cutoff = when - window
            for name, last in list(seen.items()):
                if last < cutoff:
                    del seen[name]
            return len(seen)

    def reset(self, key: str) -> None:
        with self._lock:
            self._counts.pop(key, None)
            self._distinct.pop(key, None)

    def sweep(self, now: datetime, window: timedelta) -> None:
        """Drop empty buckets. Cheap and bounds memory over long uptimes."""
        if now - self._last_sweep < timedelta(minutes=5):
            return
        with self._lock:
            self._last_sweep = now
            cutoff = now - window
            for key in list(self._counts):
                bucket = self._counts[key]
                while bucket and bucket[0] < cutoff:
                    bucket.popleft()
                if not bucket:
                    del self._counts[key]
            for key in list(self._distinct):
                seen = self._distinct[key]
                for name, last in list(seen.items()):
                    if last < cutoff:
                        del seen[name]
                if not seen:
                    del self._distinct[key]

    def stats(self) -> dict:
        with self._lock:
            return {'threshold_keys': len(self._counts),
                    'distinct_keys': len(self._distinct)}


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

VALID_SEVERITIES = {'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
CORRELATION_TYPES = {'single', 'threshold', 'distinct'}

_TEMPLATE_TOKEN = re.compile(r'\{([A-Za-z0-9_.]+)\}')


class Rule:
    def __init__(self, spec: dict, origin: str = '<inline>'):
        if not isinstance(spec, dict):
            raise RuleError('rule must be a mapping')

        self.origin = origin
        self.id = spec.get('id')
        if not self.id:
            raise RuleError("rule needs an 'id'")

        self.title = spec.get('title') or self.id
        self.enabled = bool(spec.get('enabled', True))
        self.source = spec.get('source')
        if not self.source:
            raise RuleError(f"rule '{self.id}' needs a 'source' (e.g. winevt, fim)")

        self.severity = (spec.get('severity') or 'MEDIUM').upper()
        if self.severity not in VALID_SEVERITIES:
            raise RuleError(
                f"rule '{self.id}' has invalid severity '{self.severity}'; "
                f'valid values are {sorted(VALID_SEVERITIES)}'
            )

        self.technique = spec.get('technique')
        self.alert_type = spec.get('alert_type') or self.title
        self.module = spec.get('module') or self.source.upper()

        match = spec.get('match') or {}
        if not isinstance(match, dict):
            raise RuleError(f"rule '{self.id}': 'match' must be a mapping")
        self.match = {k: v for k, v in match.items()}

        self.conditions = _build_conditions(spec.get('conditions'), f"{self.id}.conditions")
        self.exclude = _build_conditions(spec.get('exclude'), f"{self.id}.exclude")

        # Conditional severity escalation; first matching entry wins.
        self.severity_when = []
        for entry in spec.get('severity_when') or []:
            if not isinstance(entry, dict) or 'severity' not in entry:
                raise RuleError(f"rule '{self.id}': severity_when entries need a 'severity'")
            sev = str(entry['severity']).upper()
            if sev not in VALID_SEVERITIES:
                raise RuleError(f"rule '{self.id}': invalid severity_when severity '{sev}'")
            self.severity_when.append(
                (sev, _build_conditions(entry.get('conditions'), f'{self.id}.severity_when'))
            )

        correlate = spec.get('correlate') or {'type': 'single'}
        if not isinstance(correlate, dict):
            raise RuleError(f"rule '{self.id}': 'correlate' must be a mapping")
        self.correlation_type = (correlate.get('type') or 'single').lower()
        if self.correlation_type not in CORRELATION_TYPES:
            raise RuleError(
                f"rule '{self.id}': correlate.type must be one of "
                f'{sorted(CORRELATION_TYPES)}'
            )
        self.correlate_count = int(correlate.get('count', 1))
        self.correlate_window = int(correlate.get('window_seconds', 300))
        self.correlate_key = correlate.get('key') or []
        if isinstance(self.correlate_key, str):
            self.correlate_key = [self.correlate_key]
        self.distinct_field = correlate.get('distinct_field')
        if self.correlation_type == 'distinct' and not self.distinct_field:
            raise RuleError(
                f"rule '{self.id}': correlate.type 'distinct' needs a 'distinct_field'"
            )
        # Reset the window after firing so one sustained attack yields periodic
        # alerts rather than one per event past the threshold.
        self.reset_after_fire = bool(correlate.get('reset_after_fire', True))

        self.message = spec.get('message') or self.title
        self.entities_spec = spec.get('entities') or {}
        if not isinstance(self.entities_spec, dict):
            raise RuleError(f"rule '{self.id}': 'entities' must be a mapping")
        self.dedup_fields = spec.get('dedup') or []
        if isinstance(self.dedup_fields, str):
            self.dedup_fields = [self.dedup_fields]
        self.ip_field = spec.get('ip_field', 'source_ip')

        self.fired = 0
        self.suppressed = 0

    # -- evaluation ------------------------------------------------------

    def matches_identity(self, event: dict) -> bool:
        """Cheap pre-filter on source/channel/event_id before doing real work."""
        if event.get('source') != self.source:
            return False
        for key, expected in self.match.items():
            actual = resolve_field(event, key)
            if actual is _MISSING:
                return False
            if isinstance(expected, (list, tuple)):
                if not any(_as_text(actual).lower() == _as_text(e).lower()
                           for e in expected):
                    return False
            elif _as_text(actual).lower() != _as_text(expected).lower():
                return False
        return True

    def is_excluded(self, event: dict) -> bool:
        return any(condition.matches(event) for condition in self.exclude)

    def conditions_met(self, event: dict) -> bool:
        return all(condition.matches(event) for condition in self.conditions)

    def correlation_key(self, event: dict) -> str:
        parts = [self.id]
        for field in self.correlate_key:
            value = resolve_field(event, field)
            parts.append('' if value is _MISSING else _as_text(value).lower())
        return '|'.join(parts)

    def resolve_severity(self, event: dict) -> str:
        for severity, conditions in self.severity_when:
            if conditions and all(c.matches(event) for c in conditions):
                return severity
        return self.severity

    def render(self, template: str, event: dict, extra: dict) -> str:
        def replace(match: re.Match) -> str:
            token = match.group(1)
            if token in extra:
                return _as_text(extra[token])
            value = resolve_field(event, token)
            return _as_text(value) if value is not _MISSING else f'<{token}?>'
        return _TEMPLATE_TOKEN.sub(replace, template)

    def build_entities(self, event: dict) -> dict:
        entities = {}
        for name, field in self.entities_spec.items():
            value = resolve_field(event, str(field))
            if value is not _MISSING and value is not None:
                entities[name] = value
        return entities

    def dedup_subject(self, event: dict) -> str | None:
        if not self.dedup_fields:
            return None
        parts = []
        for field in self.dedup_fields:
            value = resolve_field(event, field)
            parts.append('' if value is _MISSING else _as_text(value))
        return '|'.join(parts)

    def summary(self) -> dict:
        return {
            'id': self.id,
            'title': self.title,
            'enabled': self.enabled,
            'source': self.source,
            'severity': self.severity,
            'technique': self.technique,
            'correlation': self.correlation_type,
            'threshold': self.correlate_count if self.correlation_type != 'single' else None,
            'window_seconds': self.correlate_window if self.correlation_type != 'single' else None,
            'exclusions': len(self.exclude),
            'fired': self.fired,
            'suppressed': self.suppressed,
            'origin': self.origin,
        }


class GlobalException:
    """An allowlist entry applied across rules.

    Real deployments always have known-good activity that trips a good rule - a
    vulnerability scanner that fails logons all day, a backup account that works
    at 3am. Muting the rule loses genuine coverage; this mutes the specific thing.
    """

    def __init__(self, spec: dict, origin: str = '<inline>'):
        if not isinstance(spec, dict):
            raise RuleError('exception must be a mapping')
        self.comment = spec.get('comment') or '(no comment)'
        self.rule_ids = spec.get('rules') or []
        if isinstance(self.rule_ids, str):
            self.rule_ids = [self.rule_ids]
        self.conditions = _build_conditions(spec.get('conditions'), 'exception.conditions')
        if not self.conditions:
            raise RuleError('exception needs at least one condition')
        self.origin = origin
        self.hits = 0

    def applies_to(self, rule: Rule) -> bool:
        if not self.rule_ids:
            return True
        return any(fnmatch.fnmatch(rule.id, pattern) for pattern in self.rule_ids)

    def matches(self, event: dict) -> bool:
        return all(condition.matches(event) for condition in self.conditions)

    def summary(self) -> dict:
        return {'comment': self.comment, 'rules': self.rule_ids or ['*'],
                'hits': self.hits, 'origin': self.origin}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class RuleEngine:
    def __init__(self, emit):
        """`emit` receives (rule, severity, message, source_ip, entities,
        dedup_subject, raw, host) for each firing rule."""
        self._emit = emit
        self.rules: list[Rule] = []
        self.exceptions: list[GlobalException] = []
        self.load_errors: list[dict] = []
        self._correlator = Correlator()
        self._by_source: dict[str, list[Rule]] = defaultdict(list)
        self.events_processed = 0
        self.alerts_emitted = 0
        self.globally_excluded = 0

    def set_rules(self, rules: list[Rule], exceptions: list[GlobalException],
                  errors: list[dict] | None = None) -> None:
        self.rules = rules
        self.exceptions = exceptions
        self.load_errors = errors or []
        self._by_source.clear()
        for rule in rules:
            self._by_source[rule.source].append(rule)

    def process(self, event: dict) -> int:
        """Evaluate every rule for one event. Returns the number of alerts fired."""
        self.events_processed += 1
        now = event.get('time') or datetime.now(timezone.utc)
        self._correlator.sweep(now, timedelta(seconds=3600))

        fired = 0
        for rule in self._by_source.get(event.get('source'), ()):
            if not rule.enabled:
                continue
            try:
                if self._evaluate(rule, event, now):
                    fired += 1
            except Exception as exc:
                # A broken rule must not stop the others or the collector.
                print(f'[!] Rule "{rule.id}" raised during evaluation: {exc}')
        return fired

    def _evaluate(self, rule: Rule, event: dict, now: datetime) -> bool:
        if not rule.matches_identity(event):
            return False

        # Exclusions run before conditions and before correlation state is
        # touched, so excluded events never contribute to a threshold count.
        if rule.is_excluded(event):
            rule.suppressed += 1
            return False

        for exception in self.exceptions:
            if exception.applies_to(rule) and exception.matches(event):
                exception.hits += 1
                rule.suppressed += 1
                self.globally_excluded += 1
                return False

        if not rule.conditions_met(event):
            return False

        extra: dict[str, Any] = {}
        key = rule.correlation_key(event)
        window = timedelta(seconds=rule.correlate_window)

        if rule.correlation_type == 'threshold':
            count = self._correlator.add_and_count(key, now, window)
            extra['match_count'] = count
            if count < rule.correlate_count:
                return False
            if rule.reset_after_fire:
                self._correlator.reset(key)

        elif rule.correlation_type == 'distinct':
            value = resolve_field(event, rule.distinct_field)
            if value is _MISSING or value is None:
                return False
            count = self._correlator.add_and_count_distinct(
                key, _as_text(value).lower(), now, window)
            extra['distinct_count'] = count
            extra['match_count'] = count
            if count < rule.correlate_count:
                return False
            if rule.reset_after_fire:
                self._correlator.reset(key)

        severity = rule.resolve_severity(event)
        message = rule.render(rule.message, event, extra)
        entities = rule.build_entities(event)
        entities.update({k: v for k, v in extra.items() if k != 'match_count'
                         or rule.correlation_type != 'single'})

        source_ip = resolve_field(event, rule.ip_field)
        if source_ip is _MISSING:
            source_ip = None

        rule.fired += 1
        self.alerts_emitted += 1
        self._emit(rule=rule, severity=severity, message=message,
                   source_ip=source_ip, entities=entities,
                   dedup_subject=rule.dedup_subject(event),
                   raw=event.get('raw'), host=event.get('host'))
        return True

    # -- introspection ---------------------------------------------------

    def stats(self) -> dict:
        enabled = [r for r in self.rules if r.enabled]
        techniques = sorted({r.technique for r in enabled if r.technique})
        return {
            'rules_loaded': len(self.rules),
            'rules_enabled': len(enabled),
            'rules_disabled': len(self.rules) - len(enabled),
            'load_errors': self.load_errors,
            'exceptions': len(self.exceptions),
            'techniques_covered': techniques,
            'technique_count': len(techniques),
            'events_processed': self.events_processed,
            'alerts_emitted': self.alerts_emitted,
            'globally_excluded': self.globally_excluded,
            'correlation_state': self._correlator.stats(),
        }

    def rule_summaries(self) -> list[dict]:
        return [rule.summary() for rule in self.rules]

    def exception_summaries(self) -> list[dict]:
        return [exc.summary() for exc in self.exceptions]
