"""Normalized alert schema shared by every detection module.

Detection modules construct an Alert and hand it to the pipeline; nothing writes
to the database directly. Keeping one shape for every alert is what makes the
later phases cheap:

  * ``host`` is stamped on every alert now, so shipping alerts from several
    machines to a central collector later needs no schema change.
  * ``rule_id`` and ``technique`` are carried through unused for now - the YAML
    rule engine and its MITRE ATT&CK mappings populate them in Phase 2.
  * ``entities`` holds the concrete things an alert is *about* (the IP, the
    account, the process, the file). Response actions in a later phase need a
    machine-readable target to act on, not a prose description.
"""

import hashlib
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone

# Ordered least to most urgent, so severity floors can be compared numerically.
SEVERITY_ORDER = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

HOSTNAME = socket.gethostname()


def severity_rank(severity: str) -> int:
    """Position of a severity in SEVERITY_ORDER; unknown values sort lowest."""
    try:
        return SEVERITY_ORDER.index((severity or '').upper())
    except ValueError:
        return -1


def meets_threshold(severity: str, minimum: str) -> bool:
    """True if `severity` is at least as urgent as `minimum`."""
    return severity_rank(severity) >= severity_rank(minimum)


@dataclass
class Alert:
    module: str
    alert_type: str
    severity: str
    description: str

    source_ip: str | None = None

    # Populated by the Phase 2 rule engine.
    rule_id: str | None = None
    technique: str | None = None

    # Machine-readable subjects of the alert, e.g. {'user': 'admin', 'port': 4444}.
    entities: dict = field(default_factory=dict)

    # The original log line or event payload, kept for analyst triage.
    raw: str | None = None

    # Overrides the fingerprint's variable part when the default is too coarse or
    # too fine. FIM passes the file path so two different modified files stay
    # separate alerts rather than collapsing into one.
    dedup_subject: str | None = None

    host: str = HOSTNAME
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def fingerprint(self) -> str:
        """Stable identity for this *kind* of alert, used to collapse repeats.

        Deliberately excludes the timestamp, the description's variable parts and
        the occurrence count: two alerts with the same fingerprint are the same
        condition recurring, not new information.
        """
        subject = self.dedup_subject if self.dedup_subject is not None else (self.source_ip or '')
        parts = [self.host, self.module, self.alert_type, str(subject)]
        return hashlib.sha256('|'.join(parts).encode('utf-8')).hexdigest()[:32]

    def notification_title(self) -> str:
        return f"SOC ALERT: {self.severity}"

    def notification_body(self) -> str:
        return f"[{self.module}] {self.alert_type}\n{self.description}"
