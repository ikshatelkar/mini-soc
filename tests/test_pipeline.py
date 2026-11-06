"""Writer loop: new alerts and escalations notify, plain recurrences stay silent."""

import time

import config
from core.events import Alert
from core.pipeline import AlertPipeline


class Recorder:
    def __init__(self):
        self.seen = []

    def submit(self, alert):
        self.seen.append(alert.severity)

    def stop(self):
        pass


def test_writer_notifies_on_insert_and_escalation_only(temp_db, monkeypatch):
    monkeypatch.setattr(config, 'GEO_ENRICHMENT_ENABLED', False)
    p = AlertPipeline()
    p.notifier = Recorder()
    p.email_immediate = None
    p._spawn(p._writer_loop, 'alert-writer')
    try:
        for sev in ['MEDIUM', 'MEDIUM', 'CRITICAL', 'LOW']:
            p.submit(Alert(module='FIM', alert_type='t', severity=sev, description='d'))
        deadline = time.time() + 5
        while p.inserted + p.aggregated < 4 and time.time() < deadline:
            time.sleep(0.05)
    finally:
        p.stop()
    assert p.notifier.seen == ['MEDIUM', 'CRITICAL']
    assert p.write_errors == 0
