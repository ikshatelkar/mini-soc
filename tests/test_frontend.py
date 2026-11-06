"""Runs static/js/common.js's rendering helpers under Node with hostile input.

Alert fields come from attacker-influenced places (usernames in log lines,
ISP names from the geolocation provider), so every one of them must come out
of the renderer as inert text. Skipped when Node isn't installed.
"""

import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMMON_JS = os.path.join(ROOT, 'static', 'js', 'common.js')

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')

PAYLOAD = '"><img src=x onerror=alert(1)>\''

HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const ctx = {
  document: { querySelector: () => null, documentElement: {} },
  getComputedStyle: () => ({ getPropertyValue: () => '' }),
  window: {}, console, Date, Number, String, Math,
};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx);
const p = process.argv[3];
const alert = {
  id: 7, severity: p, status: p, description: p, technique: p, rule_id: p,
  module: p, geo_country: p, geo_city: p, geo_isp: p, source_ip: p,
  last_seen: p, occurrence_count: p,
};
const out = {
  escaped: vm.runInContext('escapeHtml', ctx)(p),
  row: vm.runInContext('alertRowHtml', ctx)(alert),
  badge: vm.runInContext('statusBadge', ctx)(p),
};
process.stdout.write(JSON.stringify(out));
"""


@pytest.fixture(scope='module')
def rendered(tmp_path_factory):
    harness = tmp_path_factory.mktemp('js') / 'harness.js'
    harness.write_text(HARNESS, encoding='utf-8')
    result = subprocess.run(['node', str(harness), COMMON_JS, PAYLOAD],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_escape_html_covers_attribute_quotes(rendered):
    assert rendered['escaped'] == '&quot;&gt;&lt;img src=x onerror=alert(1)&gt;&#39;'


@pytest.mark.parametrize('key', ['row', 'badge'])
def test_no_raw_markup_survives(rendered, key):
    html = rendered[key]
    assert '<img' not in html
    assert PAYLOAD not in html
    assert '"><img' not in html
