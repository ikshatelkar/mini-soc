const FETCH_INTERVAL = 3000;

// ---------------------------------------------------------------------------
// Theme + detail-level toggles (persisted, so a choice survives a refresh)
// ---------------------------------------------------------------------------

function initThemeToggle() {
    const saved = localStorage.getItem('soc-theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);

    document.getElementById('theme-toggle').addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme')
            || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('soc-theme', next);
        // Chart colors are read from CSS custom properties at render time, so
        // they need a manual re-render on theme flip rather than waiting for
        // the next poll.
        refreshAll();
    });
}

function initModeToggle() {
    const saved = localStorage.getItem('soc-mode') || 'simple';
    document.body.setAttribute('data-mode', saved);
    document.querySelectorAll('#mode-toggle button').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.mode === saved);
        btn.addEventListener('click', () => {
            document.body.setAttribute('data-mode', btn.dataset.mode);
            localStorage.setItem('soc-mode', btn.dataset.mode);
            document.querySelectorAll('#mode-toggle button').forEach(b =>
                b.classList.toggle('active', b === btn));
        });
    });
}

function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// Module identity -> plain-language label + categorical color (identifies the
// monitoring source, never severity - those are different scales).
const MODULE_INFO = {
    WINEVT:   { label: 'System Activity',  varName: '--cat-1' },
    AUTHLOG:  { label: 'Login Attempts',   varName: '--cat-2' },
    FIM:      { label: 'File Changes',     varName: '--cat-3' },
    NETWORK:  { label: 'Network Activity', varName: '--cat-4' },
    LOG_MONITOR: { label: 'Login Attempts', varName: '--cat-2' },
};

function moduleLabel(module) {
    return (MODULE_INFO[module] && MODULE_INFO[module].label) || module;
}

function moduleColor(module) {
    const info = MODULE_INFO[module];
    return cssVar(info ? info.varName : '--text-muted') || '#898781';
}

// Severity -> status color. Status colors are fixed, never per-module.
const SEVERITY_VAR = {
    CRITICAL: '--status-critical',
    HIGH: '--status-serious',
    MEDIUM: '--status-warning',
    LOW: '--text-muted',
    INFO: '--text-muted',
};

function severityColor(sev) {
    return cssVar(SEVERITY_VAR[sev] || '--text-muted') || '#898781';
}

const SEVERITY_ICON = { CRITICAL: '\u{1F6A8}', HIGH: '⚠️', MEDIUM: '●', LOW: '○', INFO: '○' };

function relativeTime(isoString) {
    if (!isoString) return 'unknown';
    const then = new Date(isoString).getTime();
    const diffSec = Math.round((Date.now() - then) / 1000);
    if (diffSec < 5) return 'just now';
    if (diffSec < 60) return `${diffSec}s ago`;
    const min = Math.round(diffSec / 60);
    if (min < 60) return `${min}m ago`;
    const hr = Math.round(min / 60);
    if (hr < 24) return `${hr}h ago`;
    const day = Math.round(hr / 24);
    if (day < 30) return `${day}d ago`;
    return new Date(isoString).toLocaleDateString();
}

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

let lastStats = { modules: {}, severities: {}, total_events: 0, mapped_origins: 0,
                  lifecycle: { needs_attention: 0, open_total: 0, handled_total: 0 } };
let currentLogStatus = 'open';

// A session can expire (or be revoked) while the dashboard is sitting open in
// a tab. Every poll hits this same login-gated API, so checking once here
// and sending the tab back to /login is simpler than teaching every render
// function what an empty/401 response means.
function redirectIfUnauthorized(response) {
    if (response.status === 401) {
        window.location.href = '/login';
        return true;
    }
    return false;
}

async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        if (redirectIfUnauthorized(response)) return;
        lastStats = await response.json();
        renderCharts(lastStats);
        renderKPIs(lastStats);
    } catch (err) {
        console.error('Error fetching stats:', err);
    }
}

async function fetchNeedsAttention() {
    try {
        const response = await fetch('/api/alerts/needs-attention');
        if (redirectIfUnauthorized(response)) return;
        renderAttention(await response.json());
    } catch (err) {
        console.error('Error fetching needs-attention:', err);
    }
}

async function fetchAlerts() {
    try {
        const qs = currentLogStatus ? `?status=${currentLogStatus}` : '';
        const response = await fetch(`/api/alerts${qs}`);
        if (redirectIfUnauthorized(response)) return;
        updateTable(await response.json());
    } catch (err) {
        console.error('Error fetching alerts:', err);
    }
}

async function fetchGeoMap() {
    try {
        const response = await fetch('/api/geomap');
        if (redirectIfUnauthorized(response)) return;
        renderWorldMap(await response.json());
    } catch (err) {
        console.error('Error fetching geo map:', err);
    }
}

async function fetchHealth() {
    try {
        const response = await fetch('/api/health');
        if (redirectIfUnauthorized(response)) return;
        const health = await response.json();
        renderPipelineIndicator(health.pipeline);
        renderScope(health.fim_scope);
        renderTelemetry(health.event_log_channels, health.network_monitor);
        renderDetectionSummary(health.detection);
    } catch (err) {
        console.error('Error fetching health:', err);
    }
}

async function fetchAgents() {
    try {
        const response = await fetch('/api/agents');
        if (redirectIfUnauthorized(response)) return;
        renderAgents(await response.json());
    } catch (err) {
        console.error('Error fetching agents:', err);
    }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

async function postAction(path) {
    try {
        const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
        if (redirectIfUnauthorized(response)) return;
        await Promise.all([fetchNeedsAttention(), fetchAlerts(), fetchStats()]);
    } catch (err) {
        console.error('Action failed:', err);
    }
}

function acknowledgeAlert(id) { postAction(`/api/alerts/${id}/acknowledge`); }
function dismissAlert(id) { postAction(`/api/alerts/${id}/dismiss`); }
function reopenAlert(id) { postAction(`/api/alerts/${id}/reopen`); }

// ---------------------------------------------------------------------------
// Rendering: Needs Attention hero
// ---------------------------------------------------------------------------

function renderAttention(alerts) {
    const body = document.getElementById('attention-body');
    const subtitle = document.getElementById('attention-subtitle');
    const pill = document.getElementById('header-status-pill');
    const pillText = document.getElementById('header-status-text');

    if (!alerts || alerts.length === 0) {
        subtitle.textContent = '';
        body.innerHTML = `
            <div class="hero-empty">
                <div class="check-icon">✓</div>
                <div>
                    <h3>All clear</h3>
                    <p>Nothing needs your attention right now. Monitoring is active.</p>
                </div>
            </div>`;
        pill.className = 'status-pill good';
        pillText.textContent = 'All clear';
        return;
    }

    subtitle.textContent = `${alerts.length} item${alerts.length === 1 ? '' : 's'}`;
    pill.className = 'status-pill critical';
    pillText.textContent = `${alerts.length} need${alerts.length === 1 ? 's' : ''} attention`;

    body.innerHTML = `<div class="attention-list">${alerts.map(renderAttentionCard).join('')}</div>`;
}

function renderAttentionCard(a) {
    const cardClass = a.severity === 'CRITICAL' ? 'critical' : 'serious';
    const origin = a.geo_city ? `${a.geo_city}, ${a.geo_country}` : (a.source_ip || '');
    const technique = a.technique
        ? `<span class="technique-badge">${a.technique}</span>` : '';
    return `
        <div class="attention-card ${cardClass}">
            <span class="severity-chip ${a.severity}">${SEVERITY_ICON[a.severity] || ''} ${a.severity === 'CRITICAL' ? 'Critical' : 'High Priority'}</span>
            <div class="attention-body">
                <p class="attention-headline">${escapeHtml(a.description)}</p>
                <div class="attention-meta">
                    <span>${relativeTime(a.last_seen || a.timestamp)}</span>
                    ${origin ? `<span>${origin}</span>` : ''}
                    ${a.occurrence_count > 1 ? `<span>happened ${a.occurrence_count} times</span>` : ''}
                </div>
                <div class="attention-technical advanced-only">
                    ${a.rule_id || ''} ${technique}
                </div>
            </div>
            <div class="attention-actions">
                <button class="btn-action handle" type="button" onclick="acknowledgeAlert(${a.id})">Mark Handled</button>
                <button class="btn-action dismiss" type="button" onclick="dismissAlert(${a.id})">Dismiss</button>
            </div>
        </div>`;
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str ?? '';
    return div.innerHTML;
}

// ---------------------------------------------------------------------------
// Rendering: KPIs
// ---------------------------------------------------------------------------

function renderKPIs(stats) {
    const lifecycle = stats.lifecycle || {};
    const needsAttention = lifecycle.needs_attention || 0;

    document.getElementById('stat-needs-attention').textContent = needsAttention;
    document.getElementById('stat-handled').textContent = lifecycle.handled_total || 0;
    document.getElementById('stat-total-events').textContent = stats.total_events || 0;
    document.getElementById('stat-origins').textContent = stats.mapped_origins || 0;

    const tile = document.getElementById('tile-needs-attention');
    tile.classList.toggle('critical', needsAttention > 0);
    tile.classList.toggle('good', needsAttention === 0);
}

// ---------------------------------------------------------------------------
// Rendering: charts
// ---------------------------------------------------------------------------

function chartLayoutDefaults() {
    return {
        font: { family: 'system-ui, sans-serif', color: cssVar('--text-secondary') },
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        margin: { t: 40, b: 40, l: 40, r: 40 },
        titlefont: { size: 15, color: cssVar('--text-primary') },
    };
}

function renderCharts(stats) {
    const modules = stats.modules || {};
    const moduleKeys = Object.keys(modules);

    const pieData = [{
        values: moduleKeys.map(k => modules[k]),
        labels: moduleKeys.map(moduleLabel),
        type: 'pie',
        hole: 0.55,
        marker: {
            colors: moduleKeys.map(moduleColor),
            line: { color: cssVar('--surface-card'), width: 2 },
        },
        textinfo: 'label+percent',
        hoverinfo: 'label+value',
    }];
    Plotly.react('alerts-by-type-pie', pieData,
        { ...chartLayoutDefaults(), title: 'Activity by Source' },
        { displayModeBar: false, responsive: true });

    const severities = stats.severities || {};
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const sevLabels = order.filter(s => severities[s] !== undefined);

    const barData = [{
        x: sevLabels,
        y: sevLabels.map(s => severities[s]),
        type: 'bar',
        marker: {
            color: sevLabels.map(severityColor),
            line: { color: cssVar('--border'), width: 1 },
        },
    }];
    Plotly.react('alerts-by-severity-bar', barData, {
        ...chartLayoutDefaults(),
        title: 'Volume by Severity',
        xaxis: { gridcolor: cssVar('--gridline') },
        yaxis: { gridcolor: cssVar('--gridline') },
    }, { displayModeBar: false, responsive: true });
}

function renderWorldMap(geoData) {
    const statusEl = document.getElementById('map-status');
    if (!geoData || geoData.length === 0) {
        statusEl.textContent = 'No external activity mapped yet.';
        Plotly.react('attack-world-map', [], { ...chartLayoutDefaults() },
            { displayModeBar: false, responsive: true });
        return;
    }
    statusEl.textContent = `${geoData.length} location${geoData.length === 1 ? '' : 's'}`;

    const data = [{
        type: 'scattergeo',
        mode: 'markers',
        lat: geoData.map(d => d.geo_lat),
        lon: geoData.map(d => d.geo_lon),
        text: geoData.map(d => `${d.source_ip}<br>${d.geo_city}, ${d.geo_country}<br>${d.geo_isp}<br>Events: ${d.hit_count}`),
        marker: {
            size: geoData.map(d => Math.log2(d.hit_count + 1) * 8 + 5),
            color: geoData.map(d => severityColor(d.severity)),
            line: { color: cssVar('--surface-card'), width: 1 },
            opacity: 0.85,
        },
    }];

    Plotly.react('attack-world-map', data, {
        ...chartLayoutDefaults(),
        geo: {
            projection: { type: 'robinson' },
            bgcolor: 'rgba(0,0,0,0)',
            showland: true,
            landcolor: cssVar('--surface-sunken') || cssVar('--gridline'),
            showocean: true,
            oceancolor: cssVar('--surface-page'),
            showlakes: false,
            showcountries: true,
            countrycolor: cssVar('--gridline'),
        },
        margin: { t: 0, b: 0, l: 0, r: 0 },
    }, { displayModeBar: false, responsive: true });
}

// ---------------------------------------------------------------------------
// Rendering: health / scope
// ---------------------------------------------------------------------------

function renderPipelineIndicator(pipelineStats) {
    const el = document.getElementById('pipeline-indicator');
    if (!pipelineStats) return;
    el.textContent = `queue ${pipelineStats.queue_depth}/${pipelineStats.queue_capacity}`
        + (pipelineStats.dropped > 0 ? ` · ${pipelineStats.dropped} dropped` : '');
}

const TELEMETRY_STATUS_LABEL = {
    running: { icon: '\u{1F7E2}', text: 'collecting', cls: '' },
    access_denied: { icon: '\u{1F512}', text: 'needs admin', cls: 'missing' },
    not_available: { icon: '⚪', text: 'not installed', cls: '' },
    unavailable: { icon: '⚪', text: 'unavailable', cls: '' },
    degraded: { icon: '\u{1F7E1}', text: 'degraded', cls: '' },
    error: { icon: '\u{1F534}', text: 'error', cls: 'missing' },
    not_started: { icon: '⚪', text: 'starting...', cls: '' },
};

function renderScope(scope) {
    const el = document.getElementById('scope-body');
    if (!scope || scope.length === 0) {
        el.innerHTML = '<span style="color: var(--text-muted)">No directories configured for file monitoring.</span>';
        return;
    }
    el.innerHTML = scope.map(s => `
        <div class="scope-chip ${s.exists ? '' : 'missing'}">
            <span>\u{1F4C1} ${s.path}</span>
            <span class="scope-count">${s.exists ? `${s.file_count} file(s) watched` : 'not found'}</span>
        </div>`).join('');
}

function renderTelemetry(channels, network) {
    const el = document.getElementById('telemetry-body');
    if (!el) return;
    const chips = [];

    (channels || []).forEach(ch => {
        const s = TELEMETRY_STATUS_LABEL[ch.status] || { icon: '⚪', text: ch.status, cls: '' };
        const detail = ch.status === 'running' ? `${ch.events_seen} event(s)` : s.text;
        chips.push(`<div class="scope-chip ${s.cls}" title="${escapeHtml(ch.detail || s.text)}">
            <span>${s.icon} ${ch.channel}</span><span class="scope-count">${detail}</span></div>`);
    });

    if (network) {
        const s = TELEMETRY_STATUS_LABEL[network.status] || { icon: '⚪', text: network.status, cls: '' };
        const detail = (network.status === 'running' || network.status === 'degraded')
            ? `${network.listeners} listening, ${network.connections} established` : s.text;
        chips.push(`<div class="scope-chip ${s.cls}" title="${escapeHtml(network.detail || s.text)}">
            <span>${s.icon} Network sockets</span><span class="scope-count">${detail}</span></div>`);
    }
    el.innerHTML = chips.join('');
}

const AGENT_STATUS_LABEL = {
    online: { icon: '🟢', cls: '' },
    offline: { icon: '🔴', cls: 'missing' },
    'never connected': { icon: '⚪', cls: '' },
};

function renderAgents(agents) {
    const el = document.getElementById('agents-body');
    if (!el) return;
    if (!agents || agents.length === 0) {
        el.innerHTML = '<span style="color: var(--text-muted)">No workers enrolled yet - add one below.</span>';
        return;
    }
    el.innerHTML = agents.map(a => {
        const s = AGENT_STATUS_LABEL[a.status] || { icon: '⚪', cls: '' };
        const lastSeen = a.last_seen ? relativeTime(a.last_seen) : 'never';
        return `<div class="scope-chip ${s.cls}">
            <span>${s.icon} ${escapeHtml(a.name)}</span>
            <span class="scope-count">${a.status} · last seen ${lastSeen}</span>
            <button type="button" class="icon-btn agent-revoke" onclick="revokeAgent(${a.id}, '${escapeHtml(a.name)}')" title="Revoke this worker's access">Revoke</button>
        </div>`;
    }).join('');
}

async function revokeAgent(id, name) {
    if (!confirm(`Revoke access for "${name}"? It will stop being able to send events immediately.`)) return;
    try {
        const response = await fetch(`/api/agents/${id}`, { method: 'DELETE' });
        if (redirectIfUnauthorized(response)) return;
        await fetchAgents();
    } catch (err) {
        console.error('Error revoking agent:', err);
    }
}

function initAgentEnrollment() {
    const form = document.getElementById('agent-add-form');
    if (!form) return;
    form.addEventListener('submit', async (evt) => {
        evt.preventDefault();
        const input = document.getElementById('agent-name-input');
        const name = input.value.trim();
        if (!name) return;
        try {
            const response = await fetch('/api/agents', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name }),
            });
            if (redirectIfUnauthorized(response)) return;
            const result = await response.json();
            if (!response.ok) {
                alert(result.error || 'Could not enroll worker.');
                return;
            }
            const reveal = document.getElementById('agent-token-reveal');
            reveal.hidden = false;
            reveal.innerHTML = `<strong>Worker token (shown once - copy it now):</strong>
                <code class="mono">${escapeHtml(result.token)}</code>
                <p>Paste this into <code>config_local.py</code> as <code>AGENT_TOKEN</code> on
                "${escapeHtml(result.name)}", alongside <code>SERVER_URL</code> and
                <code>AGENT_NAME = "${escapeHtml(result.name)}"</code>. It cannot be shown again -
                revoke and re-enroll if it's lost.</p>`;
            input.value = '';
            await fetchAgents();
        } catch (err) {
            console.error('Error enrolling agent:', err);
        }
    });
}

function renderDetectionSummary(detection) {
    const el = document.getElementById('detection-summary');
    const errEl = document.getElementById('rule-errors');
    if (!el || !detection) return;

    el.textContent = `${detection.rules_enabled} rules active · `
        + `${detection.technique_count} ATT&CK techniques · `
        + `${detection.events_processed} events evaluated`;

    if (!errEl) return;
    const errors = detection.load_errors || [];
    errEl.innerHTML = errors.length === 0 ? '' :
        `<strong>⚠ ${errors.length} rule(s) failed to load:</strong>` +
        errors.map(e => `<div>${escapeHtml(e.file)}${e.rule ? ':' + escapeHtml(e.rule) : ''} — ${escapeHtml(e.error)}</div>`).join('');
}

// ---------------------------------------------------------------------------
// Rendering: activity log table
// ---------------------------------------------------------------------------

function initLogTabs() {
    document.querySelectorAll('#log-tabs button').forEach(btn => {
        btn.addEventListener('click', () => {
            currentLogStatus = btn.dataset.status;
            document.querySelectorAll('#log-tabs button').forEach(b => b.classList.toggle('active', b === btn));
            fetchAlerts();
        });
    });
}

function statusBadge(status) {
    const label = { open: 'Open', acknowledged: 'Handled', dismissed: 'Dismissed' }[status] || status;
    return `<span class="status-badge ${status}">${label}</span>`;
}

function rowActions(alert) {
    if (alert.status === 'open') {
        return `<div class="row-actions">
            <button type="button" onclick="acknowledgeAlert(${alert.id})">Handle</button>
            <button type="button" onclick="dismissAlert(${alert.id})">Dismiss</button>
        </div>`;
    }
    return `<div class="row-actions"><button type="button" onclick="reopenAlert(${alert.id})">Reopen</button></div>`;
}

function updateTable(alerts) {
    const tbody = document.getElementById('alerts-table-body');
    tbody.innerHTML = '';

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-note">Nothing here.</td></tr>`;
        return;
    }

    alerts.forEach(a => {
        const tr = document.createElement('tr');
        const origin = a.geo_country ? `${a.geo_city}, ${a.geo_country}` : (a.source_ip || 'This device');
        const technique = a.technique ? `<span class="technique-badge">${a.technique}</span>` : '';
        const ruleTag = a.rule_id ? `<div class="rule-tag">${a.rule_id}</div>` : '';
        const countBadge = a.occurrence_count > 1
            ? `<span class="count-badge repeat">×${a.occurrence_count}</span>` : '';

        tr.innerHTML = `
            <td class="mono" style="color: var(--text-muted); white-space: nowrap;" title="${a.last_seen || a.timestamp}">${relativeTime(a.last_seen || a.timestamp)}</td>
            <td class="advanced-only"><strong>${moduleLabel(a.module)}</strong>${ruleTag}</td>
            <td><span class="severity-chip ${a.severity}">${SEVERITY_ICON[a.severity] || ''} ${a.severity}</span></td>
            <td>${escapeHtml(a.description)} ${countBadge}</td>
            <td class="advanced-only">${technique}</td>
            <td>${statusBadge(a.status || 'open')}</td>
            <td style="font-size: 0.85em">${origin}<div class="advanced-only" style="color:var(--text-muted); font-size:0.85em">${a.geo_isp || ''}</div></td>
            <td>${rowActions(a)}</td>
        `;
        tbody.appendChild(tr);
    });
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

async function refreshAll() {
    await fetchStats();
    await Promise.all([fetchNeedsAttention(), fetchAlerts(), fetchGeoMap(), fetchHealth(),
                       fetchAgents()]);
}

function initDashboard() {
    initThemeToggle();
    initModeToggle();
    initLogTabs();
    initAgentEnrollment();
    refreshAll();
    setInterval(refreshAll, FETCH_INTERVAL);
}

document.addEventListener('DOMContentLoaded', initDashboard);
