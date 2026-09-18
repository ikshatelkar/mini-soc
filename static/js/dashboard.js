const FETCH_INTERVAL = 3000;

// csrfToken/apiFetch, theme+mode toggles, cssVar, MODULE_INFO/moduleLabel/
// moduleColor, severityColor/SEVERITY_ICON, relativeTime, escapeHtml,
// redirectIfUnauthorized, and the alert-lifecycle action helpers
// (acknowledge/dismiss/reopen, statusBadge, rowActions, renderAlertTable)
// all live in common.js, shared with the All Alerts page.

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

let lastStats = { modules: {}, severities: {}, total_events: 0, mapped_origins: 0,
                  lifecycle: { needs_attention: 0, open_total: 0, handled_total: 0 } };
let currentLogStatus = 'open';

async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        if (redirectIfUnauthorized(response)) return;
        lastStats = await response.json();
        renderCharts(lastStats);
        renderKPIs(lastStats);
        updateSidebarBadges(lastStats);
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

// Alert lifecycle actions (acknowledge/dismiss/reopen) live in common.js;
// after any of them succeeds there, refresh everything this page shows that
// could have changed.
setAlertsChangedHandler(() => Promise.all([fetchNeedsAttention(), fetchAlerts(), fetchStats()]));

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
//
// chartLayoutDefaults/renderWorldMap live in common.js - shared with the
// standalone Map page.

function renderCharts(stats) {
    const modules = stats.modules || {};
    // Ascending, so the largest ends up at the top of the horizontal bar -
    // Plotly draws categories bottom-to-top by default, so this reads like a
    // normal ranked leaderboard instead of upside down.
    const moduleKeys = Object.keys(modules).sort((a, b) => modules[a] - modules[b]);

    // A pie/donut breaks down completely once one source dominates - real
    // deployments are often 95%+ auth log noise, which leaves every other
    // slice an invisible sliver. A bar keeps every source legible regardless
    // of how skewed the split is, the same reason the severity chart next to
    // it is already a bar and not a pie.
    const moduleBarData = [{
        x: moduleKeys.map(k => modules[k]),
        y: moduleKeys.map(moduleLabel),
        type: 'bar',
        orientation: 'h',
        marker: {
            color: moduleKeys.map(moduleColor),
            line: { color: cssVar('--border'), width: 1 },
        },
        text: moduleKeys.map(k => modules[k]),
        textposition: 'auto',
        hoverinfo: 'y+x',
    }];
    Plotly.react('alerts-by-type-bar', moduleBarData, {
        ...chartLayoutDefaults(),
        title: 'Activity by Source',
        xaxis: { gridcolor: cssVar('--gridline') },
        yaxis: { automargin: true },
        showlegend: false,
    }, { displayModeBar: false, responsive: true });

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
        const response = await apiFetch(`/api/agents/${id}`, { method: 'DELETE' });
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
            const response = await apiFetch('/api/agents', {
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

function updateTable(alerts) {
    renderAlertTable(document.getElementById('alerts-table-body'), alerts,
        'Nothing in the last 24 hours. Older activity is on the All Alerts page.');
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
    initSidebar();
    initThemeToggle(refreshAll);
    initModeToggle();
    initLogTabs();
    initAgentEnrollment();
    refreshAll();
    setInterval(refreshAll, FETCH_INTERVAL);
}

document.addEventListener('DOMContentLoaded', initDashboard);
