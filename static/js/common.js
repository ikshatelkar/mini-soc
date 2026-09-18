// Shared helpers for both dashboard.js (main page) and all-alerts.js (the
// All Alerts page) - loaded as a plain <script> before either, so everything
// here is just global functions/consts like the rest of this project's JS.

// The session's CSRF token, rendered into a <meta> tag by the page template
// (core/auth.py mints it) - read once and attached to every mutating
// request so app.py's before_request check accepts it. GET requests never
// need it.
function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
}

function apiFetch(path, options = {}) {
    const opts = { ...options, headers: { ...(options.headers || {}) } };
    if (opts.method && opts.method !== 'GET') {
        opts.headers['X-CSRFToken'] = csrfToken();
    }
    return fetch(path, opts);
}

// A session can expire (or be revoked) while a tab is sitting open. Every
// poll hits a login-gated API, so checking once here and sending the tab
// back to /login is simpler than teaching every render function what an
// empty/401 response means.
function redirectIfUnauthorized(response) {
    if (response.status === 401) {
        // A background poll, not a click, is what's likely to notice a
        // session superseded by a login elsewhere - carry that reason to
        // /login so it's explained there rather than looking like a silent
        // logout. Best-effort: if the body isn't readable, redirect anyway.
        response.json().then(body => {
            window.location.href = body && body.reason === 'session_superseded'
                ? '/login?reason=elsewhere' : '/login';
        }).catch(() => { window.location.href = '/login'; });
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Theme + detail-level toggles (persisted, so a choice survives a refresh)
// ---------------------------------------------------------------------------

function initThemeToggle(onChange) {
    const saved = localStorage.getItem('soc-theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);

    document.getElementById('theme-toggle').addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme')
            || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('soc-theme', next);
        // Chart colors are read from CSS custom properties at render time, so
        // a page with charts needs a manual re-render on theme flip rather
        // than waiting for the next poll.
        if (onChange) onChange();
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

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str ?? '';
    return div.innerHTML;
}

// ---------------------------------------------------------------------------
// Alert lifecycle actions - shared by the dashboard's Activity Log and the
// All Alerts page. Each page registers what should happen after a
// successful action via setAlertsChangedHandler(), since the two pages fetch
// different things (the dashboard also refreshes its hero/KPIs; All Alerts
// just re-runs its current filtered query).
// ---------------------------------------------------------------------------

let _onAlertsChanged = () => {};
function setAlertsChangedHandler(fn) { _onAlertsChanged = fn; }

async function postAction(path) {
    try {
        const response = await apiFetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
        if (redirectIfUnauthorized(response)) return;
        await _onAlertsChanged();
    } catch (err) {
        console.error('Action failed:', err);
    }
}

function acknowledgeAlert(id) { postAction(`/api/alerts/${id}/acknowledge`); }
function dismissAlert(id) { postAction(`/api/alerts/${id}/dismiss`); }
function reopenAlert(id) { postAction(`/api/alerts/${id}/reopen`); }

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

// Renders one alert as a table row matching the shared .soc-table markup -
// used by both the dashboard's Activity Log and the All Alerts page so the
// two never drift out of sync visually.
function alertRowHtml(a) {
    const origin = a.geo_country ? `${a.geo_city}, ${a.geo_country}` : (a.source_ip || 'This device');
    const technique = a.technique ? `<span class="technique-badge">${a.technique}</span>` : '';
    const ruleTag = a.rule_id ? `<div class="rule-tag">${a.rule_id}</div>` : '';
    const countBadge = a.occurrence_count > 1
        ? `<span class="count-badge repeat">×${a.occurrence_count}</span>` : '';

    return `
        <td class="mono" style="color: var(--text-muted); white-space: nowrap;" title="${a.last_seen || a.timestamp}">${relativeTime(a.last_seen || a.timestamp)}</td>
        <td class="advanced-only"><strong>${moduleLabel(a.module)}</strong>${ruleTag}</td>
        <td><span class="severity-chip ${a.severity}">${SEVERITY_ICON[a.severity] || ''} ${a.severity}</span></td>
        <td>${escapeHtml(a.description)} ${countBadge}</td>
        <td class="advanced-only">${technique}</td>
        <td>${statusBadge(a.status || 'open')}</td>
        <td style="font-size: 0.85em">${origin}<div class="advanced-only" style="color:var(--text-muted); font-size:0.85em">${a.geo_isp || ''}</div></td>
        <td>${rowActions(a)}</td>
    `;
}

function renderAlertTable(tbody, alerts, emptyMessage) {
    tbody.innerHTML = '';
    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-note">${emptyMessage || 'Nothing here.'}</td></tr>`;
        return;
    }
    alerts.forEach(a => {
        const tr = document.createElement('tr');
        tr.innerHTML = alertRowHtml(a);
        tbody.appendChild(tr);
    });
}

// ---------------------------------------------------------------------------
// World map - shared by the dashboard's compact card and the standalone Map
// page (static/js/map-page.js). Requires Plotly to already be loaded.
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

function renderWorldMap(geoData) {
    const statusEl = document.getElementById('map-status');
    if (!geoData || geoData.length === 0) {
        if (statusEl) statusEl.textContent = 'No external activity mapped yet.';
        Plotly.react('attack-world-map', [], { ...chartLayoutDefaults() },
            { displayModeBar: false, responsive: true });
        return;
    }
    if (statusEl) statusEl.textContent = `${geoData.length} location${geoData.length === 1 ? '' : 's'}`;

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
// Nav dropdown - the "☰ Menu" button in the header, shared by every page.
// ---------------------------------------------------------------------------

function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const collapseBtn = document.getElementById('sidebar-collapse-btn');
    const tooltip = document.getElementById('sidebar-tooltip');
    if (!sidebar || !collapseBtn) return;

    const stored = localStorage.getItem('soc-sidebar-collapsed');
    // No saved choice yet: default to collapsed on a narrow screen, where a
    // 256px sidebar would eat most of the viewport, expanded otherwise.
    const collapsed = stored !== null ? stored === 'true' : window.innerWidth < 640;
    sidebar.classList.toggle('collapsed', collapsed);
    collapseBtn.setAttribute('aria-expanded', String(!collapsed));

    collapseBtn.addEventListener('click', () => {
        const nowCollapsed = sidebar.classList.toggle('collapsed');
        collapseBtn.setAttribute('aria-expanded', String(!nowCollapsed));
        localStorage.setItem('soc-sidebar-collapsed', String(nowCollapsed));
        if (tooltip) tooltip.style.display = 'none';
    });

    if (!tooltip) return;
    sidebar.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('mouseenter', () => {
            if (!sidebar.classList.contains('collapsed')) return;
            const label = item.querySelector('.nav-label');
            if (!label) return;
            tooltip.textContent = label.textContent;
            const rect = item.getBoundingClientRect();
            tooltip.style.left = `${rect.right + 8}px`;
            tooltip.style.top = `${rect.top + rect.height / 2 - 12}px`;
            tooltip.style.display = 'block';
        });
        item.addEventListener('mouseleave', () => { tooltip.style.display = 'none'; });
    });
}

// ---------------------------------------------------------------------------
// Sidebar badge counts (All alerts / Active / Handled / Dismissed) - shared
// across every page since the sidebar itself is shared. The dashboard
// already polls /api/stats for its own charts/KPIs and feeds that response
// in directly (see dashboard.js); every other page has nothing else pulling
// /api/stats, so it starts its own lightweight poll here instead.
// ---------------------------------------------------------------------------

function updateSidebarBadges(stats) {
    const lifecycle = (stats && stats.lifecycle) || {};
    setBadgeText('badge-all', lifecycle.total);
    setBadgeText('badge-active', lifecycle.open_total);
    setBadgeText('badge-handled', lifecycle.acknowledged_total);
    setBadgeText('badge-dismissed', lifecycle.dismissed_total);
}

function setBadgeText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = (value ?? 0).toString();
}

let _sidebarBadgePollStarted = false;
function startSidebarBadgePolling(intervalMs) {
    if (_sidebarBadgePollStarted) return;
    _sidebarBadgePollStarted = true;

    async function poll() {
        try {
            const response = await fetch('/api/stats');
            if (redirectIfUnauthorized(response)) return;
            updateSidebarBadges(await response.json());
        } catch (err) {
            console.error('Error fetching sidebar badge counts:', err);
        }
    }
    poll();
    setInterval(poll, intervalMs || 8000);
}
