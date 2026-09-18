// The All Alerts page: full history, worst severity first (see
// core/db.py's get_all_alerts), with filters and pagination. Shares
// csrfToken/apiFetch/renderAlertTable/alert-actions with the dashboard via
// common.js.

let currentPage = { limit: 50, offset: 0, total: 0 };

function currentFilters() {
    const filters = {
        severity: document.getElementById('filter-severity').value,
        status: document.getElementById('filter-status').value,
        module: document.getElementById('filter-module').value,
        search: document.getElementById('filter-search').value.trim(),
    };
    const since = document.getElementById('filter-since').value;
    const until = document.getElementById('filter-until').value;
    // Dates come from <input type="date"> as a bare day (YYYY-MM-DD); widen
    // to a full-day range so "until" includes that day's events instead of
    // excluding everything after midnight.
    if (since) filters.since = `${since}T00:00:00`;
    if (until) filters.until = `${until}T23:59:59`;
    return filters;
}

function buildQuery(filters, limit, offset) {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
        if (value) params.set(key, value);
    });
    params.set('limit', limit);
    params.set('offset', offset);
    return params.toString();
}

async function fetchAllAlerts() {
    try {
        const qs = buildQuery(currentFilters(), currentPage.limit, currentPage.offset);
        const response = await fetch(`/api/alerts/all?${qs}`);
        if (redirectIfUnauthorized(response)) return;
        const data = await response.json();
        currentPage.total = data.total;
        renderAlertTable(document.getElementById('all-alerts-table-body'), data.alerts,
            'No alerts match these filters.');
        renderPagination(data);
    } catch (err) {
        console.error('Error fetching all alerts:', err);
    }
}

function renderPagination(data) {
    const summary = document.getElementById('pagination-summary');
    const prev = document.getElementById('pagination-prev');
    const next = document.getElementById('pagination-next');

    if (data.total === 0) {
        summary.textContent = 'No results';
    } else {
        const from = data.offset + 1;
        const to = Math.min(data.offset + data.alerts.length, data.total);
        summary.textContent = `${from}-${to} of ${data.total}`;
    }
    prev.disabled = currentPage.offset === 0;
    next.disabled = currentPage.offset + currentPage.limit >= data.total;
}

function initFilters() {
    ['filter-severity', 'filter-status', 'filter-module', 'filter-since', 'filter-until'].forEach(id => {
        document.getElementById(id).addEventListener('change', () => {
            currentPage.offset = 0;
            fetchAllAlerts();
        });
    });

    // Debounced so free-text search doesn't fire a request on every
    // keystroke.
    let searchTimer = null;
    document.getElementById('filter-search').addEventListener('input', () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => {
            currentPage.offset = 0;
            fetchAllAlerts();
        }, 300);
    });

    document.getElementById('filter-clear').addEventListener('click', () => {
        ['filter-severity', 'filter-status', 'filter-module', 'filter-since', 'filter-until', 'filter-search']
            .forEach(id => { document.getElementById(id).value = ''; });
        currentPage.offset = 0;
        fetchAllAlerts();
    });
}

function initPagination() {
    document.getElementById('pagination-prev').addEventListener('click', () => {
        currentPage.offset = Math.max(0, currentPage.offset - currentPage.limit);
        fetchAllAlerts();
    });
    document.getElementById('pagination-next').addEventListener('click', () => {
        currentPage.offset += currentPage.limit;
        fetchAllAlerts();
    });
}

// The "All Alerts"/"Active"/"Dismissed" nav toggles all land on this same
// page with a different ?status= - seed the filter dropdown from that so the
// results are actually pre-filtered, not just the heading (app.py renders
// the heading server-side from the same query param).
function applyFiltersFromUrl() {
    const params = new URLSearchParams(window.location.search);
    const status = params.get('status');
    if (status) document.getElementById('filter-status').value = status;
}

setAlertsChangedHandler(fetchAllAlerts);

document.addEventListener('DOMContentLoaded', () => {
    initSidebar();
    initThemeToggle();
    initModeToggle();
    applyFiltersFromUrl();
    initFilters();
    initPagination();
    fetchAllAlerts();
    startSidebarBadgePolling();
});
