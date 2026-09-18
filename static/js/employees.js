// The Employees page: one row per computer this SOC knows about (see
// core/db.py's get_employees_overview), each nameable and expandable into
// its own alert list.

async function fetchEmployees() {
    try {
        const response = await fetch('/api/employees');
        if (redirectIfUnauthorized(response)) return;
        renderEmployees(await response.json());
    } catch (err) {
        console.error('Error fetching employees:', err);
    }
}

async function saveEmployeeName(host, input) {
    const employee_name = input.value.trim();
    try {
        const response = await apiFetch('/api/employees', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host, employee_name }),
        });
        if (redirectIfUnauthorized(response)) return;
        input.classList.add('saved-flash');
        setTimeout(() => input.classList.remove('saved-flash'), 800);
    } catch (err) {
        console.error('Error saving employee name:', err);
    }
}

function renderEmployees(rows) {
    const tbody = document.getElementById('employees-table-body');
    tbody.innerHTML = '';

    if (!rows || rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-note">No computers seen yet.</td></tr>`;
        return;
    }

    rows.forEach(r => {
        const tr = document.createElement('tr');
        const lastActivity = r.most_recent ? relativeTime(r.most_recent) : 'never';
        const urgentCell = r.urgent_count > 0
            ? `<span class="count-badge repeat">${r.urgent_count}</span>` : '0';
        tr.innerHTML = `
            <td class="mono"><strong>${escapeHtml(r.host)}</strong></td>
            <td>
                <input type="text" class="employee-name-input" placeholder="Assign a name..."
                       value="${escapeHtml(r.employee_name || '')}" data-host="${escapeHtml(r.host)}">
            </td>
            <td>${r.open_count}</td>
            <td class="advanced-only">${urgentCell}</td>
            <td>${r.total}</td>
            <td style="color: var(--text-muted); font-size: 0.85em">${lastActivity}</td>
            <td><div class="row-actions"><button type="button" onclick="showEmployeeAlerts('${escapeHtml(r.host)}')">View Alerts</button></div></td>
        `;
        tbody.appendChild(tr);
    });

    tbody.querySelectorAll('.employee-name-input').forEach(input => {
        input.addEventListener('blur', () => saveEmployeeName(input.dataset.host, input));
        input.addEventListener('keydown', (evt) => {
            if (evt.key === 'Enter') input.blur();
        });
    });
}

async function showEmployeeAlerts(host) {
    const card = document.getElementById('employee-alerts-card');
    const heading = document.getElementById('employee-alerts-heading');
    heading.textContent = `Alerts for ${host}`;
    card.hidden = false;
    card.scrollIntoView({ behavior: 'smooth', block: 'start' });
    try {
        const response = await fetch(`/api/alerts/all?host=${encodeURIComponent(host)}&limit=100`);
        if (redirectIfUnauthorized(response)) return;
        const data = await response.json();
        renderAlertTable(document.getElementById('employee-alerts-table-body'), data.alerts,
            'No alerts for this computer.');
    } catch (err) {
        console.error('Error fetching employee alerts:', err);
    }
}

function initEmployeeAlertsClose() {
    document.getElementById('employee-alerts-close').addEventListener('click', () => {
        document.getElementById('employee-alerts-card').hidden = true;
    });
}

// Re-run whatever alert list is currently open after an acknowledge/dismiss/
// reopen action, same pattern as the dashboard and All Alerts page.
setAlertsChangedHandler(() => {
    fetchEmployees();
    const card = document.getElementById('employee-alerts-card');
    if (!card.hidden) {
        const host = document.getElementById('employee-alerts-heading').textContent.replace('Alerts for ', '');
        showEmployeeAlerts(host);
    }
});

document.addEventListener('DOMContentLoaded', () => {
    initSidebar();
    initThemeToggle();
    initModeToggle();
    initEmployeeAlertsClose();
    fetchEmployees();
    startSidebarBadgePolling();
});
