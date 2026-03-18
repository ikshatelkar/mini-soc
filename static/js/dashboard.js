const FETCH_INTERVAL = 3000; // Fetch new data every 3 seconds

// Centralized Plotly theme for our dark mode SOC UI
const chartLayoutDefaults = {
    font: { family: 'Roboto Mono', color: '#94a3b8' },
    paper_bgcolor: 'rgba(0,0,0,0)',
    plot_bgcolor: 'rgba(0,0,0,0)',
    margin: { t: 50, b: 40, l: 40, r: 40 },
    titlefont: { size: 16, color: '#e2e8f0' }
};

// Colors mapping for severities and modules
const colorMap = {
    'CRITICAL': '#ef4444',
    'HIGH': '#f97316',
    'MEDIUM': '#eab308',
    'LOW': '#3b82f6',
    'INFO': '#14b8a6',
    'LOG_MONITOR': '#3b82f6',
    'FIM': '#14b8a6',
    'NETWORK': '#a855f7'
};

async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        renderCharts(data);
    } catch (err) {
        console.error("Error fetching stats:", err);
    }
}

async function fetchAlerts() {
    try {
        const response = await fetch('/api/alerts');
        const alerts = await response.json();
        updateTable(alerts);
        updateTopStats(alerts);
    } catch (err) {
        console.error("Error fetching alerts:", err);
    }
}

function updateTopStats(alerts) {
    // Animate counter logic could be added here, but direct assignment works for now
    document.getElementById('total-alerts-count').innerText = alerts.length;
    
    const criticalCount = alerts.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH').length;
    document.getElementById('critical-alerts-count').innerText = criticalCount;
    
    const fimCount = alerts.filter(a => a.module === 'FIM').length;
    document.getElementById('fim-alerts-count').innerText = fimCount;
}

function renderCharts(stats) {
    // --- 1. Pie Chart: Event Breakdown by Module ---
    const modules = stats.modules || {};
    const moduleLabels = Object.keys(modules);
    const moduleValues = Object.values(modules);
    
    const pieData = [{
        values: moduleValues,
        labels: moduleLabels,
        type: 'pie',
        hole: 0.5,
        marker: { 
            colors: moduleLabels.map(m => colorMap[m] || '#64748b'),
            line: { color: '#111827', width: 2 }
        },
        textinfo: 'label+percent',
        hoverinfo: 'label+value'
    }];
    const pieLayout = { ...chartLayoutDefaults, title: 'Alerts by Sensor Module' };
    Plotly.react('alerts-by-type-pie', pieData, pieLayout, {displayModeBar: false, responsive: true});

    // --- 2. Bar Chart: Anomalies by Severity ---
    const severities = stats.severities || {};
    const sevLabels = Object.keys(severities);
    const sevValues = Object.values(severities);

    // Order severities logically
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    sevLabels.sort((a, b) => order.indexOf(a) - order.indexOf(b));
    const sortedValues = sevLabels.map(s => severities[s]);

    const barData = [{
        x: sevLabels,
        y: sortedValues,
        type: 'bar',
        marker: {
            color: sevLabels.map(s => colorMap[s] || '#64748b'),
            line: { color: 'rgba(255,255,255,0.1)', width: 1 }
        }
    }];
    const barLayout = { 
        ...chartLayoutDefaults, 
        title: 'Alert Volume by Severity',
        xaxis: { gridcolor: 'rgba(255,255,255,0.05)' },
        yaxis: { gridcolor: 'rgba(255,255,255,0.05)' }
    };
    Plotly.react('alerts-by-severity-bar', barData, barLayout, {displayModeBar: false, responsive: true});
}

function updateTable(alerts) {
    const tbody = document.getElementById('alerts-table-body');
    tbody.innerHTML = ''; 

    if (alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color: #94a3b8">No anomalies detected yet. Listening...</td></tr>`;
        return;
    }

    alerts.forEach(alert => {
        const tr = document.createElement('tr');
        
        tr.innerHTML = `
            <td style="color: #94a3b8">${alert.timestamp}</td>
            <td><strong>${alert.module}</strong></td>
            <td><span class="sev-badge sev-${alert.severity}">${alert.severity}</span></td>
            <td><span style="opacity: 0.9">${alert.description}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

function initDashboard() {
    // Initial fetch
    fetchStats();
    fetchAlerts();
    
    // Setup polling
    setInterval(() => {
        fetchStats();
        fetchAlerts();
    }, FETCH_INTERVAL);
}

document.addEventListener('DOMContentLoaded', initDashboard);
