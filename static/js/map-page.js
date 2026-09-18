// The standalone Map page: a bigger version of the dashboard's compact world
// map card. renderWorldMap/chartLayoutDefaults live in common.js, shared
// with the dashboard.

async function fetchGeoMap() {
    try {
        const response = await fetch('/api/geomap');
        if (redirectIfUnauthorized(response)) return;
        renderWorldMap(await response.json());
    } catch (err) {
        console.error('Error fetching geo map:', err);
    }
}

const MAP_FETCH_INTERVAL = 5000;

document.addEventListener('DOMContentLoaded', () => {
    initSidebar();
    initThemeToggle(fetchGeoMap);
    initModeToggle();
    fetchGeoMap();
    setInterval(fetchGeoMap, MAP_FETCH_INTERVAL);
    startSidebarBadgePolling();
});
