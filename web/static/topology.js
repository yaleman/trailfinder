// Global state
let topologyData = null;

// Initialize the application
document.addEventListener('DOMContentLoaded', function () {
    initializeEventListeners();
    loadTopology();
});

// Event Listeners
function initializeEventListeners() {
    // Refresh button
    document.getElementById('refresh-topology').addEventListener('click', loadTopology);

    // Show networks toggle
    document.getElementById('show-networks').addEventListener('change', (e) => {
        if (topologyData) {
            renderTopology(topologyData);
        }
    });

    // Device type filter checkboxes
    const deviceTypeCheckboxes = [
        'filter-router',
        'filter-switch',
        'filter-firewall',
        'filter-accesspoint',
        'filter-unknown',
        'filter-internet'
    ];

    deviceTypeCheckboxes.forEach(id => {
        const checkbox = document.getElementById(id);
        if (checkbox) {
            checkbox.addEventListener('change', () => {
                if (topologyData) {
                    renderTopology(topologyData);
                }
            });
        }
    });

    // Initialize modal event listeners from common.js
    initializeModalEventListeners();
}

// Utility Functions
function getVisibleDeviceTypes() {
    const deviceTypes = [];
    const checkboxMap = {
        'filter-router': 'Router',
        'filter-switch': 'Switch',
        'filter-firewall': 'Firewall',
        'filter-accesspoint': 'AccessPoint',
        'filter-unknown': 'Unknown'
    };

    for (const [checkboxId, deviceType] of Object.entries(checkboxMap)) {
        const checkbox = document.getElementById(checkboxId);
        if (checkbox && checkbox.checked) {
            deviceTypes.push(deviceType);
        }
    }

    return deviceTypes;
}

function shouldShowInternetNode() {
    const checkbox = document.getElementById('filter-internet');
    return checkbox ? checkbox.checked : true;
}

// Network Topology
let topologyControls = null;

async function loadTopology() {
    const showNetworks = document.getElementById('show-networks')?.checked || false;
    const visibleDeviceTypes = getVisibleDeviceTypes();
    const showInternet = shouldShowInternetNode();

    const result = await loadAndRenderTopology('topology-container', {
        showNetworks,
        visibleDeviceTypes,
        showInternet,
        onNodeClick: showDeviceDetails
    });

    if (result) {
        topologyData = result.topologyData;
        topologyControls = result.controls;

        // Setup reset zoom button
        const resetZoomBtn = document.getElementById('reset-zoom');
        if (resetZoomBtn && topologyControls) {
            resetZoomBtn.onclick = topologyControls.resetZoom;
        }
    }
}

function renderTopology(topology) {
    // Re-render with current settings
    const showNetworks = document.getElementById('show-networks')?.checked || false;
    const visibleDeviceTypes = getVisibleDeviceTypes();
    const showInternet = shouldShowInternetNode();

    const result = renderNetworkTopology(topology, 'topology-container', {
        showNetworks,
        visibleDeviceTypes,
        showInternet,
        onNodeClick: showDeviceDetails
    });

    if (result) {
        topologyControls = result;

        // Setup reset zoom button
        const resetZoomBtn = document.getElementById('reset-zoom');
        if (resetZoomBtn && topologyControls) {
            resetZoomBtn.onclick = topologyControls.resetZoom;
        }
    }
}

// Device details modal and all utility functions are now in common.js