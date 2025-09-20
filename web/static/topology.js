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

    // Hide device names toggle
    document.getElementById('hide-device-names').addEventListener('click', (e) => {
        // Toggle active state
        e.target.classList.toggle('active');

        if (topologyData) {
            renderTopology(topologyData);
        }
    });

    // Device type filter buttons
    const deviceTypeButtons = [
        'filter-router',
        'filter-switch',
        'filter-firewall',
        'filter-accesspoint',
        'filter-unknown',
        'filter-internet'
    ];

    deviceTypeButtons.forEach(id => {
        const button = document.getElementById(id);
        if (button) {
            button.addEventListener('click', () => {
                // Toggle active state
                button.classList.toggle('active');

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
    const buttonMap = {
        'filter-router': 'Router',
        'filter-switch': 'Switch',
        'filter-firewall': 'Firewall',
        'filter-accesspoint': 'AccessPoint',
        'filter-unknown': 'Unknown'
    };

    for (const [buttonId, deviceType] of Object.entries(buttonMap)) {
        const button = document.getElementById(buttonId);
        if (button && button.classList.contains('active')) {
            deviceTypes.push(deviceType);
        }
    }

    return deviceTypes;
}

function shouldShowInternetNode() {
    const button = document.getElementById('filter-internet');
    return button ? button.classList.contains('active') : true;
}

function shouldShowDeviceNames() {
    const button = document.getElementById('hide-device-names');
    return button ? !button.classList.contains('active') : true; // Inverted because it's "hide" names
}

// Network Topology
let topologyControls = null;

async function loadTopology() {
    const visibleDeviceTypes = getVisibleDeviceTypes();
    const showInternet = shouldShowInternetNode();
    const showDeviceNames = shouldShowDeviceNames();

    const result = await loadAndRenderTopology('topology-container', {
        visibleDeviceTypes,
        showInternet,
        showDeviceNames,
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
    const visibleDeviceTypes = getVisibleDeviceTypes();
    const showInternet = shouldShowInternetNode();
    const showDeviceNames = shouldShowDeviceNames();

    const result = renderNetworkTopology(topology, 'topology-container', {
        visibleDeviceTypes,
        showInternet,
        showDeviceNames,
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