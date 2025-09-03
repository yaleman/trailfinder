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

    // Initialize modal event listeners from common.js
    initializeModalEventListeners();
}

// Network Topology
let topologyControls = null;

async function loadTopology() {
    const showNetworks = document.getElementById('show-networks')?.checked || false;
    
    const result = await loadAndRenderTopology('topology-container', {
        showNetworks,
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
    
    const result = renderNetworkTopology(topology, 'topology-container', {
        showNetworks,
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