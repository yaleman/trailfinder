// Global state
let devicesData = [];
let topologyData = null;
let selectedDevice = null;

// Initialize the application
document.addEventListener('DOMContentLoaded', function () {
    initializeTabs();
    initializeEventListeners();
    loadDevices();
});

// Tab Management
function initializeTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.id.replace('-tab', '-view');

            // Remove active class from all tabs and contents
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));

            // Add active class to clicked tab and corresponding content
            button.classList.add('active');
            document.getElementById(tabId).classList.add('active');

            // Load data for specific tabs
            if (tabId === 'topology-view' && !topologyData) {
                loadTopology();
            } else if (tabId === 'pathfinder-view') {
                loadPathfinderDevices();
            }
        });
    });
}

// Event Listeners
function initializeEventListeners() {
    // Refresh buttons
    document.getElementById('refresh-devices').addEventListener('click', loadDevices);
    document.getElementById('refresh-topology').addEventListener('click', loadTopology);

    // Device filter
    document.getElementById('device-filter').addEventListener('input', filterDevices);

    // Initialize modal event listeners from common.js
    initializeModalEventListeners();

    // Path finder
    document.getElementById('find-path').addEventListener('click', findPath);
    document.getElementById('source-device').addEventListener('change', updateSourceInterfaces);
}

// API Functions are now in common.js

// Device Management
async function loadDevices() {
    createLoadingDiv('Loading devices...', 'devices-list');

    devicesData = await apiCall('/devices');
    if (devicesData) {
        renderDevices(devicesData);
    }
}

function renderDevices(devices) {
    const devicesList = document.getElementById('devices-list');

    // Clear existing content
    devicesList.textContent = '';

    if (!devices || devices.length === 0) {
        const noDataDiv = document.createElement('div');
        noDataDiv.className = 'no-data';
        noDataDiv.textContent = 'No devices found';
        devicesList.appendChild(noDataDiv);
        return;
    }

    devices.forEach(device => {
        const deviceCard = document.createElement('div');
        deviceCard.className = 'device-card';
        deviceCard.onclick = () => showDeviceDetails(device.device_id);
        
        const hostname = document.createElement('h3');
        hostname.textContent = device.hostname;
        deviceCard.appendChild(hostname);
        
        if (device.name) {
            const deviceName = document.createElement('p');
            deviceName.className = 'device-name';
            deviceName.textContent = device.name;
            deviceCard.appendChild(deviceName);
        }
        
        const deviceType = document.createElement('div');
        deviceType.className = `device-type ${(device.device_type || 'unknown').toLowerCase()}`;
        deviceType.textContent = device.device_type || 'Unknown';
        deviceCard.appendChild(deviceType);
        
        const statsContainer = document.createElement('div');
        statsContainer.className = 'device-stats';
        const statsList = document.createElement('ul');
        statsList.className = 'device-stats';
        
        const interfacesStat = document.createElement('li');
        interfacesStat.textContent = `📡 ${device.interface_count} interfaces`;
        statsList.appendChild(interfacesStat);
        
        const routesStat = document.createElement('li');
        routesStat.textContent = `🛣️ ${device.route_count} routes`;
        statsList.appendChild(routesStat);
        
        statsContainer.appendChild(statsList);
        deviceCard.appendChild(statsContainer);
        
        if (device.brand) {
            const deviceBrand = document.createElement('div');
            deviceBrand.className = 'device-brand';
            deviceBrand.textContent = device.brand;
            deviceCard.appendChild(deviceBrand);
        }
        
        if (device.last_seen) {
            const lastSeen = document.createElement('div');
            lastSeen.className = 'device-last-seen';
            lastSeen.textContent = `Last seen: ${formatDate(device.last_seen)}`;
            deviceCard.appendChild(lastSeen);
        }
        
        devicesList.appendChild(deviceCard);
    });
}

function filterDevices() {
    const filterValue = document.getElementById('device-filter').value.toLowerCase();
    const filteredDevices = devicesData.filter(device =>
        device.hostname.toLowerCase().includes(filterValue) ||
        (device.name && device.name.toLowerCase().includes(filterValue)) ||
        (device.brand && device.brand.toLowerCase().includes(filterValue))
    );

    renderDevices(filteredDevices);
}

// Device Details Modal is now handled by common.js showDeviceDetails function

// Network Topology
let topologyControls = null;

async function loadTopology() {
    const result = await loadAndRenderTopology('topology-container', {
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

// Path Finder
async function loadPathfinderDevices() {
    if (!devicesData.length) {
        await loadDevices();
    }

    const sourceSelect = document.getElementById('source-device');
    // Clear existing options
    sourceSelect.textContent = '';
    
    // Add default option
    const defaultOption = document.createElement('option');
    defaultOption.value = '';
    defaultOption.textContent = 'Select device...';
    sourceSelect.appendChild(defaultOption);
    
    // Add device options
    devicesData.forEach(device => {
        const option = document.createElement('option');
        option.value = device.hostname;
        option.textContent = device.hostname;
        sourceSelect.appendChild(option);
    });
}

async function updateSourceInterfaces() {
    const deviceHostname = document.getElementById('source-device').value;
    const interfaceSelect = document.getElementById('source-interface');

    if (!deviceHostname) {
        interfaceSelect.textContent = '';
        const defaultOption = document.createElement('option');
        defaultOption.value = '';
        defaultOption.textContent = 'Select interface...';
        interfaceSelect.appendChild(defaultOption);
        return;
    }

    const deviceDetail = await apiCall(`/devices/${deviceHostname}`);
    if (deviceDetail) {
        interfaceSelect.textContent = '';
        
        // Add default option
        const defaultOption = document.createElement('option');
        defaultOption.value = '';
        defaultOption.textContent = 'Select interface...';
        interfaceSelect.appendChild(defaultOption);
        
        // Add interface options
        deviceDetail.interfaces.forEach(iface => {
            const option = document.createElement('option');
            option.value = iface.name;
            option.textContent = `${iface.name} (${iface.interface_type})`;
            interfaceSelect.appendChild(option);
        });
    }
}

async function findPath() {
    const sourceDevice = document.getElementById('source-device').value;
    const sourceInterface = document.getElementById('source-interface').value;
    const sourceIp = document.getElementById('source-ip').value;
    const destinationIp = document.getElementById('destination-ip').value;

    if (!destinationIp) {
        showError('Please specify a destination IP or network');
        return;
    }

    const request = {
        source: {
            device: sourceDevice || null,
            interface: sourceInterface || null,
            ip: sourceIp || null
        },
        destination: {
            ip: destinationIp
        }
    };

    createLoadingDiv('Finding path...', 'path-results');

    const pathResult = await apiCall('/pathfind', {
        method: 'POST',
        body: JSON.stringify(request)
    });

    if (pathResult) {
        renderPathResult(pathResult);
    }
}

function renderPathResult(result) {
    const container = document.getElementById('path-results');
    container.textContent = '';

    if (!result.success) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error';
        
        const errorTitle = document.createElement('h3');
        errorTitle.textContent = 'Path Finding Failed';
        errorDiv.appendChild(errorTitle);
        
        const errorMessage = document.createElement('p');
        errorMessage.textContent = result.error;
        errorDiv.appendChild(errorMessage);
        
        container.appendChild(errorDiv);
        return;
    }

    const title = document.createElement('h3');
    title.textContent = `Path Found (${result.total_hops} hops)`;
    container.appendChild(title);
    
    const pathVisualization = document.createElement('div');
    pathVisualization.className = 'path-visualization';
    
    result.path.forEach((hop, index) => {
        const pathHop = document.createElement('div');
        pathHop.className = 'path-hop';
        
        const hopNumber = document.createElement('div');
        hopNumber.className = 'hop-number';
        hopNumber.textContent = index + 1;
        pathHop.appendChild(hopNumber);
        
        const hopDetails = document.createElement('div');
        hopDetails.className = 'hop-details';
        
        const deviceInfo = document.createElement('strong');
        deviceInfo.textContent = hop.device;
        hopDetails.appendChild(deviceInfo);
        
        const viaText = document.createTextNode(` via ${hop.interface}`);
        hopDetails.appendChild(viaText);
        
        if (hop.gateway) {
            const gatewayText = document.createTextNode(` → ${hop.gateway}`);
            hopDetails.appendChild(gatewayText);
        }
        
        const hopNetwork = document.createElement('div');
        hopNetwork.className = 'hop-network';
        hopNetwork.textContent = hop.network;
        hopDetails.appendChild(hopNetwork);
        
        pathHop.appendChild(hopDetails);
        pathVisualization.appendChild(pathHop);
    });
    
    container.appendChild(pathVisualization);
}
