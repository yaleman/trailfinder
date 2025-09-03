// Global state
let devicesData = [];

// Initialize the application
document.addEventListener('DOMContentLoaded', function () {
    initializeEventListeners();
    loadPathfinderDevices();
});

// Event Listeners
function initializeEventListeners() {
    // Find path button
    document.getElementById('find-path').addEventListener('click', findPath);

    // Source device change
    document.getElementById('source-device').addEventListener('change', updateSourceInterfaces);
}

// API Functions are now in common.js

// Path Finder Functions
async function loadPathfinderDevices() {
    devicesData = await apiCall('/devices');
    if (devicesData) {
        const sourceSelect = document.getElementById('source-device');
        sourceSelect.textContent = '';
        
        // Add default option
        const defaultOption = document.createElement('option');
        defaultOption.value = '';
        defaultOption.textContent = 'Select device...';
        sourceSelect.appendChild(defaultOption);
        
        // Add device options
        devicesData.forEach(device => {
            const option = document.createElement('option');
            option.value = device.device_id;
            option.textContent = device.hostname;
            sourceSelect.appendChild(option);
        });
    }
}

async function updateSourceInterfaces() {
    const deviceId = document.getElementById('source-device').value;
    const interfaceSelect = document.getElementById('source-interface');

    if (!deviceId) {
        interfaceSelect.textContent = '';
        const defaultOption = document.createElement('option');
        defaultOption.value = '';
        defaultOption.textContent = 'Select interface...';
        interfaceSelect.appendChild(defaultOption);
        return;
    }

    const deviceDetail = await apiCall(`/devices/${deviceId}`);
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
            option.textContent = `${iface.name} (${getInterfaceTypeDisplay(iface.interface_type)})`;
            interfaceSelect.appendChild(option);
        });
    }
}

async function findPath() {
    const sourceDeviceId = document.getElementById('source-device').value;
    const sourceInterface = document.getElementById('source-interface').value;
    const sourceIp = document.getElementById('source-ip').value;
    const destinationIp = document.getElementById('destination-ip').value;

    if (!destinationIp) {
        showError('Please specify a destination IP or network');
        return;
    }

    const request = {
        source: {
            device_id: sourceDeviceId || null,
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

// Utility functions are now in common.js