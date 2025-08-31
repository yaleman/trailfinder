// Global state
let devicesData = [];

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
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

// API Functions
async function apiCall(endpoint, options = {}) {
    try {
        const response = await fetch(`/api${endpoint}`, {
            headers: {
                'Content-Type': 'application/json',
            },
            ...options
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error(`API call failed for ${endpoint}:`, error);
        showError(`Failed to load data from ${endpoint}`);
        return null;
    }
}

// Path Finder Functions
async function loadPathfinderDevices() {
    devicesData = await apiCall('/devices');
    if (devicesData) {
        const sourceSelect = document.getElementById('source-device');
        sourceSelect.innerHTML = '<option value="">Select device...</option>' +
            devicesData.map(device => 
                `<option value="${device.device_id}">${device.hostname}</option>`
            ).join('');
    }
}

async function updateSourceInterfaces() {
    const deviceId = document.getElementById('source-device').value;
    const interfaceSelect = document.getElementById('source-interface');
    
    if (!deviceId) {
        interfaceSelect.innerHTML = '<option value="">Select interface...</option>';
        return;
    }
    
    const deviceDetail = await apiCall(`/devices/${deviceId}`);
    if (deviceDetail) {
        interfaceSelect.innerHTML = '<option value="">Select interface...</option>' +
            deviceDetail.interfaces.map(iface => 
                `<option value="${iface.name}">${iface.name} (${getInterfaceTypeDisplay(iface.interface_type)})</option>`
            ).join('');
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
    
    const results = document.getElementById('path-results');
    results.innerHTML = '<div class="loading">Finding path...</div>';
    
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
    
    if (!result.success) {
        container.innerHTML = `
            <div class="error">
                <h3>Path Finding Failed</h3>
                <p>${result.error}</p>
            </div>
        `;
        return;
    }
    
    const pathHTML = result.path.map((hop, index) => `
        <div class="path-hop">
            <div class="hop-number">${index + 1}</div>
            <div class="hop-details">
                <strong>${hop.device}</strong> via ${hop.interface}
                ${hop.gateway ? `→ ${hop.gateway}` : ''}
                <div class="hop-network">${hop.network}</div>
            </div>
        </div>
    `).join('');
    
    container.innerHTML = `
        <h3>Path Found (${result.total_hops} hops)</h3>
        <div class="path-visualization">
            ${pathHTML}
        </div>
    `;
}

// Utility Functions
function getInterfaceTypeDisplay(interfaceType) {
    if (typeof interfaceType === 'object') {
        // Handle {"Other": "wg"} format
        const type = Object.keys(interfaceType)[0];
        const value = interfaceType[type];
        return type === 'Other' ? value : type;
    }
    return interfaceType;
}

function showError(message) {
    // Create a simple error notification
    const error = document.createElement('div');
    error.style.position = 'fixed';
    error.style.top = '20px';
    error.style.right = '20px';
    error.style.background = '#e74c3c';
    error.style.color = 'white';
    error.style.padding = '1rem';
    error.style.borderRadius = '8px';
    error.style.zIndex = '9999';
    error.textContent = message;
    
    document.body.appendChild(error);
    
    setTimeout(() => {
        document.body.removeChild(error);
    }, 5000);
}