// Global state
let devicesData = [];

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeEventListeners();
    loadDevices();
});

// Event Listeners
function initializeEventListeners() {
    // Refresh button
    document.getElementById('refresh-devices').addEventListener('click', loadDevices);
    
    // Device filter
    document.getElementById('device-filter').addEventListener('input', filterDevices);
    
    // Modal close
    document.querySelector('.close').addEventListener('click', closeModal);
    window.addEventListener('click', (event) => {
        const modal = document.getElementById('device-modal');
        if (event.target === modal) {
            closeModal();
        }
    });
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

// Device Management
async function loadDevices() {
    const devicesList = document.getElementById('devices-list');
    devicesList.innerHTML = '<div class="loading">Loading devices...</div>';
    
    devicesData = await apiCall('/devices');
    if (devicesData) {
        renderDevices(devicesData);
    }
}

function renderDevices(devices) {
    const devicesList = document.getElementById('devices-list');
    
    if (!devices || devices.length === 0) {
        devicesList.innerHTML = '<div class="no-data">No devices found</div>';
        return;
    }
    
    const devicesHTML = devices.map(device => `
        <div class="device-card" onclick="showDeviceDetails('${device.device_id}')">
            <h3>${device.hostname}</h3>
            ${device.name ? `<p class="device-name">${device.name}</p>` : ''}
            <div class="device-type ${(device.device_type || 'unknown').toLowerCase()}">${device.device_type || 'Unknown'}</div>
            <div class="device-stats">
                <span>📡 ${device.interface_count} interfaces</span>
                <span>🛣️ ${device.route_count} routes</span>
            </div>
            ${device.brand ? `<div class="device-brand">${device.brand}</div>` : ''}
            ${device.last_seen ? `<div class="device-last-seen">Last seen: ${formatDate(device.last_seen)}</div>` : ''}
        </div>
    `).join('');
    
    devicesList.innerHTML = devicesHTML;
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

// Device Details Modal
async function showDeviceDetails(deviceId) {
    const modal = document.getElementById('device-modal');
    const content = document.getElementById('device-detail-content');
    
    content.innerHTML = '<div class="loading">Loading device details...</div>';
    modal.style.display = 'block';
    
    const deviceDetail = await apiCall(`/devices/${deviceId}`);
    if (deviceDetail) {
        renderDeviceDetails(deviceDetail);
    }
}

function renderDeviceDetails(device) {
    const content = document.getElementById('device-detail-content');
    
    const interfacesTable = device.interfaces.map(iface => {
        const interfaceType = getInterfaceTypeDisplay(iface.interface_type);
        const interfaceClass = getInterfaceTypeClass(iface.interface_type);
        return `
            <tr>
                <td>${iface.name}</td>
                <td><span class="interface-type ${interfaceClass}">${interfaceType}</span></td>
                <td>${iface.vlan || 'N/A'}</td>
                <td>${iface.addresses.join(', ') || 'None'}</td>
                <td>${iface.comment || ''}</td>
            </tr>
        `;
    }).join('');
    
    const routesTable = device.routes.map(route => `
        <tr>
            <td>${route.target}</td>
            <td><span class="route-type ${getRouteTypeClass(route.route_type)}">${getRouteTypeDisplay(route.route_type)}</span></td>
            <td>${route.gateway || 'N/A'}</td>
            <td>${route.distance || 'N/A'}</td>
        </tr>
    `).join('');
    
    content.innerHTML = `
        <div class="device-detail">
            <h2>${device.hostname}</h2>
            ${device.name ? `<p><strong>Name:</strong> ${device.name}</p>` : ''}
            <p><strong>Device ID:</strong> ${device.device_id}</p>
            <p><strong>Type:</strong> ${device.device_type}</p>
            <p><strong>Owner:</strong> ${typeof device.owner === 'object' ? device.owner.Named || 'Unknown' : device.owner}</p>
            
            <div class="detail-section">
                <h3>Interfaces (${device.interfaces.length})</h3>
                <table class="interfaces-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>VLAN</th>
                            <th>IP Addresses</th>
                            <th>Comment</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${interfacesTable}
                    </tbody>
                </table>
            </div>
            
            <div class="detail-section">
                <h3>Routes (${device.routes.length})</h3>
                <table class="routes-table">
                    <thead>
                        <tr>
                            <th>Target</th>
                            <th>Type</th>
                            <th>Gateway</th>
                            <th>Distance</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${routesTable}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

function closeModal() {
    document.getElementById('device-modal').style.display = 'none';
}

// Utility Functions
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

function getRouteTypeClass(routeType) {
    if (typeof routeType === 'object') {
        const type = Object.keys(routeType)[0];
        return type.toLowerCase();
    }
    return routeType.toLowerCase();
}

function getRouteTypeDisplay(routeType) {
    if (typeof routeType === 'object') {
        const type = Object.keys(routeType)[0];
        return type;
    }
    return routeType;
}

function getInterfaceTypeDisplay(interfaceType) {
    if (typeof interfaceType === 'object') {
        // Handle {"Other": "wg"} format
        const type = Object.keys(interfaceType)[0];
        const value = interfaceType[type];
        return type === 'Other' ? value : type;
    }
    return interfaceType;
}

function getInterfaceTypeClass(interfaceType) {
    if (typeof interfaceType === 'object') {
        const type = Object.keys(interfaceType)[0];
        return type.toLowerCase();
    }
    return interfaceType.toLowerCase();
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