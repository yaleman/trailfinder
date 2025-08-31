// Global state
let devicesData = [];

// Initialize the application
document.addEventListener('DOMContentLoaded', function () {
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
        console.error("API call failed", endpoint, error);
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

    // Clear existing content
    content.textContent = '';

    // Create main container
    const deviceDetailDiv = document.createElement('div');
    deviceDetailDiv.className = 'device-detail';

    // Device header
    const hostname = document.createElement('h2');
    hostname.textContent = device.hostname;
    deviceDetailDiv.appendChild(hostname);

    // Device name (optional)
    if (device.name) {
        const nameP = document.createElement('p');
        const nameStrong = document.createElement('strong');
        nameStrong.textContent = 'Name: ';
        nameP.appendChild(nameStrong);
        nameP.appendChild(document.createTextNode(device.name));
        deviceDetailDiv.appendChild(nameP);
    }

    // Device ID
    const deviceIdP = document.createElement('p');
    const deviceIdStrong = document.createElement('strong');
    deviceIdStrong.textContent = 'Device ID: ';
    deviceIdP.appendChild(deviceIdStrong);
    deviceIdP.appendChild(document.createTextNode(device.device_id));
    deviceDetailDiv.appendChild(deviceIdP);

    // Device Type
    const deviceTypeP = document.createElement('p');
    const deviceTypeStrong = document.createElement('strong');
    deviceTypeStrong.textContent = 'Type: ';
    deviceTypeP.appendChild(deviceTypeStrong);
    deviceTypeP.appendChild(document.createTextNode(device.device_type));
    deviceDetailDiv.appendChild(deviceTypeP);

    // Owner
    const ownerP = document.createElement('p');
    const ownerStrong = document.createElement('strong');
    ownerStrong.textContent = 'Owner: ';
    ownerP.appendChild(ownerStrong);
    const ownerText = typeof device.owner === 'object' ? device.owner.Named || 'Unknown' : device.owner;
    ownerP.appendChild(document.createTextNode(ownerText));
    deviceDetailDiv.appendChild(ownerP);

    // Interfaces section
    const interfacesSection = createInterfacesSection(device.interfaces);
    deviceDetailDiv.appendChild(interfacesSection);

    // Routes section
    const routesSection = createRoutesSection(device.routes);
    deviceDetailDiv.appendChild(routesSection);

    content.appendChild(deviceDetailDiv);
}

function closeModal() {
    document.getElementById('device-modal').style.display = 'none';
}

// Helper functions for DOM creation
function createInterfacesSection(interfaces) {
    const section = document.createElement('div');
    section.className = 'detail-section';

    const heading = document.createElement('h3');
    heading.textContent = `Interfaces (${interfaces.length})`;
    section.appendChild(heading);

    const table = document.createElement('table');
    table.className = 'interfaces-table';

    // Create header
    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    const headers = ['Name', 'Type', 'VLAN', 'IP Addresses', 'Comment'];
    headers.forEach(headerText => {
        const th = document.createElement('th');
        th.textContent = headerText;
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    // Create body
    const tbody = document.createElement('tbody');
    interfaces.forEach(iface => {
        const row = document.createElement('tr');

        // Name
        const nameCell = document.createElement('td');
        nameCell.textContent = iface.name;
        row.appendChild(nameCell);

        // Type
        const typeCell = document.createElement('td');
        const typeSpan = document.createElement('span');
        const interfaceType = getInterfaceTypeDisplay(iface.interface_type);
        const interfaceClass = getInterfaceTypeClass(iface.interface_type);
        typeSpan.className = `interface-type ${interfaceClass}`;
        typeSpan.textContent = interfaceType;
        typeCell.appendChild(typeSpan);
        row.appendChild(typeCell);

        // VLAN
        const vlanCell = document.createElement('td');
        const vlansDisplay = iface.vlans && iface.vlans.length > 0 ? iface.vlans.join(', ') : 'N/A';
        vlanCell.textContent = vlansDisplay;
        row.appendChild(vlanCell);

        // IP Addresses
        const addressesCell = document.createElement('td');
        addressesCell.textContent = iface.addresses.join(', ') || 'None';
        row.appendChild(addressesCell);

        // Comment
        const commentCell = document.createElement('td');
        commentCell.textContent = iface.comment || '';
        row.appendChild(commentCell);

        tbody.appendChild(row);
    });
    table.appendChild(tbody);
    section.appendChild(table);

    return section;
}

function createRoutesSection(routes) {
    const section = document.createElement('div');
    section.className = 'detail-section';

    const heading = document.createElement('h3');
    heading.textContent = `Routes (${routes.length})`;
    section.appendChild(heading);

    const table = document.createElement('table');
    table.className = 'routes-table';

    // Create header
    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    const headers = ['Target', 'Type', 'Gateway', 'Distance'];
    headers.forEach(headerText => {
        const th = document.createElement('th');
        th.textContent = headerText;
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    // Create body
    const tbody = document.createElement('tbody');
    routes.forEach(route => {
        const row = document.createElement('tr');

        // Target
        const targetCell = document.createElement('td');
        targetCell.textContent = route.target;
        row.appendChild(targetCell);

        // Type
        const typeCell = document.createElement('td');
        const typeSpan = document.createElement('span');
        typeSpan.className = `route-type ${getRouteTypeClass(route.route_type)}`;
        typeSpan.textContent = getRouteTypeDisplay(route.route_type);
        typeCell.appendChild(typeSpan);
        row.appendChild(typeCell);

        // Gateway
        const gatewayCell = document.createElement('td');
        gatewayCell.textContent = route.gateway || 'N/A';
        row.appendChild(gatewayCell);

        // Distance
        const distanceCell = document.createElement('td');
        distanceCell.textContent = route.distance || 'N/A';
        row.appendChild(distanceCell);

        tbody.appendChild(row);
    });
    table.appendChild(tbody);
    section.appendChild(table);

    return section;
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