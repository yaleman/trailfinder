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

    // Initialize modal event listeners from common.js
    initializeModalEventListeners();
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
        
        const statsList = document.createElement('ul');
        statsList.className = 'device-stats';
        
        const interfacesStat = document.createElement('li');
        interfacesStat.textContent = `📡 ${device.interface_count} interfaces`;
        statsList.appendChild(interfacesStat);
        
        const routesStat = document.createElement('li');
        routesStat.textContent = `🛣️ ${device.route_count} routes`;
        statsList.appendChild(routesStat);
        
        deviceCard.appendChild(statsList);
        
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

// All utility functions are now in common.js