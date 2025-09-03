/**
 * Shared utilities and common functionality for TrailFinder web interface
 */

// =============================================================================
// API Functions
// =============================================================================

/**
 * Makes an API call with consistent error handling and JSON parsing
 * @param {string} endpoint - API endpoint (without /api prefix)
 * @param {Object} options - Fetch options
 * @returns {Promise<Object|null>} - Response data or null on error
 */
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

// =============================================================================
// UI Utilities
// =============================================================================

/**
 * Creates a loading div with the specified message
 * @param {string} message - Loading message to display
 * @param {string} targetElementId - ID of element to clear and show loading in
 */
function createLoadingDiv(message, targetElementId) {
    const targetElement = document.getElementById(targetElementId);
    if (!targetElement) {
        console.error(`Element with id '${targetElementId}' not found`);
        return;
    }

    // Clear existing content
    targetElement.textContent = '';

    // Create loading div
    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'loading';
    loadingDiv.textContent = message;

    // Append to target element
    targetElement.appendChild(loadingDiv);
}

/**
 * Shows an error notification toast
 * @param {string} message - Error message to display
 */
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
        if (document.body.contains(error)) {
            document.body.removeChild(error);
        }
    }, 5000);
}

/**
 * Formats a date string for display
 * @param {string} dateString - ISO date string
 * @returns {string} Formatted date
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

// =============================================================================
// Data Type Utilities
// =============================================================================

/**
 * Gets the display string for an interface type
 * @param {string|Object} interfaceType - Interface type (string or object)
 * @returns {string} Display string
 */
function getInterfaceTypeDisplay(interfaceType) {
    if (typeof interfaceType === 'object') {
        // Handle {"Other": "wg"} format
        const type = Object.keys(interfaceType)[0];
        const value = interfaceType[type];
        return type === 'Other' ? value : type;
    }
    return interfaceType;
}

/**
 * Gets the CSS class for an interface type
 * @param {string|Object} interfaceType - Interface type
 * @returns {string} CSS class name
 */
function getInterfaceTypeClass(interfaceType) {
    if (typeof interfaceType === 'object') {
        const type = Object.keys(interfaceType)[0];
        return type.toLowerCase();
    }
    return interfaceType.toLowerCase();
}

/**
 * Gets the display string for a route type
 * @param {string|Object} routeType - Route type
 * @returns {string} Display string
 */
function getRouteTypeDisplay(routeType) {
    if (typeof routeType === 'object') {
        const type = Object.keys(routeType)[0];
        return type;
    }
    return routeType;
}

/**
 * Gets the CSS class for a route type
 * @param {string|Object} routeType - Route type
 * @returns {string} CSS class name
 */
function getRouteTypeClass(routeType) {
    if (typeof routeType === 'object') {
        const type = Object.keys(routeType)[0];
        return type.toLowerCase();
    }
    return routeType.toLowerCase();
}

// =============================================================================
// Device and Network Utilities
// =============================================================================

/**
 * Gets color for a device type
 * @param {string} deviceType - Device type
 * @returns {string} Hex color code
 */
function getDeviceColor(deviceType) {
    const colors = {
        'Router': '#ff6b6b',
        'Switch': '#4ecdc4',
        'Firewall': '#45b7d1',
        'AccessPoint': '#96ceb4'
    };
    return colors[deviceType] || '#999';
}

/**
 * Gets color for a connection type
 * @param {string} connectionType - Connection type
 * @returns {string} Hex color code
 */
function getConnectionColor(connectionType) {
    const colors = {
        'DirectLink': '#2ecc71',
        'Gateway': '#e74c3c',
        'SameNetwork': '#f39c12',
        'Internet': '#9b59b6',
        'CDP': '#3498db'
    };
    return colors[connectionType] || '#999';
}

// =============================================================================
// Modal Management
// =============================================================================

/**
 * Closes the device modal
 */
function closeModal() {
    const modal = document.getElementById('device-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

/**
 * Sets up modal event listeners (should be called once during initialization)
 */
function initializeModalEventListeners() {
    // Modal close button
    const closeBtn = document.querySelector('.close');
    if (closeBtn) {
        closeBtn.addEventListener('click', closeModal);
    }

    // Click outside modal to close
    window.addEventListener('click', (event) => {
        const modal = document.getElementById('device-modal');
        if (event.target === modal) {
            closeModal();
        }
    });
}

// =============================================================================
// Device Details Rendering
// =============================================================================

/**
 * Creates a standardized device details section
 * @param {Object} device - Device data
 * @returns {HTMLElement} Device details div
 */
function createDeviceDetailsDiv(device) {
    const deviceDetailDiv = document.createElement('div');
    deviceDetailDiv.className = 'device-detail';

    // Device header
    const header = document.createElement('h2');
    header.textContent = device.hostname;
    deviceDetailDiv.appendChild(header);

    // Device name (optional)
    if (device.name) {
        const nameP = createInfoParagraph('Name', device.name);
        deviceDetailDiv.appendChild(nameP);
    }

    // Device ID
    const deviceIdP = createInfoParagraph('Device ID', device.device_id);
    deviceDetailDiv.appendChild(deviceIdP);

    // Device Type
    const deviceTypeP = createInfoParagraph('Type', device.device_type);
    deviceDetailDiv.appendChild(deviceTypeP);

    // Owner
    const ownerText = typeof device.owner === 'object' ? device.owner.Named || 'Unknown' : device.owner;
    const ownerP = createInfoParagraph('Owner', ownerText);
    deviceDetailDiv.appendChild(ownerP);

    // Interfaces section
    const interfacesSection = createInterfacesTable(device.interfaces);
    deviceDetailDiv.appendChild(interfacesSection);

    // Routes section
    const routesSection = createRoutesTable(device.routes);
    deviceDetailDiv.appendChild(routesSection);

    return deviceDetailDiv;
}

/**
 * Creates a standardized info paragraph with label and value
 * @param {string} label - Label text
 * @param {string} value - Value text
 * @returns {HTMLElement} Paragraph element
 */
function createInfoParagraph(label, value) {
    const p = document.createElement('p');
    const strong = document.createElement('strong');
    strong.textContent = `${label}: `;
    p.appendChild(strong);
    p.appendChild(document.createTextNode(value));
    return p;
}

/**
 * Creates a standardized interfaces table
 * @param {Array} interfaces - Array of interface objects
 * @returns {HTMLElement} Interfaces section div
 */
function createInterfacesTable(interfaces) {
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

        // IP Addresses - handle both formats
        const addressesCell = document.createElement('td');
        let addressesDisplay = 'None';
        if (iface.addresses && iface.addresses.length > 0) {
            // Check if addresses have ip/prefix_length structure or are simple strings
            if (typeof iface.addresses[0] === 'object' && iface.addresses[0].ip) {
                addressesDisplay = iface.addresses.map(addr => `${addr.ip}/${addr.prefix_length}`).join(', ');
            } else {
                addressesDisplay = iface.addresses.join(', ');
            }
        }
        addressesCell.textContent = addressesDisplay;
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

/**
 * Creates a standardized routes table
 * @param {Array} routes - Array of route objects
 * @returns {HTMLElement} Routes section div
 */
function createRoutesTable(routes) {
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

/**
 * Shows device details in the modal using standardized rendering
 * @param {string} deviceId - Device ID to fetch and display
 */
async function showDeviceDetails(deviceId) {
    const modal = document.getElementById('device-modal');
    const content = document.getElementById('device-detail-content');

    if (!modal || !content) {
        console.error('Device modal elements not found');
        return;
    }

    createLoadingDiv('Loading device details...', 'device-detail-content');
    modal.style.display = 'block';

    const deviceDetail = await apiCall(`/devices/${deviceId}`);
    if (deviceDetail) {
        // Clear loading and add device details
        content.textContent = '';
        const deviceDetailsDiv = createDeviceDetailsDiv(deviceDetail);
        content.appendChild(deviceDetailsDiv);
    }
}