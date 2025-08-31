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

    // Modal close
    document.querySelector('.close').addEventListener('click', closeModal);
    window.addEventListener('click', (event) => {
        const modal = document.getElementById('device-modal');
        if (event.target === modal) {
            closeModal();
        }
    });

    // Path finder
    document.getElementById('find-path').addEventListener('click', findPath);
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
        console.error("API call failed", endpoint, error);
        showError(`Failed to load data from ${endpoint}`);
        return null;
    }
}

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

    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'loading';
    loadingDiv.textContent = 'Loading device details...';
    content.textContent = ''; // Clear existing content
    content.appendChild(loadingDiv);

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
        const vlansDisplay = iface.vlans && iface.vlans.length > 0 ? iface.vlans.join(', ') : 'N/A';
        return `
            <tr>
                <td>${iface.name}</td>
                <td><span class="interface-type ${interfaceClass}">${interfaceType}</span></td>
                <td>${vlansDisplay}</td>
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

// Network Topology
async function loadTopology() {
    createLoadingDiv('Loading network topology...', 'topology-container');

    topologyData = await apiCall('/topology');
    if (topologyData) {
        renderTopology(topologyData);
    }
}

function renderTopology(topology) {
    const container = document.getElementById('topology-container');
    // Clear loading message and ensure SVG exists
    container.innerHTML = '<svg id="topology-svg"></svg>';

    const svg = d3.select('#topology-svg');
    const width = container.clientWidth;
    const height = container.clientHeight;

    // Clear existing content
    svg.selectAll('*').remove();

    // Create force simulation
    const simulation = d3.forceSimulation(topology.devices)
        .force('link', d3.forceLink(topology.connections)
            .id(d => d.device_id)
            .distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2));

    // Add zoom behavior
    const zoom = d3.zoom()
        .scaleExtent([0.1, 4])
        .on('zoom', (event) => {
            g.attr('transform', event.transform);
        });

    svg.call(zoom);

    const g = svg.append('g');

    // Create links
    const link = g.append('g')
        .selectAll('line')
        .data(topology.connections)
        .enter().append('line')
        .attr('class', 'link')
        .style('stroke', d => getConnectionColor(d.connection_type))
        .style('stroke-width', 2)
        .style('stroke-opacity', 0.7);

    // Create nodes
    const node = g.append('g')
        .selectAll('circle')
        .data(topology.devices)
        .enter().append('circle')
        .attr('class', 'node')
        .attr('r', 20)
        .style('fill', d => getDeviceColor(d.device_type))
        .style('stroke', '#fff')
        .style('stroke-width', 2)
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended))
        .on('click', (_event, d) => showDeviceDetails(d.device_id))
        .on('mouseover', (_event, d) => {
            // Add tooltip
            d3.select('body').append('div')
                .attr('class', 'tooltip')
                .style('position', 'absolute')
                .style('background', 'rgba(0,0,0,0.8)')
                .style('color', 'white')
                .style('padding', '8px')
                .style('border-radius', '4px')
                .style('pointer-events', 'none')
                .text(d.hostname);
        })
        .on('mouseout', () => {
            d3.selectAll('.tooltip').remove();
        });

    // Add labels
    const label = g.append('g')
        .selectAll('text')
        .data(topology.devices)
        .enter().append('text')
        .text(d => d.hostname)
        .style('font-size', '12px')
        .style('text-anchor', 'middle')
        .style('pointer-events', 'none')
        .attr('dy', -25);

    // Update positions on simulation tick
    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        node
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);

        label
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    });

    // Drag functions
    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }

    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }

    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }

    // Reset zoom button
    document.getElementById('reset-zoom').onclick = () => {
        svg.transition().duration(750).call(
            zoom.transform,
            d3.zoomIdentity
        );
    };
}

// Path Finder
async function loadPathfinderDevices() {
    if (!devicesData.length) {
        await loadDevices();
    }

    const sourceSelect = document.getElementById('source-device');
    sourceSelect.innerHTML = '<option value="">Select device...</option>' +
        devicesData.map(device =>
            `<option value="${device.hostname}">${device.hostname}</option>`
        ).join('');
}

async function updateSourceInterfaces() {
    const deviceHostname = document.getElementById('source-device').value;
    const interfaceSelect = document.getElementById('source-interface');

    if (!deviceHostname) {
        interfaceSelect.innerHTML = '<option value="">Select interface...</option>';
        return;
    }

    const deviceDetail = await apiCall(`/devices/${deviceHostname}`);
    if (deviceDetail) {
        interfaceSelect.innerHTML = '<option value="">Select interface...</option>' +
            deviceDetail.interfaces.map(iface =>
                `<option value="${iface.name}">${iface.name} (${iface.interface_type})</option>`
            ).join('');
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

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

function getDeviceColor(deviceType) {
    const colors = {
        'Router': '#ff6b6b',
        'Switch': '#4ecdc4',
        'Firewall': '#45b7d1',
        'AccessPoint': '#96ceb4'
    };
    return colors[deviceType] || '#999';
}

function getConnectionColor(connectionType) {
    const colors = {
        'DirectLink': '#2ecc71',
        'Gateway': '#e74c3c',
        'SameNetwork': '#f39c12'
    };
    return colors[connectionType] || '#999';
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