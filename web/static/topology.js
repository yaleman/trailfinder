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
        showError(`Failed to load data from ${url}`);
        return null;
    }
}

// Network Topology
async function loadTopology() {
    const container = document.getElementById('topology-container');
    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'loading';
    loadingDiv.textContent = 'Loading network topology...';
    container.textContent = ''; // Clear existing content
    container.appendChild(loadingDiv);

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

    // Map connections to use source/target format expected by D3
    const links = topology.connections.map(conn => ({
        ...conn,
        source: conn.from,
        target: conn.to
    }));

    // Create force simulation
    const simulation = d3.forceSimulation(topology.devices)
        .force('link', d3.forceLink(links)
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
        .data(links)
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
        .attr('r', d => d.device_id === 'internet' ? 30 : 20)
        .style('fill', d => d.device_id === 'internet' ? '#3498db' : getDeviceColor(d.device_type))
        .style('stroke', '#fff')
        .style('stroke-width', 2)
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended))
        .on('click', (_event, d) => {
            if (d.device_id !== 'internet') {
                showDeviceDetails(d.device_id);
            }
        })
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

// Device Details Modal (shared functionality)
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
    createDeviceDetailDiv(content, device);
}

function createDeviceDetailDiv(content, device) {
    // Clear existing content
    content.textContent = '';

    const deviceDetailDiv = document.createElement('div');
    deviceDetailDiv.classList.add('device-detail');

    const header = document.createElement('h2');
    header.textContent = device.hostname;
    deviceDetailDiv.appendChild(header);

    if (device.name) {
        const nameParagraph = document.createElement('p');
        const strongName = document.createElement('strong');
        strongName.textContent = 'Name:';
        nameParagraph.appendChild(strongName);
        nameParagraph.append(` ${device.name}`);
        deviceDetailDiv.appendChild(nameParagraph);
    }

    const deviceIdParagraph = document.createElement('p');
    const strongDeviceId = document.createElement('strong');
    strongDeviceId.textContent = 'Device ID:';
    deviceIdParagraph.appendChild(strongDeviceId);
    deviceIdParagraph.append(` ${device.device_id}`);
    deviceDetailDiv.appendChild(deviceIdParagraph);

    const typeParagraph = document.createElement('p');
    const strongType = document.createElement('strong');
    strongType.textContent = 'Type:';
    typeParagraph.appendChild(strongType);
    typeParagraph.append(` ${device.device_type}`);
    deviceDetailDiv.appendChild(typeParagraph);

    const ownerParagraph = document.createElement('p');
    const strongOwner = document.createElement('strong');
    strongOwner.textContent = 'Owner:';
    ownerParagraph.appendChild(strongOwner);
    const owner = typeof device.owner === 'object' ? device.owner.Named || 'Unknown' : device.owner;
    ownerParagraph.append(` ${owner}`);
    deviceDetailDiv.appendChild(ownerParagraph);

    // Interfaces section
    const interfacesSection = document.createElement('div');
    interfacesSection.classList.add('detail-section');

    const interfacesHeader = document.createElement('h3');
    interfacesHeader.textContent = `Interfaces (${device.interfaces.length})`;
    interfacesSection.appendChild(interfacesHeader);

    const interfacesTable = document.createElement('table');
    interfacesTable.classList.add('interfaces-table');

    const interfacesThead = document.createElement('thead');
    const interfacesHeaderRow = document.createElement('tr');
    ['Name', 'Type', 'VLAN', 'IP Addresses', 'Comment'].forEach(headerText => {
        const th = document.createElement('th');
        th.textContent = headerText;
        interfacesHeaderRow.appendChild(th);
    });
    interfacesThead.appendChild(interfacesHeaderRow);
    interfacesTable.appendChild(interfacesThead);

    const interfacesTbody = document.createElement('tbody');
    device.interfaces.forEach(iface => {
        const row = document.createElement('tr');

        const nameCell = document.createElement('td');
        nameCell.textContent = iface.name;
        row.appendChild(nameCell);

        const typeCell = document.createElement('td');
        const typeSpan = document.createElement('span');
        typeSpan.classList.add('interface-type', getInterfaceTypeClass(iface.interface_type));
        typeSpan.textContent = getInterfaceTypeDisplay(iface.interface_type);
        typeCell.appendChild(typeSpan);
        row.appendChild(typeCell);

        const vlanCell = document.createElement('td');
        const vlansDisplay = iface.vlans && iface.vlans.length > 0 ? iface.vlans.join(', ') : 'N/A';
        vlanCell.textContent = vlansDisplay;
        row.appendChild(vlanCell);

        const addressesCell = document.createElement('td');
        addressesCell.textContent = iface.addresses.join(', ') || 'None';
        row.appendChild(addressesCell);

        const commentCell = document.createElement('td');
        commentCell.textContent = iface.comment || '';
        row.appendChild(commentCell);

        interfacesTbody.appendChild(row);
    });
    interfacesTable.appendChild(interfacesTbody);
    interfacesSection.appendChild(interfacesTable);
    deviceDetailDiv.appendChild(interfacesSection);

    // Routes section
    const routesSection = document.createElement('div');
    routesSection.classList.add('detail-section');

    const routesHeader = document.createElement('h3');
    routesHeader.textContent = `Routes (${device.routes.length})`;
    routesSection.appendChild(routesHeader);

    const routesTable = document.createElement('table');
    routesTable.classList.add('routes-table');

    const routesThead = document.createElement('thead');
    const routesHeaderRow = document.createElement('tr');
    ['Target', 'Type', 'Gateway', 'Distance'].forEach(headerText => {
        const th = document.createElement('th');
        th.textContent = headerText;
        routesHeaderRow.appendChild(th);
    });
    routesThead.appendChild(routesHeaderRow);
    routesTable.appendChild(routesThead);

    const routesTbody = document.createElement('tbody');
    device.routes.forEach(route => {
        const row = document.createElement('tr');

        const targetCell = document.createElement('td');
        targetCell.textContent = route.target;
        row.appendChild(targetCell);

        const typeCell = document.createElement('td');
        const typeSpan = document.createElement('span');
        typeSpan.classList.add('route-type', getRouteTypeClass(route.route_type));
        typeSpan.textContent = getRouteTypeDisplay(route.route_type);
        typeCell.appendChild(typeSpan);
        row.appendChild(typeCell);

        const gatewayCell = document.createElement('td');
        gatewayCell.textContent = route.gateway || 'N/A';
        row.appendChild(gatewayCell);

        const distanceCell = document.createElement('td');
        distanceCell.textContent = route.distance || 'N/A';
        row.appendChild(distanceCell);

        routesTbody.appendChild(row);
    });
    routesTable.appendChild(routesTbody);
    routesSection.appendChild(routesTable);
    deviceDetailDiv.appendChild(routesSection);

    content.appendChild(deviceDetailDiv);
}

function closeModal() {
    document.getElementById('device-modal').style.display = 'none';
}

// Utility Functions
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
        'SameNetwork': '#f39c12',
        'Internet': '#9b59b6',
        'CDP': '#3498db'
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