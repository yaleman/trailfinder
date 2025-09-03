/**
 * D3.js-based topology visualization utilities with full interactive features
 */

/**
 * Load and render topology data with D3.js force simulation
 */
async function loadAndRenderTopology(containerId, options = {}) {
    try {
        console.log('Loading topology data...');
        const response = await fetch('/api/topology');
        const topology = await response.json();
        
        console.log('Topology loaded, rendering...');
        const controls = renderNetworkTopology(topology, containerId, options);
        
        return {
            topologyData: topology,
            controls: controls
        };
    } catch (error) {
        console.error('Error loading topology:', error);
        return null;
    }
}

/**
 * Render the network topology with D3.js force simulation
 */
function renderNetworkTopology(topology, containerId, options = {}) {
    console.log('Starting D3.js topology render');
    
    const container = document.getElementById(containerId);
    if (!container) {
        console.error(`Container ${containerId} not found`);
        return null;
    }
    
    // Clear existing content
    container.innerHTML = '<svg id="topology-svg"></svg>';
    
    const svg = d3.select('#topology-svg');
    const width = container.clientWidth || 1336;
    const height = container.clientHeight || 600;
    
    // Set SVG dimensions and viewBox
    svg.attr('width', width)
       .attr('height', height)
       .attr('viewBox', `0 0 ${width} ${height}`)
       .style('background', 'white')
       .style('border', '1px solid #ddd');
    
    // Clear existing content
    svg.selectAll('*').remove();
    
    console.log('Devices:', topology.devices?.length || 0);
    console.log('Connections:', topology.connections?.length || 0);
    
    // Map connections to use source/target format expected by D3
    const links = (topology.connections || []).map(conn => ({
        ...conn,
        source: conn.from,
        target: conn.to
    }));
    
    // Create main group for all elements
    const g = svg.append('g');
    
    // Add zoom behavior
    const zoom = d3.zoom()
        .scaleExtent([0.1, 4])
        .on('zoom', (event) => {
            g.attr('transform', event.transform);
        });
    
    svg.call(zoom);
    
    // Create force simulation
    const simulation = d3.forceSimulation(topology.devices || [])
        .force('link', d3.forceLink(links)
            .id(d => d.device_id)
            .distance(150))
        .force('charge', d3.forceManyBody().strength(-400))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(d => d.device_id === 'internet' ? 35 : 25));
    
    // Create links
    const link = g.append('g')
        .attr('class', 'links')
        .selectAll('line')
        .data(links)
        .enter().append('line')
        .attr('class', 'link')
        .style('stroke', d => getConnectionColor(d.connection_type))
        .style('stroke-width', 2)
        .style('stroke-opacity', 0.7);
    
    // Create nodes
    const node = g.append('g')
        .attr('class', 'nodes')
        .selectAll('circle')
        .data(topology.devices || [])
        .enter().append('circle')
        .attr('class', 'node')
        .attr('r', d => d.device_id === 'internet' ? 30 : 20)
        .style('fill', d => d.device_id === 'internet' ? '#3498db' : getDeviceColor(d.device_type))
        .style('stroke', '#fff')
        .style('stroke-width', 3)
        .style('cursor', 'pointer')
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended))
        .on('click', (event, d) => {
            if (d.device_id !== 'internet' && options.onNodeClick) {
                options.onNodeClick(d.device_id);
            }
        })
        .on('mouseover', (event, d) => {
            // Add tooltip
            const tooltip = d3.select('body').append('div')
                .attr('class', 'tooltip')
                .style('position', 'absolute')
                .style('background', 'rgba(0,0,0,0.8)')
                .style('color', 'white')
                .style('padding', '8px')
                .style('border-radius', '4px')
                .style('pointer-events', 'none')
                .style('z-index', '9999')
                .style('font-size', '12px')
                .text(`${d.hostname} (${d.device_type || 'Unknown'})`);
            
            // Position tooltip
            tooltip.style('left', (event.pageX + 10) + 'px')
                   .style('top', (event.pageY - 10) + 'px');
        })
        .on('mousemove', (event) => {
            // Update tooltip position
            d3.select('.tooltip')
                .style('left', (event.pageX + 10) + 'px')
                .style('top', (event.pageY - 10) + 'px');
        })
        .on('mouseout', () => {
            d3.selectAll('.tooltip').remove();
        });
    
    // Add labels
    const label = g.append('g')
        .attr('class', 'labels')
        .selectAll('text')
        .data(topology.devices || [])
        .enter().append('text')
        .text(d => d.hostname)
        .style('font-size', '12px')
        .style('font-weight', 'bold')
        .style('text-anchor', 'middle')
        .style('pointer-events', 'none')
        .style('fill', '#2c3e50')
        .attr('dy', -35);
    
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
    
    // Return controls object
    const controls = {
        resetZoom: () => {
            svg.transition()
               .duration(750)
               .call(zoom.transform, d3.zoomIdentity);
        },
        simulation: simulation,
        zoom: zoom
    };
    
    console.log('D3.js topology render complete');
    return controls;
}

// Utility Functions
function getDeviceColor(deviceType) {
    const colors = {
        'Router': '#e74c3c',
        'Switch': '#27ae60',
        'Firewall': '#e67e22',
        'AccessPoint': '#9b59b6',
        'Unknown': '#95a5a6'
    };
    return colors[deviceType] || '#95a5a6';
}

function getConnectionColor(connectionType) {
    const colors = {
        'DirectLink': '#2ecc71',
        'Gateway': '#e74c3c', 
        'SameNetwork': '#f39c12',
        'Internet': '#9b59b6',
        'CDP': '#3498db'
    };
    return colors[connectionType] || '#666';
}