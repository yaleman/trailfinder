// Simple, working topology renderer
function renderSimpleTopology(topology, containerId) {
    console.log('Starting simple topology render');
    
    const container = document.getElementById(containerId);
    if (!container) {
        console.error(`Container ${containerId} not found`);
        return;
    }
    
    const width = 1336;
    const height = 600;
    
    // Create SVG with explicit HTML
    container.innerHTML = `
        <svg id="topology-svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" 
             style="background: white; border: 1px solid #ccc;">
        </svg>
    `;
    
    const svg = d3.select('#topology-svg');
    const g = svg.append('g');
    
    console.log('Devices:', topology.devices.length);
    console.log('Connections:', topology.connections.length);
    
    // Position devices in a circle
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) / 3;
    
    topology.devices.forEach((device, i) => {
        const angle = (i * 2 * Math.PI) / topology.devices.length;
        device.x = centerX + radius * Math.cos(angle);
        device.y = centerY + radius * Math.sin(angle);
    });
    
    // Draw connections
    const connections = topology.connections.map(conn => ({
        source: topology.devices.find(d => d.device_id === conn.from),
        target: topology.devices.find(d => d.device_id === conn.to),
        ...conn
    })).filter(conn => conn.source && conn.target);
    
    console.log('Valid connections:', connections.length);
    
    // Add lines for connections
    g.selectAll('.connection-line')
        .data(connections)
        .enter()
        .append('line')
        .attr('class', 'connection-line')
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y)
        .attr('stroke', '#666')
        .attr('stroke-width', 2);
    
    // Add circles for devices
    g.selectAll('.device-circle')
        .data(topology.devices)
        .enter()
        .append('circle')
        .attr('class', 'device-circle')
        .attr('cx', d => d.x)
        .attr('cy', d => d.y)
        .attr('r', d => d.device_id === 'internet' ? 40 : 30)
        .attr('fill', d => d.device_id === 'internet' ? '#3498db' : '#e74c3c')
        .attr('stroke', '#2c3e50')
        .attr('stroke-width', 3);
    
    // Add text labels
    g.selectAll('.device-label')
        .data(topology.devices)
        .enter()
        .append('text')
        .attr('class', 'device-label')
        .attr('x', d => d.x)
        .attr('y', d => d.y - 50)
        .attr('text-anchor', 'middle')
        .attr('font-size', '14px')
        .attr('font-weight', 'bold')
        .attr('fill', '#2c3e50')
        .text(d => d.hostname);
    
    console.log('Simple topology render complete');
}

// Override the topology loading function
async function loadAndRenderTopology(containerId, options = {}) {
    try {
        console.log('Loading topology data...');
        const response = await fetch('/api/topology');
        const topology = await response.json();
        
        console.log('Topology loaded, rendering...');
        renderSimpleTopology(topology, containerId);
        
        return {
            topologyData: topology,
            controls: { resetZoom: () => console.log('Reset zoom not implemented') }
        };
    } catch (error) {
        console.error('Error loading topology:', error);
        return null;
    }
}