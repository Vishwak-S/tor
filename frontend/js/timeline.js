// Timeline Visualization using D3.js

function updateTimeline() {
    const container = document.getElementById('timeline-viz');
    
    if (!container || appState.correlations.length === 0) {
        container.innerHTML = '<p style="text-align: center; padding: 40px;">No correlation data available for timeline.</p>';
        return;
    }
    
    // Clear existing content
    container.innerHTML = '';
    
    // Set dimensions
    const margin = {top: 40, right: 30, bottom: 60, left: 60};
    const width = container.clientWidth - margin.left - margin.right;
    const height = 500 - margin.top - margin.bottom;
    
    // Create SVG
    const svg = d3.select(container)
        .append('svg')
        .attr('width', width + margin.left + margin.right)
        .attr('height', height + margin.top + margin.bottom)
        .append('g')
        .attr('transform', `translate(${margin.left},${margin.top})`);
    
    // Prepare data
    const timelineData = appState.correlations.map(corr => ({
        timestamp: new Date(corr.timestamp),
        confidence: corr.confidence_score,
        srcIp: corr.src_ip,
        guardNode: corr.guard_nickname
    })).sort((a, b) => a.timestamp - b.timestamp);
    
    // Create scales
    const xScale = d3.scaleTime()
        .domain(d3.extent(timelineData, d => d.timestamp))
        .range([0, width]);
    
    const yScale = d3.scaleLinear()
        .domain([0, 1])
        .range([height, 0]);
    
    // Create axes
    const xAxis = d3.axisBottom(xScale)
        .ticks(8)
        .tickFormat(d3.timeFormat('%H:%M:%S'));
    
    const yAxis = d3.axisLeft(yScale)
        .ticks(5)
        .tickFormat(d => `${(d * 100).toFixed(0)}%`);
    
    // Add X axis
    svg.append('g')
        .attr('transform', `translate(0,${height})`)
        .call(xAxis)
        .selectAll('text')
        .attr('transform', 'rotate(-45)')
        .style('text-anchor', 'end');
    
    // Add Y axis
    svg.append('g')
        .call(yAxis);
    
    // Add X axis label
    svg.append('text')
        .attr('x', width / 2)
        .attr('y', height + 50)
        .style('text-anchor', 'middle')
        .text('Timestamp');
    
    // Add Y axis label
    svg.append('text')
        .attr('transform', 'rotate(-90)')
        .attr('x', -height / 2)
        .attr('y', -45)
        .style('text-anchor', 'middle')
        .text('Confidence Score');
    
    // Add title
    svg.append('text')
        .attr('x', width / 2)
        .attr('y', -10)
        .style('text-anchor', 'middle')
        .style('font-size', '16px')
        .style('font-weight', 'bold')
        .text('Correlation Timeline');
    
    // Create tooltip
    const tooltip = d3.select(container)
        .append('div')
        .style('position', 'absolute')
        .style('background', 'rgba(0, 0, 0, 0.8)')
        .style('color', 'white')
        .style('padding', '10px')
        .style('border-radius', '5px')
        .style('pointer-events', 'none')
        .style('opacity', 0);
    
    // Add circles
    svg.selectAll('circle')
        .data(timelineData)
        .enter()
        .append('circle')
        .attr('cx', d => xScale(d.timestamp))
        .attr('cy', d => yScale(d.confidence))
        .attr('r', 6)
        .attr('fill', d => d.confidence >= 0.7 ? '#10b981' : 
                          d.confidence >= 0.5 ? '#f59e0b' : '#ef4444')
        .attr('opacity', 0.7)
        .on('mouseover', function(event, d) {
            d3.select(this)
                .attr('r', 10)
                .attr('opacity', 1);
            
            tooltip
                .style('opacity', 1)
                .html(`
                    <strong>Time:</strong> ${d.timestamp.toLocaleString()}<br>
                    <strong>Source IP:</strong> ${d.srcIp}<br>
                    <strong>Guard:</strong> ${d.guardNode}<br>
                    <strong>Confidence:</strong> ${(d.confidence * 100).toFixed(1)}%
                `)
                .style('left', (event.pageX + 10) + 'px')
                .style('top', (event.pageY - 30) + 'px');
        })
        .on('mouseout', function() {
            d3.select(this)
                .attr('r', 6)
                .attr('opacity', 0.7);
            
            tooltip.style('opacity', 0);
        });
    
    // Add line
    const line = d3.line()
        .x(d => xScale(d.timestamp))
        .y(d => yScale(d.confidence))
        .curve(d3.curveMonotoneX);
    
    svg.append('path')
        .datum(timelineData)
        .attr('fill', 'none')
        .attr('stroke', '#6366f1')
        .attr('stroke-width', 2)
        .attr('d', line)
        .attr('opacity', 0.5);
}
