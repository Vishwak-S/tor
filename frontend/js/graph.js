// Network Graph Visualization using vis.js

let network = null;

function updateNetworkGraph() {
    const container = document.getElementById('network-graph');
    
    if (!container) return;
    
    // Get filter settings
    const showGuards = document.getElementById('showGuards').checked;
    const showExits = document.getElementById('showExits').checked;
    const showCorrelations = document.getElementById('showCorrelations').checked;
    
    // Prepare nodes
    const nodes = [];
    const edges = [];
    
    // Add guard nodes
    if (showGuards && appState.nodes.length > 0) {
        appState.nodes.slice(0, 30).forEach(node => {
            nodes.push({
                id: node.fingerprint,
                label: node.nickname,
                title: `${node.nickname}\nIP: ${node.ip_address}\nCountry: ${node.country_code || 'Unknown'}`,
                color: {
                    background: '#3b82f6',
                    border: '#1d4ed8'
                },
                shape: 'dot',
                size: 15
            });
        });
    }
    
    // Add correlation edges
    if (showCorrelations && appState.correlations.length > 0) {
        appState.correlations.slice(0, 20).forEach((corr, idx) => {
            // Add source IP as node
            const sourceId = `src_${corr.src_ip}`;
            if (!nodes.find(n => n.id === sourceId)) {
                nodes.push({
                    id: sourceId,
                    label: corr.src_ip,
                    title: `Source IP: ${corr.src_ip}`,
                    color: {
                        background: '#ef4444',
                        border: '#991b1b'
                    },
                    shape: 'diamond',
                    size: 20
                });
            }
            
            // Add edge from source to guard
            edges.push({
                from: sourceId,
                to: corr.guard_fingerprint,
                label: `${(corr.confidence_score * 100).toFixed(0)}%`,
                color: {
                    color: corr.confidence_score >= 0.7 ? '#10b981' : 
                           corr.confidence_score >= 0.5 ? '#f59e0b' : '#94a3b8'
                },
                width: Math.max(1, corr.confidence_score * 5),
                arrows: 'to'
            });
        });
    }
    
    // Create network
    const data = { nodes, edges };
    
    const options = {
        nodes: {
            font: {
                size: 12,
                color: '#ffffff'
            },
            borderWidth: 2
        },
        edges: {
            font: {
                size: 10,
                align: 'middle'
            },
            smooth: {
                type: 'continuous'
            }
        },
        physics: {
            enabled: true,
            barnesHut: {
                gravitationalConstant: -8000,
                springConstant: 0.04,
                springLength: 150
            },
            stabilization: {
                iterations: 150
            }
        },
        interaction: {
            hover: true,
            tooltipDelay: 200
        }
    };
    
    // Destroy existing network
    if (network) {
        network.destroy();
    }
    
    // Create new network
    network = new vis.Network(container, data, options);
    
    // Add event listeners
    network.on('click', function(params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            console.log('Clicked node:', nodeId);
        }
    });
}
