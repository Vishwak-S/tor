// TOR-Unveil Main Application Logic

const API_BASE_URL = 'http://localhost:5000/api';

// State Management
const appState = {
    nodes: [],
    flows: [],
    correlations: [],
    currentTab: 'overview'
};

// Utility Functions
function showLoading() {
    document.getElementById('loadingOverlay').style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loadingOverlay').style.display = 'none';
}

function showStatus(elementId, message, type = 'info') {
    const statusEl = document.getElementById(elementId);
    statusEl.textContent = message;
    statusEl.className = `status-msg ${type}`;
}

function updateStatusIndicator(status, text) {
    const dot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');
    
    dot.style.backgroundColor = status === 'success' ? 'var(--success-color)' : 'var(--danger-color)';
    statusText.textContent = text;
}

// API Functions
async function apiCall(endpoint, method = 'GET', body = null) {
    try {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json'
            }
        };
        
        if (body && method !== 'GET') {
            options.body = JSON.stringify(body);
        }
        
        const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error || 'API call failed');
        }
        
        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// Core Functions
async function crawlTopology() {
    showLoading();
    showStatus('topologyStatus', 'Crawling TOR network...', 'info');
    
    try {
        const result = await apiCall('/topology/crawl', 'POST');
        showStatus('topologyStatus', 
            `✓ Crawled ${result.data.consensus_nodes} nodes, enhanced ${result.data.enhanced_nodes}`, 
            'success');
        updateStatusIndicator('success', 'Topology Updated');
        
        // Refresh nodes
        await loadNodes();
    } catch (error) {
        showStatus('topologyStatus', `✗ Error: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

async function loadNodes() {
    try {
        const result = await apiCall('/topology/nodes?type=guard&limit=100');
        appState.nodes = result.nodes;
        
        // Update stats
        document.getElementById('guardNodeCount').textContent = result.count;
        
        showStatus('topologyStatus', `✓ Loaded ${result.count} guard nodes`, 'success');
        
        // Update graph if on network tab
        if (appState.currentTab === 'network') {
            updateNetworkGraph();
        }
    } catch (error) {
        console.error('Load nodes error:', error);
    }
}

async function uploadPCAP() {
    const fileInput = document.getElementById('pcapFile');
    const file = fileInput.files[0];
    
    if (!file) {
        showStatus('pcapStatus', '✗ Please select a PCAP file', 'error');
        return;
    }
    
    showLoading();
    showStatus('pcapStatus', 'Uploading and analyzing PCAP...', 'info');
    
    try {
        const formData = new FormData();
        formData.append('file', file);
        
        const response = await fetch(`${API_BASE_URL}/pcap/upload`, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            showStatus('pcapStatus', 
                `✓ Uploaded ${file.name}: ${data.flows_extracted} flows extracted`, 
                'success');
            document.getElementById('flowCount').textContent = data.flows_extracted;
        } else {
            throw new Error(data.error);
        }
    } catch (error) {
        showStatus('pcapStatus', `✗ Error: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

async function runCorrelation() {
    showLoading();
    showStatus('correlationStatus', 'Running correlation analysis...', 'info');
    
    try {
        const result = await apiCall('/correlation/run', 'POST');
        showStatus('correlationStatus', 
            `✓ Analyzed ${result.data.flows_processed} flows, found ${result.data.total_correlations} correlations`, 
            'success');
        
        // Refresh results
        await loadResults();
    } catch (error) {
        showStatus('correlationStatus', `✗ Error: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

async function loadResults() {
    try {
        const result = await apiCall('/correlation/results?limit=50');
        appState.correlations = result.results;
        
        // Update stats
        document.getElementById('correlationCount').textContent = result.count;
        
        if (result.count > 0) {
            const avgConf = result.results.reduce((sum, r) => sum + r.confidence_score, 0) / result.count;
            document.getElementById('avgConfidence').textContent = avgConf.toFixed(3);
        }
        
        // Render table
        renderResultsTable();
        
        // Update visualizations
        if (appState.currentTab === 'network') {
            updateNetworkGraph();
        } else if (appState.currentTab === 'timeline') {
            updateTimeline();
        }
    } catch (error) {
        console.error('Load results error:', error);
    }
}

function renderResultsTable() {
    const container = document.getElementById('results-table');
    
    if (appState.correlations.length === 0) {
        container.innerHTML = '<p style="text-align: center; padding: 40px; color: var(--text-secondary);">No correlation results yet. Upload PCAP and run correlation.</p>';
        return;
    }
    
    let tableHTML = `
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Source IP</th>
                    <th>Timestamp</th>
                    <th>Guard Node</th>
                    <th>Country</th>
                    <th>Confidence</th>
                    <th>Scores</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    appState.correlations.forEach((corr, index) => {
        const confidenceClass = corr.confidence_score >= 0.7 ? 'high' : 
                               corr.confidence_score >= 0.5 ? 'medium' : 'low';
        
        tableHTML += `
            <tr>
                <td>${index + 1}</td>
                <td><code>${corr.src_ip}</code></td>
                <td>${new Date(corr.timestamp).toLocaleString()}</td>
                <td>
                    <strong>${corr.guard_nickname}</strong><br>
                    <small>${corr.guard_ip}</small>
                </td>
                <td>${corr.guard_country || 'N/A'}</td>
                <td>
                    <span class="confidence-badge confidence-${confidenceClass}">
                        ${(corr.confidence_score * 100).toFixed(1)}%
                    </span>
                </td>
                <td>
                    <small>
                        T: ${corr.temporal_score.toFixed(2)} | 
                        B: ${corr.bandwidth_score.toFixed(2)} | 
                        P: ${corr.pattern_score.toFixed(2)}
                    </small>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
}

async function generateReport(type) {
    showLoading();
    showStatus('reportStatus', `Generating ${type.toUpperCase()} report...`, 'info');
    
    try {
        const result = await apiCall('/report/generate', 'POST', { type });
        
        // Trigger download
        window.open(`${API_BASE_URL}/report/download/${result.filename}`, '_blank');
        
        showStatus('reportStatus', `✓ Report generated: ${result.filename}`, 'success');
    } catch (error) {
        showStatus('reportStatus', `✗ Error: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

// Tab Management
function switchTab(tabName) {
    // Update state
    appState.currentTab = tabName;
    
    // Update button states
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.classList.add('active');
    
    // Update content
    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active');
    });
    document.getElementById(`${tabName}-tab`).classList.add('active');
    
    // Load data for specific tabs
    if (tabName === 'network') {
        updateNetworkGraph();
    } else if (tabName === 'timeline') {
        updateTimeline();
    } else if (tabName === 'results') {
        loadResults();
    }
}

// Initialize
async function init() {
    console.log('TOR-Unveil Dashboard Initialized');
    
    // Check API health
    try {
        const health = await fetch(`${API_BASE_URL}/health`);
        const data = await health.json();
        
        if (data.status === 'healthy') {
            updateStatusIndicator('success', 'System Ready');
        }
    } catch (error) {
        updateStatusIndicator('error', 'API Unavailable');
        console.error('Health check failed:', error);
    }
    
    // Load initial data
    loadNodes();
    loadResults();
}

// Start application
window.addEventListener('DOMContentLoaded', init);
