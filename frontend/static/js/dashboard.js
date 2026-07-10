// Dashboard state
let dashboardData = null;
let refreshInterval = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    loadDashboard();
    setupFileUpload();
    setupAutoRefresh();
});

// Load dashboard data
function loadDashboard() {
    fetch('/api/dashboard/stats')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                dashboardData = data.data;
                updateStats(data.data);
                updateAnalysisList(data.data.recent_scans);
                updateReports(data.data.recent_scans);
                updateTimeline(data.data.scan_timeline);
                updateDistribution(data.data.threat_distribution);
            } else {
                showError('Failed to load dashboard data');
            }
        })
        .catch(error => {
            console.error('Error loading dashboard:', error);
            showError('Network error loading dashboard');
        });
}

// Update statistics
function updateStats(data) {
    document.getElementById('filesScanned').textContent = data.total_scans || 0;
    document.getElementById('threatsDetected').textContent = data.threats_detected || 0;
    document.getElementById('highRisk').textContent = data.high_risk || 0;
    document.getElementById('criticalRisk').textContent = data.critical_risk || 0;
}

// Update analysis list
function updateAnalysisList(scans) {
    const container = document.getElementById('analysisList');
    
    if (!scans || scans.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-inbox"></i>
                <p>No analyses yet</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    scans.forEach(scan => {
        const riskClass = getRiskClass(scan.risk_score);
        const statusClass = getStatusClass(scan.status);
        const date = new Date(scan.scan_date);
        const formattedDate = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        
        html += `
            <div class="analysis-item" onclick="showScanDetails(${scan.id})">
                <div class="analysis-info">
                    <div class="analysis-filename">${escapeHtml(scan.filename)}</div>
                    <div class="analysis-meta">
                        <span>${scan.malware_family || 'Unknown'}</span>
                        <span>•</span>
                        <span>${formattedDate}</span>
                    </div>
                </div>
                <div class="analysis-score">
                    <span class="risk-score ${riskClass}">${scan.risk_score || 0}%</span>
                    <span class="status-badge ${statusClass}">${scan.status || 'Unknown'}</span>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

// Update reports list
function updateReports(scans) {
    const container = document.getElementById('reportsList');
    
    if (!scans || scans.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-file-pdf"></i>
                <p>No reports available</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    scans.slice(0, 5).forEach(scan => {
        if (scan.report_path) {
            const date = new Date(scan.scan_date);
            const formattedDate = date.toLocaleDateString();
            
            html += `
                <div class="report-item" onclick="downloadReport(${scan.id})">
                    <div class="report-info">
                        <i class="fas fa-file-pdf"></i>
                        <div>
                            <div class="report-name">${escapeHtml(scan.filename)}</div>
                            <div class="report-date">${formattedDate}</div>
                        </div>
                    </div>
                    <button class="btn-download" onclick="event.stopPropagation(); downloadReport(${scan.id})">
                        <i class="fas fa-download"></i>
                    </button>
                </div>
            `;
        }
    });
    
    container.innerHTML = html || '<p style="color: var(--text-secondary);">No reports available</p>';
}

// Update timeline chart
function updateTimeline(timelineData) {
    const container = document.getElementById('timelineChart');
    
    if (!timelineData || timelineData.length === 0) {
        container.innerHTML = '<p style="color: var(--text-secondary); text-align: center; padding: 40px;">No timeline data available</p>';
        return;
    }
    
    // Create canvas for chart
    container.innerHTML = '<canvas id="timelineCanvas"></canvas>';
    const ctx = document.getElementById('timelineCanvas').getContext('2d');
    
    const labels = timelineData.map(item => {
        const date = new Date(item.date);
        return date.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
    });
    
    const data = timelineData.map(item => item.count);
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Scans per Day',
                data: data,
                borderColor: '#6c5ce7',
                backgroundColor: 'rgba(108, 92, 231, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#6c5ce7'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: '#a0a0b8'
                    }
                },
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: '#a0a0b8'
                    }
                }
            }
        }
    });
}

// Update threat distribution
function updateDistribution(distributionData) {
    const container = document.getElementById('distributionChart');
    
    if (!distributionData || distributionData.length === 0) {
        container.innerHTML = '<p style="color: var(--text-secondary); text-align: center; padding: 40px;">No distribution data available</p>';
        return;
    }
    
    // Create canvas for chart
    container.innerHTML = '<canvas id="distributionCanvas"></canvas>';
    const ctx = document.getElementById('distributionCanvas').getContext('2d');
    
    const colors = {
        'Safe': '#74b9ff',
        'Low': '#00b894',
        'Medium': '#fdcb6e',
        'High': '#ff7675',
        'Critical': '#ff6b6b'
    };
    
    const labels = distributionData.map(item => item.level);
    const data = distributionData.map(item => item.count);
    const backgroundColor = labels.map(label => colors[label] || '#a0a0b8');
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: backgroundColor,
                borderWidth: 2,
                borderColor: '#1a1a2e'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#ffffff',
                        padding: 20
                    }
                }
            },
            cutout: '60%'
        }
    });
}

// Setup file upload
function setupFileUpload() {
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    
    uploadArea.addEventListener('click', () => {
        fileInput.click();
    });
    
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.style.borderColor = '#6c5ce7';
        uploadArea.style.background = 'rgba(108, 92, 231, 0.05)';
    });
    
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.style.borderColor = '#2a2a4e';
        uploadArea.style.background = 'transparent';
    });
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.style.borderColor = '#2a2a4e';
        uploadArea.style.background = 'transparent';
        
        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });
    
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });
}

// Handle file upload
function handleFileUpload(file) {
    const progressDiv = document.getElementById('uploadProgress');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    
    progressDiv.style.display = 'block';
    progressFill.style.width = '0%';
    progressText.textContent = '0%';
    
    const formData = new FormData();
    formData.append('file', file);
    
    const xhr = new XMLHttpRequest();
    
    xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
            const percent = Math.round((e.loaded / e.total) * 100);
            progressFill.style.width = percent + '%';
            progressText.textContent = percent + '%';
        }
    });
    
    xhr.addEventListener('load', () => {
        if (xhr.status === 200) {
            const response = JSON.parse(xhr.responseText);
            if (response.success) {
                showSuccess('File uploaded and queued for scanning');
                setTimeout(() => {
                    loadDashboard();
                }, 3000);
            } else {
                showError(response.error || 'Upload failed');
            }
        } else {
            showError('Upload failed: ' + xhr.status);
        }
        
        setTimeout(() => {
            progressDiv.style.display = 'none';
            progressFill.style.width = '0%';
            progressText.textContent = '0%';
        }, 3000);
    });
    
    xhr.addEventListener('error', () => {
        showError('Network error during upload');
        progressDiv.style.display = 'none';
    });
    
    xhr.open('POST', '/api/upload');
    xhr.send(formData);
}

// Show scan details in modal
function showScanDetails(scanId) {
    fetch(`/api/scan/${scanId}`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const scan = data.result;
                const modal = document.getElementById('scanModal');
                const body = document.getElementById('modalBody');
                
                const date = new Date(scan.scan_date);
                const formattedDate = date.toLocaleString();
                
                let detectionsHtml = '';
                if (scan.detections && Object.keys(scan.detections).length > 0) {
                    detectionsHtml = '<h4>Detection Details</h4><div class="detection-list">';
                    const entries = Object.entries(scan.detections).slice(0, 10);
                    entries.forEach(([engine, result]) => {
                        if (result.detected) {
                            detectionsHtml += `
                                <div class="detection-item">
                                    <span class="engine-name">${escapeHtml(engine)}</span>
                                    <span class="detection-result">${escapeHtml(result.result || 'Malicious')}</span>
                                </div>
                            `;
                        }
                    });
                    detectionsHtml += '</div>';
                }
                
                body.innerHTML = `
                    <div class="detail-row">
                        <span class="detail-label">Filename</span>
                        <span class="detail-value">${escapeHtml(scan.filename)}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">File Hash</span>
                        <span class="detail-value" style="font-size:12px;word-break:break-all;">${scan.file_hash}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">File Size</span>
                        <span class="detail-value">${formatFileSize(scan.file_size)}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Scan Date</span>
                        <span class="detail-value">${formattedDate}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Risk Score</span>
                        <span class="detail-value risk-score ${getRiskClass(scan.risk_score)}">${scan.risk_score}%</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Malware Family</span>
                        <span class="detail-value">${scan.malware_family || 'Unknown'}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Status</span>
                        <span class="detail-value status-badge ${getStatusClass(scan.status)}">${scan.status || 'Unknown'}</span>
                    </div>
                    ${detectionsHtml}
                    ${scan.report_path ? `
                        <div style="margin-top:20px;text-align:center;">
                            <button class="btn-upload" onclick="downloadReport(${scan.id})">
                                <i class="fas fa-file-pdf"></i> Download Full Report
                            </button>
                        </div>
                    ` : ''}
                `;
                
                modal.classList.add('active');
            } else {
                showError('Failed to load scan details');
            }
        })
        .catch(error => {
            console.error('Error loading scan details:', error);
            showError('Network error loading scan details');
        });
}

// Close modal
function closeModal() {
    document.getElementById('scanModal').classList.remove('active');
}

// Download report
function downloadReport(scanId) {
    window.location.href = `/api/report/${scanId}`;
}

// Refresh dashboard
function refreshDashboard() {
    loadDashboard();
    const btn = document.querySelector('.btn-refresh');
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    setTimeout(() => {
        btn.innerHTML = '<i class="fas fa-sync-alt"></i>';
    }, 1000);
}

// Setup auto-refresh
function setupAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
    refreshInterval = setInterval(() => {
        loadDashboard();
    }, 30000); // Refresh every 30 seconds
}

// Helper functions
function getRiskClass(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'safe';
}

function getStatusClass(status) {
    if (!status) return 'safe';
    const lower = status.toLowerCase();
    if (lower.includes('critical')) return 'critical';
    if (lower.includes('high')) return 'high-risk';
    if (lower.includes('medium')) return 'medium-risk';
    if (lower.includes('low')) return 'low-risk';
    return 'safe';
}

function formatFileSize(bytes) {
    if (!bytes) return 'Unknown';
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + sizes[i];
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Notification helpers
function showSuccess(message) {
    showNotification(message, 'success');
}

function showError(message) {
    showNotification(message, 'error');
}

function showNotification(message, type) {
    // Simple alert for now - could be enhanced with toast notifications
    if (type === 'error') {
        console.error(message);
        alert('Error: ' + message);
    } else {
        console.log(message);
        // Could show a toast notification here
    }
}

// Close modal on click outside
document.addEventListener('click', function(event) {
    const modal = document.getElementById('scanModal');
    if (event.target === modal) {
        closeModal();
    }
});

// Close modal on escape key
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        closeModal();
    }
});