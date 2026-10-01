/* ==========================================================================
   PhishGuard - Frontend Logic & Real-Time API Integration
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
    initTabNavigation();
    initUrlScanner();
    initMessageAnalyzer();
    initScanHistory();
    loadDashboardStats();
    loadRecentHistory();
});

/* ==========================================================================
   1. TAB NAVIGATION
   ========================================================================== */
function initTabNavigation() {
    const navButtons = document.querySelectorAll('.nav-btn, .switch-tab');
    const tabPanes = document.querySelectorAll('.tab-pane');

    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');
            if (!targetTab) return;

            // Update active state on sidebar buttons
            document.querySelectorAll('.sidebar .nav-btn').forEach(b => {
                b.classList.toggle('active', b.getAttribute('data-tab') === targetTab);
            });

            // Show target tab pane
            tabPanes.forEach(pane => {
                pane.classList.toggle('active', pane.id === `tab-${targetTab}`);
            });

            // Refresh tab-specific data
            if (targetTab === 'dashboard') {
                loadDashboardStats();
                loadRecentHistory();
            } else if (targetTab === 'scan-history') {
                loadFullHistory();
            }
        });
    });
}

/* ==========================================================================
   2. DASHBOARD METRICS & TELEMETRY
   ========================================================================== */
async function loadDashboardStats() {
    try {
        const res = await fetch('/api/stats');
        const json = await res.json();

        if (json.success) {
            const s = json.stats;
            document.getElementById('stat-total').innerText = s.total_scans;
            document.getElementById('stat-url').innerText = s.url_scans;
            document.getElementById('stat-message').innerText = s.message_scans;
            document.getElementById('stat-threats').innerText = s.high_risk + s.critical;

            document.getElementById('stat-low').innerText = s.low_risk;
            document.getElementById('stat-suspicious').innerText = s.suspicious;
            document.getElementById('stat-high').innerText = s.high_risk;
            document.getElementById('stat-critical').innerText = s.critical;

            // Calculate progress bars %
            const total = s.total_scans || 1;
            document.getElementById('bar-low').style.width = `${(s.low_risk / total) * 100}%`;
            document.getElementById('bar-suspicious').style.width = `${(s.suspicious / total) * 100}%`;
            document.getElementById('bar-high').style.width = `${(s.high_risk / total) * 100}%`;
            document.getElementById('bar-critical').style.width = `${(s.critical / total) * 100}%`;
        }
    } catch (err) {
        console.error('Error fetching dashboard stats:', err);
    }
}

async function loadRecentHistory() {
    const tableBody = document.getElementById('dashboard-recent-table');
    try {
        const res = await fetch('/api/history');
        const json = await res.json();

        if (json.success && json.data.length > 0) {
            const recent = json.data.slice(0, 5);
            tableBody.innerHTML = recent.map(r => `
                <tr>
                    <td><span class="badge ${r.scan_type.toLowerCase()}">${r.scan_type}</span></td>
                    <td><span class="summary-code">${escapeHtml(r.input_summary)}</span></td>
                    <td><strong>${r.risk_score}</strong>/100</td>
                    <td><span class="badge ${getRiskClass(r.risk_level)}">${r.risk_level}</span></td>
                    <td>${r.detected_indicators.length} rule(s)</td>
                    <td class="text-muted">${formatTimestamp(r.timestamp)}</td>
                </tr>
            `).join('');
        } else {
            tableBody.innerHTML = '<tr><td colspan="6" class="text-muted center">No scan telemetry records found. Perform a scan to populate data.</td></tr>';
        }
    } catch (err) {
        tableBody.innerHTML = '<tr><td colspan="6" class="text-muted center">Failed to load recent activity.</td></tr>';
    }
}

/* ==========================================================================
   3. URL SCANNER (REAL-TIME ANALYSIS - NO STALE CACHE)
   ========================================================================== */
function initUrlScanner() {
    const form = document.getElementById('url-scan-form');
    const input = document.getElementById('url-input');
    const resultCard = document.getElementById('url-result-card');
    const btnScan = document.getElementById('btn-scan-url');

    // Preset Pills: Only populate input field; clear old scan results
    document.querySelectorAll('#tab-url-scanner .preset-pills .pill-btn[data-url]').forEach(btn => {
        btn.addEventListener('click', () => {
            input.value = btn.getAttribute('data-url');
            // Clear any lingering previous scan result
            resultCard.innerHTML = '';
            resultCard.classList.add('hidden');
        });
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const urlToScan = input.value.trim();
        if (!urlToScan) return;

        // Clear previous scan result immediately to prevent showing stale output
        resultCard.innerHTML = '';
        resultCard.classList.add('hidden');

        // Set Loading UI State
        btnScan.disabled = true;
        btnScan.innerHTML = '<span class="pulse-dot"></span> Analyzing Real-Time...';

        try {
            const res = await fetch('/api/scan-url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: urlToScan })
            });

            const json = await res.json();
            btnScan.disabled = false;
            btnScan.innerHTML = '<span>Analyze URL</span>';

            if (json.success && json.data) {
                // Ensure the returned target URL matches what was sent
                renderScanResult(resultCard, json.data, 'URL');
                // Real-time update dashboard stats and recent logs
                loadDashboardStats();
                loadRecentHistory();
            } else {
                alert(json.error || 'Failed to scan URL');
            }
        } catch (err) {
            btnScan.disabled = false;
            btnScan.innerHTML = '<span>Analyze URL</span>';
            alert('Server error while performing real-time URL scan.');
        }
    });
}

/* ==========================================================================
   4. MESSAGE ANALYZER (REAL-TIME ANALYSIS - NO STALE CACHE)
   ========================================================================== */
function initMessageAnalyzer() {
    const form = document.getElementById('message-scan-form');
    const input = document.getElementById('message-input');
    const resultCard = document.getElementById('message-result-card');
    const btnAnalyze = document.getElementById('btn-analyze-msg');

    // Preset Pills: Only populate textarea; clear old scan results
    document.querySelectorAll('#tab-message-analyzer .preset-pills .pill-btn[data-msg]').forEach(btn => {
        btn.addEventListener('click', () => {
            input.value = btn.getAttribute('data-msg');
            // Clear any lingering previous scan result
            resultCard.innerHTML = '';
            resultCard.classList.add('hidden');
        });
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const msgToScan = input.value.trim();
        if (!msgToScan) return;

        // Clear previous scan result immediately
        resultCard.innerHTML = '';
        resultCard.classList.add('hidden');

        btnAnalyze.disabled = true;
        btnAnalyze.innerHTML = '<span class="pulse-dot"></span> Analyzing Real-Time...';

        try {
            const res = await fetch('/api/analyze-message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: msgToScan })
            });

            const json = await res.json();
            btnAnalyze.disabled = false;
            btnAnalyze.innerHTML = '<span>Analyze Message</span>';

            if (json.success && json.data) {
                renderScanResult(resultCard, json.data, 'Message');
                // Real-time update dashboard stats and recent logs
                loadDashboardStats();
                loadRecentHistory();
            } else {
                alert(json.error || 'Failed to analyze message');
            }
        } catch (err) {
            btnAnalyze.disabled = false;
            btnAnalyze.innerHTML = '<span>Analyze Message</span>';
            alert('Server error while analyzing message.');
        }
    });
}

/* ==========================================================================
   5. RENDER SCAN REPORT (DIRECTLY FROM LATEST API JSON RESPONSE)
   ========================================================================== */
function renderScanResult(container, data, type) {
    // Completely reset container inner HTML before building new report
    container.innerHTML = '';

    const riskClass = getRiskClass(data.risk_level);
    const targetDisplay = data.input || data.input_summary || 'N/A';

    let indicatorsHtml = '';
    if (data.detected_indicators && data.detected_indicators.length > 0) {
        indicatorsHtml = data.detected_indicators.map(ind => `
            <div class="indicator-item ${ind.severity}">
                <div class="ind-info">
                    <strong>${escapeHtml(ind.rule)}</strong>
                    <p>${escapeHtml(ind.description)}</p>
                </div>
                <div class="ind-pts">+${ind.points} pts</div>
            </div>
        `).join('');
    } else {
        indicatorsHtml = '<p class="text-muted">No suspicious indicators or security flags were triggered.</p>';
    }

    let recsHtml = '';
    if (data.safety_recommendation && data.safety_recommendation.length > 0) {
        recsHtml = `
            <div class="recommendations-box">
                <h4>Safety Recommendations:</h4>
                <ul>
                    ${data.safety_recommendation.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    container.innerHTML = `
        <div class="result-header-flex">
            <div>
                <h3>${type} Analysis Report</h3>
                <p class="card-desc">Target: <code>${escapeHtml(targetDisplay)}</code></p>
            </div>
            <div class="score-badge-large">
                <div class="score-circle ${riskClass}">
                    ${data.risk_score}
                </div>
                <div>
                    <span class="info-title">Risk Assessment</span>
                    <div class="risk-level-tag ${riskClass}">${escapeHtml(data.risk_level)}</div>
                </div>
            </div>
        </div>

        <div class="indicators-section">
            <h4>Triggered Rule-Based Indicators (${data.detected_indicators.length}):</h4>
            ${indicatorsHtml}
        </div>

        <div class="explanation-box">
            <h4>Summary Explanation:</h4>
            <p>${escapeHtml(data.explanation)}</p>
        </div>

        ${recsHtml}

        <div class="disclaimer-box">
            ⚠️ <strong>Disclaimer:</strong> ${escapeHtml(data.disclaimer)}
        </div>
    `;

    container.classList.remove('hidden');
    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ==========================================================================
   6. SCAN HISTORY
   ========================================================================== */
function initScanHistory() {
    document.getElementById('btn-clear-history').addEventListener('click', async () => {
        if (!confirm('Are you sure you want to clear all scan history records from SQLite?')) return;

        try {
            const res = await fetch('/api/history', { method: 'DELETE' });
            const json = await res.json();
            if (json.success) {
                loadFullHistory();
                loadDashboardStats();
                loadRecentHistory();
            } else {
                alert(json.error || 'Failed to clear history');
            }
        } catch (err) {
            alert('Error connecting to server.');
        }
    });

    const searchInput = document.getElementById('history-search');
    searchInput.addEventListener('input', () => {
        const query = searchInput.value.toLowerCase();
        document.querySelectorAll('#history-table-body tr').forEach(row => {
            const text = row.innerText.toLowerCase();
            row.style.display = text.includes(query) ? '' : 'none';
        });
    });
}

async function loadFullHistory() {
    const tableBody = document.getElementById('history-table-body');
    try {
        const res = await fetch('/api/history');
        const json = await res.json();

        if (json.success && json.data.length > 0) {
            tableBody.innerHTML = json.data.map(r => `
                <tr>
                    <td>#${r.id}</td>
                    <td><span class="badge ${r.scan_type.toLowerCase()}">${r.scan_type}</span></td>
                    <td><span class="summary-code">${escapeHtml(r.input_summary)}</span></td>
                    <td><strong>${r.risk_score}</strong>/100</td>
                    <td><span class="badge ${getRiskClass(r.risk_level)}">${r.risk_level}</span></td>
                    <td>${r.detected_indicators.map(i => escapeHtml(i.rule)).join(', ') || 'None'}</td>
                    <td class="text-muted">${formatTimestamp(r.timestamp)}</td>
                </tr>
            `).join('');
        } else {
            tableBody.innerHTML = '<tr><td colspan="7" class="text-muted center">No scan history in database.</td></tr>';
        }
    } catch (err) {
        tableBody.innerHTML = '<tr><td colspan="7" class="text-muted center">Error loading history data.</td></tr>';
    }
}

/* ==========================================================================
   HELPERS
   ========================================================================== */
function getRiskClass(level) {
    if (!level) return 'low';
    const l = level.toLowerCase();
    if (l.includes('low')) return 'low';
    if (l.includes('suspicious')) return 'suspicious';
    if (l.includes('high')) return 'high';
    if (l.includes('critical')) return 'critical';
    return 'low';
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function formatTimestamp(ts) {
    if (!ts) return '';
    const date = new Date(ts);
    if (isNaN(date.getTime())) return ts;
    return date.toLocaleString();
}
