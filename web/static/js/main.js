// GuardScan Modern Dashboard State & WebSocket Handler

let socket = null;
let currentModule = 'bola';
let activeScanId = null;
let scanFindings = [];
let totalLatencySum = 0;
let latencyCount = 0;
let lastReportPath = null;

document.addEventListener('DOMContentLoaded', function() {
    initSocketIO();
    selectModule('bola');
});

// Socket.IO Setup
function initSocketIO() {
    socket = io({
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionAttempts: 5
    });

    socket.on('connect', () => {
        updateConnStatus('connected', 'System Online (WebSocket)');
    });

    socket.on('disconnect', () => {
        updateConnStatus('disconnected', 'Disconnected');
    });

    socket.on('connect_error', () => {
        updateConnStatus('error', 'Connection Error');
    });

    socket.on('scan_progress', (data) => {
        handleProgressEvent(data);
    });

    socket.on('scan_complete', (data) => {
        handleCompleteEvent(data);
    });

    socket.on('scan_error', (data) => {
        handleErrorEvent(data);
    });
}

function updateConnStatus(status, text) {
    const el = document.getElementById('connectionStatus');
    if (!el) return;
    let dotColor = 'bg-slate-500';
    if (status === 'connected') dotColor = 'bg-emerald-400 animate-pulse';
    else if (status === 'error' || status === 'disconnected') dotColor = 'bg-rose-500';
    el.innerHTML = `<span class="w-2 h-2 rounded-full ${dotColor} mr-2"></span>${text}`;
}

// Module Selector
function selectModule(moduleId) {
    currentModule = moduleId;
    document.querySelectorAll('.module-pill').forEach(btn => {
        btn.classList.remove('bg-cyan-950/40', 'border-cyan-500', 'text-cyan-300', 'shadow-sm', 'shadow-cyan-500/10');
        btn.classList.add('border-slate-800', 'bg-slate-950/50', 'text-slate-300');
    });

    const activeBtn = document.getElementById(`mod-${moduleId}`);
    if (activeBtn) {
        activeBtn.classList.remove('border-slate-800', 'bg-slate-950/50', 'text-slate-300');
        activeBtn.classList.add('bg-cyan-950/40', 'border-cyan-500', 'text-cyan-300', 'shadow-sm', 'shadow-cyan-500/10');
    }

    // Toggle BOLA dual token section
    const bolaSec = document.getElementById('bolaConfigSection');
    if (bolaSec) {
        if (moduleId === 'bola') {
            bolaSec.classList.remove('hidden');
        } else {
            bolaSec.classList.add('hidden');
        }
    }
}

// Preset Targets
function loadPreset(type) {
    const txtArea = document.getElementById('urlsInput');
    if (type === 'dvwu') {
        txtArea.value = "http://localhost:3000/portal?username=\nhttp://localhost:3000/api/search?q=\nhttp://localhost:3000/view?file=";
        selectModule('lfi');
    } else if (type === 'api') {
        txtArea.value = "http://localhost:5000/api/v1/orders/101\nhttp://localhost:5000/api/v1/users/42\nhttp://localhost:5000/api/profile/99";
        selectModule('bola');
        document.getElementById('tokenA').value = "Bearer user_a_valid_jwt_token_sample_123";
        document.getElementById('tokenB').value = "Bearer user_b_unauthorized_attacker_token_456";
        document.getElementById('idVariations').value = "101, 102, 103, 104";
    } else if (type === 'webhook') {
        txtArea.value = "http://localhost:5000/api/payment/webhook\nhttp://localhost:5000/api/paystack/callback\nhttp://localhost:5000/api/flutterwave/webhook";
        selectModule('gateway');
    }
}

// Scan Launch Handler
async function handleStartScan(e) {
    e.preventDefault();

    const urlsRaw = document.getElementById('urlsInput').value.trim();
    if (!urlsRaw) {
        alert('Please provide at least one target URL or API endpoint.');
        return;
    }
    const urls = urlsRaw.split('\n').map(u => u.trim()).filter(u => u.length > 0);
    const threads = parseInt(document.getElementById('threadRange').value) || 5;

    // Reset Metrics & UI
    scanFindings = [];
    totalLatencySum = 0;
    latencyCount = 0;
    activeScanId = 'scan_' + Date.now();
    updateDashboardMetrics();
    renderFindingsTable();

    // Show Progress Bar
    document.getElementById('progressSection').classList.remove('hidden');
    document.getElementById('progressBar').style.width = '0%';
    document.getElementById('progressPctText').innerText = '0%';
    document.getElementById('startScanBtn').disabled = true;
    document.getElementById('scanStatusMsg').innerText = `Running ${currentModule.toUpperCase()} scan...`;

    // Prepare Request Body
    const payload = {
        urls: urls,
        threads: threads,
        scan_id: activeScanId
    };

    if (currentModule === 'bola') {
        payload.token_a = document.getElementById('tokenA').value.trim();
        payload.token_b = document.getElementById('tokenB').value.trim();
        const idVars = document.getElementById('idVariations').value.trim();
        payload.id_variations = idVars ? idVars.split(',').map(s => s.trim()) : [];
    }

    try {
        const response = await fetch(`/api/scan/${currentModule}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const resData = await response.json();
        if (!resData.success) {
            alert('Scan initiation failed: ' + (resData.error || 'Unknown error'));
            resetScanState();
        }
    } catch (err) {
        alert('Request failed: ' + err.message);
        resetScanState();
    }
}

// Progress Event Received
function handleProgressEvent(data) {
    if (data.scan_id && activeScanId && data.scan_id !== activeScanId) return;

    const scanned = data.scanned || 0;
    const total = Math.max(data.total || 1, 1);
    const pct = Math.min(100, Math.round((scanned / total) * 100));

    document.getElementById('progressBar').style.width = `${pct}%`;
    document.getElementById('progressPctText').innerText = `${pct}%`;
    document.getElementById('progressRatio').innerText = `${scanned} / ${total}`;

    if (data.current_url) {
        document.getElementById('currentTestingUrl').innerText = `Target: ${data.current_url}`;
    }

    // Process findings
    if (data.results && Array.isArray(data.results)) {
        data.results.forEach(res => {
            scanFindings.push(res);
            if (res.response_time) {
                totalLatencySum += parseFloat(res.response_time);
                latencyCount++;
            }
        });
        updateDashboardMetrics();
        renderFindingsTable();
    }
}

// Complete Event
function handleCompleteEvent(data) {
    if (data.scan_id && activeScanId && data.scan_id !== activeScanId) return;

    document.getElementById('progressBar').style.width = '100%';
    document.getElementById('progressPctText').innerText = '100%';
    document.getElementById('progressStatusLabel').innerText = 'Scan Complete. Reports Generated!';
    document.getElementById('scanStatusMsg').innerText = `Scan completed: ${data.results ? data.results.total_found : 0} vulnerabilities detected.`;

    // Re-enable start button
    document.getElementById('startScanBtn').disabled = false;

    // Enable PDF and JSON download buttons
    document.getElementById('downloadPdfBtn').disabled = false;
    document.getElementById('downloadJsonBtn').disabled = false;

    // Fetch latest reports to get exact file path
    fetchLatestReportPath();
}

// Error Event
function handleErrorEvent(data) {
    document.getElementById('progressStatusLabel').innerText = 'Scan Error: ' + (data.error || 'Execution stopped.');
    document.getElementById('scanStatusMsg').innerText = 'Error occurred during scan.';
    document.getElementById('startScanBtn').disabled = false;
}

function resetScanState() {
    document.getElementById('progressSection').classList.add('hidden');
    document.getElementById('startScanBtn').disabled = false;
    document.getElementById('scanStatusMsg').innerText = 'Ready to start scan.';
}

// Update Summary Cards
function updateDashboardMetrics() {
    const totalScanned = scanFindings.length;
    let critCount = 0;
    let highCount = 0;
    let medCount = 0;
    let totalVuln = 0;

    scanFindings.forEach(f => {
        if (f.vulnerable) {
            totalVuln++;
            const sev = (f.severity || 'Medium').toLowerCase();
            if (sev === 'critical') critCount++;
            else if (sev === 'high') highCount++;
            else medCount++;
        }
    });

    document.getElementById('metricScanned').innerText = totalScanned;
    document.getElementById('metricVulns').innerText = totalVuln;
    document.getElementById('countCrit').innerText = `${critCount} Crit`;
    document.getElementById('countHigh').innerText = `${highCount} High`;
    document.getElementById('countMed').innerText = `${medCount} Med`;

    // Latency
    const avgLatency = latencyCount > 0 ? (totalLatencySum / latencyCount).toFixed(2) : '0.00';
    document.getElementById('metricLatency').innerText = `${avgLatency}s`;

    // Security Score
    const penalty = (critCount * 30) + (highCount * 15) + (medCount * 8);
    const score = Math.max(0, 100 - penalty);
    document.getElementById('metricScore').innerText = score;

    let grade = 'Grade A';
    let gradeColor = 'text-emerald-400';
    let barColor = 'bg-emerald-500';

    if (score < 50) { grade = 'Grade F'; gradeColor = 'text-rose-500'; barColor = 'bg-rose-500'; }
    else if (score < 70) { grade = 'Grade D'; gradeColor = 'text-orange-400'; barColor = 'bg-orange-400'; }
    else if (score < 85) { grade = 'Grade B'; gradeColor = 'text-cyan-400'; barColor = 'bg-cyan-400'; }

    const gradeEl = document.getElementById('metricGrade');
    gradeEl.innerText = `/ 100 (${grade})`;
    document.getElementById('metricScore').className = `text-3xl font-black ${gradeColor}`;
    const scoreBar = document.getElementById('metricScoreBar');
    scoreBar.style.width = `${score}%`;
    scoreBar.className = `${barColor} h-full rounded-full transition-all duration-500`;
}

// Render Vulnerability Matrix
function renderFindingsTable() {
    const tbody = document.getElementById('findingsTableBody');
    const filter = document.getElementById('severityFilter').value;

    const filtered = scanFindings.filter(f => {
        if (filter === 'vuln-only') return f.vulnerable;
        if (filter === 'critical') return f.vulnerable && (f.severity || '').toLowerCase() === 'critical';
        if (filter === 'high') return f.vulnerable && (f.severity || '').toLowerCase() === 'high';
        if (filter === 'medium') return f.vulnerable && (f.severity || '').toLowerCase() === 'medium';
        return true;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr id="emptyFindingsRow">
                <td colspan="6" class="py-10 text-center text-slate-500">
                    No findings matching current filter.
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = filtered.map((finding, idx) => {
        const isVuln = finding.vulnerable;
        const sev = (finding.severity || (isVuln ? 'High' : 'Info')).toUpperCase();
        const cvss = finding.cvss_score !== undefined ? finding.cvss_score : (isVuln ? 7.5 : 0.0);
        const title = finding.title || 'Security Probe';
        const url = finding.url || '';
        const latency = finding.response_time ? `${finding.response_time}s` : '-';

        let sevBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">INFO</span>`;
        if (sev === 'CRITICAL') {
            sevBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-800">CRITICAL (${cvss})</span>`;
        } else if (sev === 'HIGH') {
            sevBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-950 text-orange-400 border border-orange-800">HIGH (${cvss})</span>`;
        } else if (sev === 'MEDIUM') {
            sevBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-400 border border-amber-800">MED (${cvss})</span>`;
        }

        const statusBadge = isVuln
            ? `<span class="inline-flex items-center text-rose-400 font-bold"><i class="fa-solid fa-circle-xmark mr-1.5"></i>VULNERABLE</span>`
            : `<span class="inline-flex items-center text-emerald-400 font-medium"><i class="fa-solid fa-circle-check mr-1.5"></i>SAFE</span>`;

        return `
            <tr class="hover:bg-slate-800/40 transition">
                <td class="py-3 px-4 font-mono text-[11px]">${statusBadge}</td>
                <td class="py-3 px-4">${sevBadge}</td>
                <td class="py-3 px-4 font-semibold text-slate-200">${escapeHtml(title)}</td>
                <td class="py-3 px-4 font-mono text-[11px] text-cyan-400 truncate max-w-xs" title="${escapeHtml(url)}">${escapeHtml(url)}</td>
                <td class="py-3 px-4 font-mono text-slate-400 text-[11px]">${latency}</td>
                <td class="py-3 px-4 text-right">
                    <button onclick="openModal(${idx})" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-[11px] font-medium transition">
                        Inspect
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function filterFindings() {
    renderFindingsTable();
}

// Finding Detail Modal
function openModal(idx) {
    const finding = scanFindings[idx];
    if (!finding) return;

    document.getElementById('modalTitle').innerText = finding.title || 'Vulnerability Finding Details';
    document.getElementById('modalUrl').innerText = finding.url || '';
    document.getElementById('modalClassification').innerText = `${finding.cwe_id || 'CWE-200'} | ${finding.owasp_category || 'A01:2021'} | Method: ${finding.method || 'Probe'}`;
    document.getElementById('modalEvidence').innerText = finding.evidence || 'No specific raw evidence captured.';
    document.getElementById('modalRemediation').innerText = finding.remediation || 'Apply standard defense-in-depth sanitization and authorization checks.';

    const codeContainer = document.getElementById('modalCodeContainer');
    if (finding.remediation_code) {
        codeContainer.classList.remove('hidden');
        document.getElementById('modalCode').innerText = finding.remediation_code;
    } else {
        codeContainer.classList.add('hidden');
    }

    document.getElementById('detailModal').classList.remove('hidden');
}

function closeModal() {
    document.getElementById('detailModal').classList.add('hidden');
}

// Fetch Reports & Trigger Downloads
async function fetchLatestReportPath() {
    try {
        const res = await fetch('/api/reports');
        const data = await res.json();
        if (data.reports && data.reports.length > 0) {
            lastReportPath = data.reports[0].path;
        }
    } catch (e) {
        console.error('Error fetching latest report:', e);
    }
}

function triggerLatestExport(format) {
    if (!lastReportPath) {
        window.location.href = '/reports';
        return;
    }
    window.location.href = `/api/reports/download?path=${encodeURIComponent(lastReportPath)}&format=${format}`;
}

function escapeHtml(text) {
    if (!text) return '';
    return text.toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
