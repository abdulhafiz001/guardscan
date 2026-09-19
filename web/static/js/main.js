/**
 * GuardScan - Modern Security Operations Dashboard & WebSocket Controller
 * Comprehensive client-side state, real-time telemetry, tab switching, and modal management.
 */

let socket = null;
let currentModule = 'bola';
let activeScanId = null;
let scanFindings = [];
let totalLatencySum = 0;
let latencyCount = 0;
let lastReportPath = null;
let scanStartTime = null;
let scanTimerInterval = null;

// Module Metadata Dictionary for Examiners & Developers
const MODULE_METADATA = {
    bola: {
        title: "Broken Object Level Authorization (BOLA / IDOR)",
        code: "OWASP API1:2023",
        cwe: "CWE-639",
        severity: "High / Critical",
        cvss: "7.5 - 9.1",
        description: "Checks if an authenticated user (User B) can access or manipulate sensitive resources belonging to another user (User A) by altering resource identifiers in REST endpoints.",
        detectionMethod: "Dual-Token Context Replay + Jaccard Key Structure Similarity (≥70%) + Response Body Length Delta Heuristics to eliminate false positives on disguised 200 OK error bodies.",
        recommendedEndpoint: "https://api.yourdomain.com/v1/orders/{id}\nhttps://api.yourdomain.com/v1/users/{id}\nhttps://api.yourdomain.com/v1/invoices/101",
        testGuide: "Provide User A token (resource owner) and User B token (attacker). GuardScan compares the structural schemas of both responses.",
        badgeColor: "bg-cyan-950 text-cyan-400 border-cyan-800"
    },
    gateway: {
        title: "Fintech Gateway & Payment Webhook Insecurity",
        code: "Fintech Threat Vector",
        cwe: "CWE-347",
        severity: "Critical",
        cvss: "8.2 - 9.8",
        description: "Probes payment callback and webhook listeners (Paystack, Flutterwave, Monnify) for missing HMAC-SHA512 cryptographic signature verification and currency tampering vulnerabilities.",
        detectionMethod: "Simulates forged charge.success and transfer.completed events without signatures or with blank/invalid hash digests to test if the backend blindly credits transactions.",
        recommendedEndpoint: "https://api.yourdomain.com/api/payment/webhook\nhttps://api.yourdomain.com/api/paystack/callback\nhttps://api.yourdomain.com/api/flutterwave/webhook",
        testGuide: "Supply your webhook handler URL. GuardScan will send simulated payment payloads to check if your server enforces signature verification before returning HTTP 200.",
        badgeColor: "bg-emerald-950 text-emerald-400 border-emerald-800"
    },
    sqli: {
        title: "SQL Injection (Authentication Bypass & Data Extraction)",
        code: "OWASP A03:2021",
        cwe: "CWE-89",
        severity: "Critical",
        cvss: "9.8",
        description: "Tests login forms, search filters, and query parameters for unescaped SQL syntax that allows database tampering, authentication bypass, or data leakage.",
        detectionMethod: "Injects boolean-based, error-based, and time-based sleep payloads using browser automation and HTTP analyzers to detect reflected errors or altered execution paths.",
        recommendedEndpoint: "https://yourdomain.com/portal?username=\nhttps://yourdomain.com/api/search?q=\nhttps://yourdomain.com/items?category=",
        testGuide: "Target parameterized query parameters or login pages. GuardScan evaluates page response changes and database error reflection.",
        badgeColor: "bg-rose-950 text-rose-400 border-rose-800"
    },
    xss: {
        title: "Cross-Site Scripting (Reflected & DOM XSS)",
        code: "OWASP A03:2021",
        cwe: "CWE-79",
        severity: "High",
        cvss: "7.1",
        description: "Tests input vectors where untrusted user input is rendered into the HTML document or executed via JavaScript without proper contextual sanitization.",
        detectionMethod: "Headless Chrome DOM execution with automated dialog event listeners (alert/confirm/prompt interception) and DOM node reflection analysis.",
        recommendedEndpoint: "https://yourdomain.com/search?q=\nhttps://yourdomain.com/profile?name=\nhttps://yourdomain.com/feedback?msg=",
        testGuide: "Target search bars or reflection endpoints. GuardScan launches headless Chromium to trigger and intercept actual browser alert dialogs.",
        badgeColor: "bg-purple-950 text-purple-400 border-purple-800"
    },
    lfi: {
        title: "Local File Inclusion (LFI) & Path Traversal",
        code: "OWASP A01:2021",
        cwe: "CWE-22",
        severity: "High",
        cvss: "7.5",
        description: "Detects path traversal sequences (../, %2e%2e%2f) attempting to bypass document root restrictions and expose sensitive local system files (e.g. /etc/passwd, win.ini).",
        detectionMethod: "Tests pre-encoded and unencoded traversal sequences against file-rendering endpoints, verifying response content against file signature indicators.",
        recommendedEndpoint: "https://yourdomain.com/view?file=\nhttps://yourdomain.com/download?doc=\nhttps://yourdomain.com/render?template=",
        testGuide: "Point to parameters taking file names or templates. GuardScan tests traversal patterns and confirms if system files are exposed.",
        badgeColor: "bg-amber-950 text-amber-400 border-amber-800"
    },
    or: {
        title: "Unvalidated Open URL Redirection",
        code: "OWASP A01:2021",
        cwe: "CWE-601",
        severity: "Medium",
        cvss: "6.1",
        description: "Checks if redirection parameters (redirect, return_url, next) can be manipulated to redirect users to malicious phishing destinations.",
        detectionMethod: "Headless Chromium navigation analysis checking whether destination URL navigates externally or executes client-side meta-refresh redirection.",
        recommendedEndpoint: "https://yourdomain.com/login?redirect=\nhttps://yourdomain.com/oauth/authorize?callback=\nhttps://yourdomain.com/out?url=",
        testGuide: "Target login redirects or link shorteners. GuardScan observes if external domains (e.g. evil.com) are accepted without domain whitelisting.",
        badgeColor: "bg-blue-950 text-blue-400 border-blue-800"
    },
    crlf: {
        title: "CRLF Injection & HTTP Response Splitting",
        code: "OWASP A03:2021",
        cwe: "CWE-113",
        severity: "Medium",
        cvss: "6.5",
        description: "Probes header reflection vectors for Carriage Return (\\r) and Line Feed (\\n) characters that allow attackers to inject custom HTTP headers or split responses.",
        detectionMethod: "Tests CRLF sequences injecting Set-Cookie and HTTP/1.1 200 OK headers, confirming if injected headers are accepted by the server.",
        recommendedEndpoint: "https://yourdomain.com/track?session=\nhttps://yourdomain.com/lang?pref=\nhttps://yourdomain.com/redirect?to=",
        testGuide: "Target parameters reflected into response headers. GuardScan verifies if arbitrary cookies or response splitting can be accomplished.",
        badgeColor: "bg-teal-950 text-teal-400 border-teal-800"
    }
};

document.addEventListener('DOMContentLoaded', function() {
    initSocketIO();
    selectModule('bola');
    initMobileNav();
});

// Socket.IO Setup
function initSocketIO() {
    socket = io({
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionAttempts: 8
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
    el.innerHTML = `<span class="w-2 h-2 rounded-full ${dotColor} mr-2"></span><span>${text}</span>`;
}

// Tab Switching (Scanner, Vulnerability Guide, CLI / CI/CD)
function switchTab(tabId) {
    const tabs = ['scanner', 'guide', 'cli'];
    tabs.forEach(t => {
        const tabContent = document.getElementById(`tab-content-${t}`);
        const navBtn = document.getElementById(`nav-btn-${t}`);
        if (tabContent) {
            if (t === tabId) {
                tabContent.classList.remove('hidden');
            } else {
                tabContent.classList.add('hidden');
            }
        }
        if (navBtn) {
            if (t === tabId) {
                navBtn.classList.add('text-cyan-400', 'bg-slate-800', 'border-slate-700');
                navBtn.classList.remove('text-slate-400');
            } else {
                navBtn.classList.remove('text-cyan-400', 'bg-slate-800', 'border-slate-700');
                navBtn.classList.add('text-slate-400');
            }
        }
    });

    // Close mobile nav if open
    const mobileMenu = document.getElementById('mobileMenu');
    if (mobileMenu && !mobileMenu.classList.contains('hidden')) {
        mobileMenu.classList.add('hidden');
    }
}

function initMobileNav() {
    const toggleBtn = document.getElementById('mobileNavToggle');
    const menu = document.getElementById('mobileMenu');
    if (toggleBtn && menu) {
        toggleBtn.addEventListener('click', () => {
            menu.classList.toggle('hidden');
        });
    }
}

// Module Selection & Dynamic Guidance
function selectModule(moduleId) {
    currentModule = moduleId;
    const meta = MODULE_METADATA[moduleId];
    if (!meta) return;

    // Update pill styles
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

    // Update the live Module Guide Banner
    const infoTitle = document.getElementById('modInfoTitle');
    const infoClassification = document.getElementById('modInfoClassification');
    const infoDesc = document.getElementById('modInfoDesc');
    const infoMethod = document.getElementById('modInfoMethod');
    const infoCvss = document.getElementById('modInfoCvss');
    const infoEndpointPlaceholder = document.getElementById('modInfoEndpoint');

    if (infoTitle) infoTitle.innerText = meta.title;
    if (infoClassification) infoClassification.innerText = `${meta.code} | ${meta.cwe}`;
    if (infoDesc) infoDesc.innerText = meta.description;
    if (infoMethod) infoMethod.innerText = meta.detectionMethod;
    if (infoCvss) infoCvss.innerText = `Severity: ${meta.severity} (CVSS v3.1: ${meta.cvss})`;
    if (infoEndpointPlaceholder) infoEndpointPlaceholder.innerText = meta.recommendedEndpoint.split('\n')[0];
}

// Insert Sample Endpoints for Selected Module
function insertModuleSampleEndpoint() {
    const meta = MODULE_METADATA[currentModule];
    if (!meta) return;
    const txtArea = document.getElementById('urlsInput');
    if (txtArea) {
        txtArea.value = meta.recommendedEndpoint;
        updateUrlCount();
    }
}

// Fast Presets
function loadPreset(type) {
    const txtArea = document.getElementById('urlsInput');
    if (type === 'dvwu') {
        txtArea.value = "http://localhost:3000/portal?username=\nhttp://localhost:3000/api/search?q=\nhttp://localhost:3000/view?file=";
        selectModule('lfi');
    } else if (type === 'api') {
        txtArea.value = "https://api.yourdomain.com/v1/orders/101\nhttps://api.yourdomain.com/v1/users/42\nhttps://api.yourdomain.com/v1/profile/99";
        selectModule('bola');
        document.getElementById('tokenA').value = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_a_owner";
        document.getElementById('tokenB').value = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_b_attacker";
        document.getElementById('idVariations').value = "101, 102, 103, 104, 105";
    } else if (type === 'webhook') {
        txtArea.value = "https://api.yourdomain.com/api/payment/webhook\nhttps://api.yourdomain.com/api/paystack/callback\nhttps://api.yourdomain.com/api/flutterwave/webhook";
        selectModule('gateway');
    }
    updateUrlCount();
}

function updateUrlCount() {
    const txtArea = document.getElementById('urlsInput');
    const badge = document.getElementById('urlCountBadge');
    if (txtArea && badge) {
        const lines = txtArea.value.split('\n').filter(l => l.trim().length > 0);
        badge.innerText = `${lines.length} endpoint${lines.length === 1 ? '' : 's'}`;
    }
}

// Clear Form Inputs
function clearInputs() {
    document.getElementById('urlsInput').value = '';
    const tokenA = document.getElementById('tokenA');
    const tokenB = document.getElementById('tokenB');
    const idVars = document.getElementById('idVariations');
    if (tokenA) tokenA.value = '';
    if (tokenB) tokenB.value = '';
    if (idVars) idVars.value = '';
    updateUrlCount();
}

// Scan Launch Handler
async function handleStartScan(e) {
    e.preventDefault();

    const urlsRaw = document.getElementById('urlsInput').value.trim();
    if (!urlsRaw) {
        alert('Please enter at least one target URL or REST endpoint.');
        return;
    }
    const urls = urlsRaw.split('\n').map(u => u.trim()).filter(u => u.length > 0);
    const threads = parseInt(document.getElementById('threadRange').value) || 5;

    // Reset Metrics & UI
    scanFindings = [];
    totalLatencySum = 0;
    latencyCount = 0;
    activeScanId = 'scan_' + Date.now();
    scanStartTime = Date.now();
    updateDashboardMetrics();
    renderFindingsTable();

    // Show Progress Bar
    const progressSec = document.getElementById('progressSection');
    progressSec.classList.remove('hidden');
    progressSec.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    document.getElementById('progressBar').style.width = '0%';
    document.getElementById('progressPctText').innerText = '0%';
    document.getElementById('progressStatusLabel').innerText = `Executing active probe with ${threads} pooled workers...`;
    document.getElementById('startScanBtn').disabled = true;
    document.getElementById('scanStatusMsg').innerText = `Scanning ${urls.length} endpoint(s) with ${currentModule.toUpperCase()}...`;

    // Start timer
    if (scanTimerInterval) clearInterval(scanTimerInterval);
    scanTimerInterval = setInterval(() => {
        const elapsedSec = Math.floor((Date.now() - scanStartTime) / 1000);
        const timerEl = document.getElementById('scanTimer');
        if (timerEl) timerEl.innerText = `${elapsedSec}s elapsed`;
    }, 1000);

    // Prepare Request Body
    const payload = {
        urls: urls,
        threads: threads,
        scan_id: activeScanId
    };

    if (currentModule === 'bola') {
        payload.token_a = (document.getElementById('tokenA')?.value || '').trim();
        payload.token_b = (document.getElementById('tokenB')?.value || '').trim();
        const idVars = (document.getElementById('idVariations')?.value || '').trim();
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

// Progress Event Received from Server
function handleProgressEvent(data) {
    if (data.scan_id && activeScanId && data.scan_id !== activeScanId) return;

    const scanned = data.scanned || 0;
    const total = Math.max(data.total || 1, 1);
    const pct = Math.min(100, Math.round((scanned / total) * 100));

    const progressBar = document.getElementById('progressBar');
    if (progressBar) progressBar.style.width = `${pct}%`;
    const progressPctText = document.getElementById('progressPctText');
    if (progressPctText) progressPctText.innerText = `${pct}%`;
    const progressRatio = document.getElementById('progressRatio');
    if (progressRatio) progressRatio.innerText = `${scanned} / ${total} requests`;

    if (data.current_url) {
        const curUrl = document.getElementById('currentTestingUrl');
        if (curUrl) curUrl.innerText = `Testing: ${data.current_url}`;
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

    if (scanTimerInterval) clearInterval(scanTimerInterval);

    document.getElementById('progressBar').style.width = '100%';
    document.getElementById('progressPctText').innerText = '100%';
    document.getElementById('progressStatusLabel').innerText = 'Audit Complete! Reports & Telemetry Generated.';
    
    const totalFound = data.results ? data.results.total_found : 0;
    document.getElementById('scanStatusMsg').innerText = `Scan completed: ${totalFound} vulnerabilit${totalFound === 1 ? 'y' : 'ies'} identified.`;

    document.getElementById('startScanBtn').disabled = false;
    document.getElementById('downloadPdfBtn').disabled = false;
    document.getElementById('downloadJsonBtn').disabled = false;

    fetchLatestReportPath();
}

// Error Event
function handleErrorEvent(data) {
    if (scanTimerInterval) clearInterval(scanTimerInterval);
    document.getElementById('progressStatusLabel').innerText = 'Scan Error: ' + (data.error || 'Execution halted.');
    document.getElementById('scanStatusMsg').innerText = 'An error occurred during scan execution.';
    document.getElementById('startScanBtn').disabled = false;
}

function resetScanState() {
    if (scanTimerInterval) clearInterval(scanTimerInterval);
    document.getElementById('progressSection').classList.add('hidden');
    document.getElementById('startScanBtn').disabled = false;
    document.getElementById('scanStatusMsg').innerText = 'Ready to start scan.';
}

// Update Summary Cards & Dynamic Health Score
function updateDashboardMetrics() {
    const totalScanned = scanFindings.length;
    let critCount = 0;
    let highCount = 0;
    let medCount = 0;
    let lowCount = 0;
    let totalVuln = 0;

    scanFindings.forEach(f => {
        if (f.vulnerable) {
            totalVuln++;
            const sev = (f.severity || 'Medium').toLowerCase();
            if (sev === 'critical') critCount++;
            else if (sev === 'high') highCount++;
            else if (sev === 'medium') medCount++;
            else lowCount++;
        }
    });

    document.getElementById('metricScanned').innerText = totalScanned;
    document.getElementById('metricVulns').innerText = totalVuln;
    document.getElementById('countCrit').innerText = `${critCount} Crit`;
    document.getElementById('countHigh').innerText = `${highCount} High`;
    document.getElementById('countMed').innerText = `${medCount} Med`;

    const avgLatency = latencyCount > 0 ? (totalLatencySum / latencyCount).toFixed(2) : '0.00';
    document.getElementById('metricLatency').innerText = `${avgLatency}s`;

    // Security Posture Score Algorithm (100 base minus penalty weighted by severity)
    const penalty = (critCount * 30) + (highCount * 15) + (medCount * 8) + (lowCount * 3);
    const score = Math.max(0, 100 - penalty);
    document.getElementById('metricScore').innerText = score;

    let grade = 'Grade A (Secure)';
    let gradeColor = 'text-emerald-400';
    let barColor = 'bg-emerald-500';

    if (score < 50) { grade = 'Grade F (Critical Risk)'; gradeColor = 'text-rose-500'; barColor = 'bg-rose-500'; }
    else if (score < 70) { grade = 'Grade D (High Risk)'; gradeColor = 'text-orange-400'; barColor = 'bg-orange-400'; }
    else if (score < 85) { grade = 'Grade B (Moderate Risk)'; gradeColor = 'text-cyan-400'; barColor = 'bg-cyan-400'; }

    const gradeEl = document.getElementById('metricGrade');
    if (gradeEl) gradeEl.innerText = `/ 100 (${grade})`;
    document.getElementById('metricScore').className = `text-3xl font-black ${gradeColor}`;
    const scoreBar = document.getElementById('metricScoreBar');
    if (scoreBar) {
        scoreBar.style.width = `${score}%`;
        scoreBar.className = `${barColor} h-full rounded-full transition-all duration-500`;
    }
}

// Render Interactive Vulnerability Matrix
function renderFindingsTable() {
    const tbody = document.getElementById('findingsTableBody');
    const filter = document.getElementById('severityFilter').value;
    const searchTerm = (document.getElementById('tableSearchInput')?.value || '').toLowerCase();

    const filtered = scanFindings.filter(f => {
        // Severity filter
        if (filter === 'vuln-only' && !f.vulnerable) return false;
        if (filter === 'critical' && (!f.vulnerable || (f.severity || '').toLowerCase() !== 'critical')) return false;
        if (filter === 'high' && (!f.vulnerable || (f.severity || '').toLowerCase() !== 'high')) return false;
        if (filter === 'medium' && (!f.vulnerable || (f.severity || '').toLowerCase() !== 'medium')) return false;

        // Search filter
        if (searchTerm) {
            const urlMatch = (f.url || '').toLowerCase().includes(searchTerm);
            const titleMatch = (f.title || '').toLowerCase().includes(searchTerm);
            const payloadMatch = String(f.payload || '').toLowerCase().includes(searchTerm);
            if (!urlMatch && !titleMatch && !payloadMatch) return false;
        }

        return true;
    });

    const badgeTotal = document.getElementById('findingsBadgeTotal');
    if (badgeTotal) badgeTotal.innerText = `${filtered.length} finding${filtered.length === 1 ? '' : 's'}`;

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr id="emptyFindingsRow">
                <td colspan="6" class="py-12 text-center text-slate-500">
                    <i class="fa-solid fa-radar text-3xl mb-3 block text-slate-600"></i>
                    ${scanFindings.length === 0 
                        ? 'No active scan findings yet. Launch a scan above to populate live findings.' 
                        : 'No findings match the current filter or search criteria.'}
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

        let sevBadge = `<span class="px-2.5 py-1 rounded-md text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">INFO</span>`;
        if (sev === 'CRITICAL') {
            sevBadge = `<span class="px-2.5 py-1 rounded-md text-[10px] font-bold bg-rose-950/80 text-rose-400 border border-rose-800 shadow-sm shadow-rose-900/30">CRITICAL (${cvss})</span>`;
        } else if (sev === 'HIGH') {
            sevBadge = `<span class="px-2.5 py-1 rounded-md text-[10px] font-bold bg-orange-950/80 text-orange-400 border border-orange-800 shadow-sm shadow-orange-900/30">HIGH (${cvss})</span>`;
        } else if (sev === 'MEDIUM') {
            sevBadge = `<span class="px-2.5 py-1 rounded-md text-[10px] font-bold bg-amber-950/80 text-amber-400 border border-amber-800 shadow-sm shadow-amber-900/30">MED (${cvss})</span>`;
        }

        const statusBadge = isVuln
            ? `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-black bg-rose-950 text-rose-400 border border-rose-800"><i class="fa-solid fa-triangle-exclamation mr-1.5"></i>VULNERABLE</span>`
            : `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-800/60"><i class="fa-solid fa-check mr-1.5"></i>SAFE</span>`;

        return `
            <tr class="hover:bg-slate-800/40 transition">
                <td class="py-3 px-4 font-mono text-[11px] whitespace-nowrap">${statusBadge}</td>
                <td class="py-3 px-4 whitespace-nowrap">${sevBadge}</td>
                <td class="py-3 px-4 font-semibold text-slate-200">${escapeHtml(title)}</td>
                <td class="py-3 px-4 font-mono text-[11px] text-cyan-400 truncate max-w-xs" title="${escapeHtml(url)}">${escapeHtml(url)}</td>
                <td class="py-3 px-4 font-mono text-slate-400 text-[11px] whitespace-nowrap">${latency}</td>
                <td class="py-3 px-4 text-right whitespace-nowrap">
                    <button onclick="openModal(${idx})" class="inline-flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] font-semibold transition hover:border-cyan-500 shadow-sm">
                        <i class="fa-solid fa-magnifying-glass text-cyan-400 text-[10px]"></i>
                        <span>Inspect</span>
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function filterFindings() {
    renderFindingsTable();
}

// Enterprise Vulnerability Inspector Modal
function openModal(idx) {
    const finding = scanFindings[idx];
    if (!finding) return;

    const sev = (finding.severity || (finding.vulnerable ? 'High' : 'Info')).toUpperCase();
    const cvss = finding.cvss_score !== undefined ? finding.cvss_score : (finding.vulnerable ? 7.5 : 0.0);

    document.getElementById('modalTitle').innerText = finding.title || 'Security Finding Details';
    document.getElementById('modalUrl').innerText = finding.url || '';
    document.getElementById('modalClassification').innerText = `${finding.cwe_id || 'CWE-200'} | ${finding.owasp_category || 'A01:2021'} | CVSS v3.1: ${cvss} (${sev})`;
    document.getElementById('modalPayload').innerText = finding.payload || 'N/A';
    document.getElementById('modalEvidence').innerText = finding.evidence || 'No specific raw telemetry captured.';
    document.getElementById('modalRemediation').innerText = finding.remediation || 'Apply standard defense-in-depth sanitization and authorization controls.';

    const sevBadge = document.getElementById('modalSevBadge');
    if (sevBadge) {
        sevBadge.innerText = `${sev} | CVSS ${cvss}`;
        if (sev === 'CRITICAL') sevBadge.className = 'px-3 py-1 rounded-md text-xs font-black bg-rose-950 text-rose-400 border border-rose-800';
        else if (sev === 'HIGH') sevBadge.className = 'px-3 py-1 rounded-md text-xs font-black bg-orange-950 text-orange-400 border border-orange-800';
        else if (sev === 'MEDIUM') sevBadge.className = 'px-3 py-1 rounded-md text-xs font-black bg-amber-950 text-amber-400 border border-amber-800';
        else sevBadge.className = 'px-3 py-1 rounded-md text-xs font-bold bg-slate-800 text-slate-400 border border-slate-700';
    }

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

// Copy Code from Modal
function copyModalCode() {
    const code = document.getElementById('modalCode').innerText;
    navigator.clipboard.writeText(code).then(() => {
        const btn = document.getElementById('copyCodeBtn');
        if (btn) {
            btn.innerHTML = '<i class="fa-solid fa-check text-emerald-400"></i> Copied!';
            setTimeout(() => {
                btn.innerHTML = '<i class="fa-solid fa-copy"></i> Copy Code';
            }, 2000);
        }
    });
}

// Copy Generic Text
function copyToClipboard(elementId, btnElement) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const text = el.innerText || el.textContent;
    navigator.clipboard.writeText(text).then(() => {
        if (btnElement) {
            const originalHTML = btnElement.innerHTML;
            btnElement.innerHTML = '<i class="fa-solid fa-check text-emerald-400"></i> Copied!';
            setTimeout(() => {
                btnElement.innerHTML = originalHTML;
            }, 2000);
        }
    });
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
