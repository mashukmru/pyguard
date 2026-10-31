/**
 * PyGuard Web Dashboard – Client-side Application
 * Handles tab navigation, API calls, live log feed, and all UI interactions.
 */

// ============================================================
// State
// ============================================================
let isFirewallRunning = false;
let liveLogInterval = null;
let lastLogCount = 0;
let countries = [];
let blockedCountries = [];
let firewallStateKnown = false;
let firewallActionInProgress = false;
let logsRequestInProgress = false;
let logsReloadQueued = false;

// ============================================================
// Tab Navigation
// ============================================================
const navItems = document.querySelectorAll('.nav-item');
const tabs = document.querySelectorAll('.tab-content');
const pageTitle = document.getElementById('page-title');

const tabTitles = {
    dashboard: 'Dashboard',
    rules: 'Rules Management',
    simulator: 'Attack Simulator',
    logs: 'Log Viewer',
};

navItems.forEach(item => {
    item.addEventListener('click', () => {
        const tabId = item.dataset.tab;
        navItems.forEach(n => n.classList.remove('active'));
        tabs.forEach(t => t.classList.remove('active'));
        item.classList.add('active');
        document.getElementById(`tab-${tabId}`).classList.add('active');
        pageTitle.textContent = tabTitles[tabId] || 'Dashboard';

        // Load data when switching tabs
        if (tabId === 'rules') {
            loadRules();
            loadGeoRules();
        }
        if (tabId === 'simulator') loadTestableRules();
        if (tabId === 'logs') loadLogs();
    });
});

// ============================================================
// API Helpers
// ============================================================
async function api(endpoint, options = {}) {
    try {
        const res = await fetch(`/api${endpoint}`, {
            headers: { 'Content-Type': 'application/json' },
            ...options,
        });
        let data;
        try {
            data = await res.json();
        } catch {
            throw new Error(`Server returned an unreadable response (HTTP ${res.status})`);
        }
        if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
        return data;
    } catch (err) {
        console.error(`API error [${endpoint}]:`, err);
        throw err;
    }
}

// ============================================================
// Toast Notifications
// ============================================================
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// ============================================================
// Firewall Toggle
// ============================================================
const toggleSwitch = document.getElementById('toggle-switch');
const toggleLabel = document.getElementById('toggle-label');

toggleSwitch.addEventListener('click', async () => {
    if (!firewallStateKnown || firewallActionInProgress) return;
    firewallActionInProgress = true;
    const expectedRunning = !isFirewallRunning;
    toggleSwitch.disabled = true;
    try {
        if (!expectedRunning) {
            await api('/stop', { method: 'POST' });
        } else {
            await api('/start', { method: 'POST' });
        }
        await refreshStatus();
        if (!firewallStateKnown) {
            showToast('Monitoring request completed, but its current state could not be confirmed.', 'error');
        } else if (isFirewallRunning === expectedRunning) {
            showToast(expectedRunning ? 'Packet monitoring started' : 'Packet monitoring stopped', expectedRunning ? 'success' : 'info');
        } else {
            showToast('The monitoring state did not change. Check the status and capture requirements.', 'error');
        }
    } catch (err) {
        await refreshStatus();
        showToast(`Error: ${err.message}`, 'error');
    } finally {
        firewallActionInProgress = false;
        toggleSwitch.disabled = !firewallStateKnown;
    }
});

async function refreshStatus() {
    try {
        const data = await api('/status');
        firewallStateKnown = true;
        isFirewallRunning = data.running;
        updateStatusUI(data);
        return true;
    } catch {
        firewallStateKnown = false;
        updateStatusUI(null);
        return false;
    }
}

function updateStatusUI(data) {
    if (!data) {
        toggleLabel.textContent = 'Monitoring status unavailable';
        toggleSwitch.classList.remove('active');
        toggleSwitch.classList.add('unavailable');
        toggleSwitch.removeAttribute('aria-checked');
        toggleSwitch.removeAttribute('aria-busy');
        toggleSwitch.disabled = true;
        document.getElementById('stat-status').textContent = 'Unavailable';
        document.getElementById('stat-scapy').textContent = 'Unknown';
        return;
    }
    toggleSwitch.classList.remove('unavailable');
    toggleSwitch.removeAttribute('aria-busy');
    toggleSwitch.setAttribute('aria-checked', String(data.running));
    toggleSwitch.disabled = firewallActionInProgress;
    // Toggle
    if (data.running) {
        toggleSwitch.classList.add('active');
        toggleLabel.textContent = 'Monitoring ON';
    } else {
        toggleSwitch.classList.remove('active');
        toggleLabel.textContent = 'Monitoring OFF';
    }

    // Sidebar status
    const sidebarStatus = document.getElementById('sidebar-status');
    const dot = sidebarStatus.querySelector('.status-dot');
    const label = sidebarStatus.querySelector('span:last-child');
    if (data.running) {
        dot.className = 'status-dot online';
        label.textContent = 'Running';
    } else {
        dot.className = 'status-dot offline';
        label.textContent = 'Offline';
    }

    // Stats
    document.getElementById('stat-status').textContent = data.running ? 'Active' : 'Offline';
    document.getElementById('stat-status').style.color = data.running ? 'var(--accent-green)' : 'var(--accent-red)';
    document.getElementById('stat-scapy').textContent = data.scapy_available ? 'Installed' : 'Missing';
    document.getElementById('stat-scapy').style.color = data.scapy_available ? 'var(--accent-green)' : 'var(--accent-red)';
}

// ============================================================
// Rules
// ============================================================
async function loadRules() {
    try {
        const data = await api('/rules');
        renderRules(data.rules);
        document.getElementById('stat-rules').textContent = data.rules.length;
    } catch (err) {
        showToast(`Failed to load rules: ${err.message}`, 'error');
    }
}

function renderRules(rules) {
    const tbody = document.getElementById('rules-tbody');
    if (!rules.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="table-empty">No rules configured.</td></tr>';
        return;
    }
    tbody.innerHTML = rules.map(r => `
        <tr>
            <td><strong>${esc(r.id)}</strong></td>
            <td><span class="action-badge ${r.action}">${r.action}</span></td>
            <td>${esc(r.source_ip || '--')}</td>
            <td>${esc(r.dst_ip || '--')}</td>
            <td>${r.dst_port ? r.dst_port.join(', ') : '--'}</td>
            <td>${esc(r.protocol || 'any')}</td>
            <td>${esc(r.description || '--')}</td>
            <td><button class="btn btn-danger" onclick="deleteRule('${esc(r.id)}')">Remove</button></td>
        </tr>
    `).join('');
}

document.getElementById('add-rule-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const body = {
        id: document.getElementById('rule-id').value.trim(),
        action: document.getElementById('rule-action').value,
        source_ip: document.getElementById('rule-source-ip').value.trim() || undefined,
        dst_ip: document.getElementById('rule-dst-ip').value.trim() || undefined,
        dst_port: parseInt(document.getElementById('rule-dst-port').value) || undefined,
        protocol: document.getElementById('rule-protocol').value || undefined,
        max_pps: parseInt(document.getElementById('rule-max-pps').value) || undefined,
        description: document.getElementById('rule-description').value.trim(),
    };
    if (!body.id) { showToast('Rule ID is required', 'error'); return; }
    try {
        await api('/rules', { method: 'POST', body: JSON.stringify(body) });
        showToast(`Rule '${body.id}' added`, 'success');
        document.getElementById('add-rule-form').reset();
        loadRules();
    } catch (err) {
        showToast(`Failed to add rule: ${err.message}`, 'error');
    }
});

async function deleteRule(ruleId) {
    try {
        await api(`/rules/${encodeURIComponent(ruleId)}`, { method: 'DELETE' });
        showToast(`Rule '${ruleId}' removed`, 'success');
        loadRules();
    } catch (err) {
        showToast(`Failed to remove rule: ${err.message}`, 'error');
    }
}

const btnRefreshRules = document.getElementById('btn-refresh-rules');
if (btnRefreshRules) btnRefreshRules.addEventListener('click', loadRules);

// ============================================================
// Geo Rules
// ============================================================
async function loadGeoRules() {
    try {
        // Load countries.json if not already loaded
        if (countries.length === 0) {
            const res = await fetch('/static/countries.json');
            countries = await res.json();
            populateCountrySelect();
        }

        const data = await api('/geo-rules');
        blockedCountries = data.blocked_countries;
        renderBlockedCountries();
    } catch (err) {
        showToast(`Failed to load geo rules: ${err.message}`, 'error');
    }
}

function populateCountrySelect() {
    const select = document.getElementById('geo-country-select');
    if (!select) return;
    
    select.innerHTML = '<option value="">-- Select Country --</option>' + 
        countries.map(c => `<option value="${c.code}">${esc(c.name)} (${c.code})</option>`).join('');
}

function renderBlockedCountries() {
    const container = document.getElementById('blocked-countries-container');
    if (!container) return;

    if (blockedCountries.length === 0) {
        container.innerHTML = '<div class="table-empty country-empty"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10Z"/></svg><span>No countries currently blocked.</span></div>';
        return;
    }

    container.innerHTML = blockedCountries.map(code => {
        const country = countries.find(c => c.code === code) || { name: code, code };
        return `
            <div class="country-chip">
                <span>${esc(country.name)} (${code})</span>
                <button class="btn-remove-geo" type="button" onclick="unblockCountry('${esc(code)}')" title="Unblock ${esc(country.name)}" aria-label="Unblock ${esc(country.name)}">
                    <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="18" y1="6" x2="6" y2="18"></line>
                        <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                </button>
            </div>
        `;
    }).join('');
}

const btnBlockCountry = document.getElementById('btn-block-country');
if (btnBlockCountry) {
    btnBlockCountry.addEventListener('click', async () => {
        const select = document.getElementById('geo-country-select');
        const code = select.value;
        if (!code) {
            showToast('Please select a country', 'error');
            return;
        }

        try {
            await api('/geo-rules/block', {
                method: 'POST',
                body: JSON.stringify({ country_code: code })
            });
            showToast(`Blocked traffic from ${code}`, 'success');
            select.value = '';
            loadGeoRules();
        } catch (err) {
            showToast(`Failed to block country: ${err.message}`, 'error');
        }
    });
}

async function unblockCountry(code) {
    try {
        await api('/geo-rules/unblock', {
            method: 'POST',
            body: JSON.stringify({ country_code: code })
        });
        showToast(`Unblocked traffic from ${code}`, 'success');
        loadGeoRules();
    } catch (err) {
        showToast(`Failed to unblock country: ${err.message}`, 'error');
    }
}

window.unblockCountry = unblockCountry;

// ============================================================
// Simulator – Network Attacks
// ============================================================
const simulatorIcons = {
    play: '<polygon points="6 3 20 12 6 21 6 3"/>',
    activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
    alert: '<path d="m10.3 3.9-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3.1l-8-14a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4m0 4h.01"/>',
    check: '<circle cx="12" cy="12" r="10"/><path d="m8 12 3 3 5-6"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="M12 8v4m0 4h.01"/>',
    arrow: '<path d="M5 12h14m-7-7 7 7-7 7"/>',
};

function simulatorIcon(name, className = '') {
    return `<svg class="${className}" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${simulatorIcons[name]}</svg>`;
}

async function runSimulation(type, btnElement) {
    btnElement.disabled = true;
    const origText = btnElement.textContent;
    btnElement.textContent = 'Running...';
    const resultEl = document.getElementById(`result-${type}`);
    resultEl.classList.remove('show');

    const body = { type, target: '127.0.0.1' };
    if (type === 'brute_force') body.port = parseInt(document.getElementById('bf-port').value) || 22;
    if (type === 'flood') body.duration = parseFloat(document.getElementById('flood-duration').value) || 2;

    try {
        const data = await api('/simulate', { method: 'POST', body: JSON.stringify(body) });
        resultEl.innerHTML = formatSimResult(type, data.result);
        resultEl.classList.add('show');
        showToast(`${type.replace('_', ' ')} simulation completed`, 'success');
    } catch (err) {
        resultEl.innerHTML = `<span style="color:var(--accent-red)">Error: ${esc(err.message)}</span>`;
        resultEl.classList.add('show');
        showToast(`Simulation failed: ${err.message}`, 'error');
    } finally {
        btnElement.disabled = false;
        btnElement.textContent = origText;
    }
}

function formatSimResult(type, result) {
    if (result.error) return `<span class="sim-inline-error">${simulatorIcon('alert')} ${esc(result.error)}</span>`;
    let html = '';
    if (type === 'port_scan') {
        html = `<div><strong>Open ports:</strong> ${result.open_ports.length ? result.open_ports.join(', ') : 'None'}</div>
                <div><strong>Closed:</strong> ${result.closed_count}</div>
                <div><strong>Duration:</strong> ${result.duration_sec}s</div>`;
    } else if (type === 'brute_force') {
        html = `<div><strong>Attempts:</strong> ${result.attempts}</div>
                <div><strong>Successful:</strong> ${result.success_count}</div>
                <div><strong>Duration:</strong> ${result.duration_sec}s</div>`;
    } else {
        html = `<div><strong>Packets sent:</strong> ${result.packets_sent}</div>
                <div><strong>Duration:</strong> ${result.duration_sec}s</div>`;
    }
    return html;
}

// Make globally accessible
window.runSimulation = runSimulation;

// ============================================================
// Simulator – Dynamic Rule Testing
// ============================================================
async function loadTestableRules() {
    const grid = document.getElementById('rule-test-grid');
    try {
        const data = await api('/rules');
        if (!data.rules.length) {
            grid.innerHTML = '<div class="log-empty">No rules configured. Add rules in the Rules tab first.</div>';
            return;
        }
        grid.innerHTML = data.rules.map(r => {
            const metaTags = [];
            if (r.source_ip) metaTags.push(`src: ${r.source_ip}`);
            if (r.dst_ip) metaTags.push(`dst: ${r.dst_ip}`);
            if (r.dst_port) metaTags.push(`port: ${r.dst_port.join(',')}`);
            if (r.protocol) metaTags.push(`proto: ${r.protocol}`);
            if (r.max_packets_per_second) metaTags.push(`max: ${r.max_packets_per_second} pps`);
            if (!metaTags.length) metaTags.push('any traffic');

            return `<div class="rule-test-card" id="test-card-${r.id}">
                <div class="rule-test-header">
                    <span class="rule-test-name">${esc(r.id)}</span>
                    <span class="action-badge ${r.action}">${r.action}</span>
                </div>
                <div class="rule-test-desc">${esc(r.description || 'No description')}</div>
                <div class="rule-test-meta">${metaTags.map(t => `<span class="meta-tag">${esc(t)}</span>`).join('')}</div>
                <div class="rule-test-actions">
                    <span class="verdict-container" id="verdict-${r.id}"></span>
                    <button class="btn btn-accent btn-sm" onclick="testRule('${esc(r.id)}', this)">
                        ${simulatorIcon('play')}<span>Test</span>
                    </button>
                </div>
            </div>`;
        }).join('');
    } catch (err) {
        grid.innerHTML = `<div class="log-empty">Failed to load rules: ${esc(err.message)}</div>`;
    }
}

async function testRule(ruleId, btnElement) {
    if (btnElement) {
        btnElement.disabled = true;
        btnElement.setAttribute('aria-busy', 'true');
        btnElement.innerHTML = `${simulatorIcon('activity', 'icon-spin')}<span>Testing…</span>`;
    }
    const verdictEl = document.getElementById(`verdict-${ruleId}`);
    if (verdictEl) verdictEl.innerHTML = `<span class="verdict-badge pending">${simulatorIcon('activity', 'icon-spin')}<span>Testing…</span></span>`;

    try {
        const data = await api('/test-rule', {
            method: 'POST',
            body: JSON.stringify({ rule_id: ruleId }),
        });

        const verdictClass = data.verdict === 'BLOCKED' ? 'blocked'
            : data.verdict === 'ALLOWED' ? 'allowed'
                : 'rate-limited';
        const icon = data.verdict === 'BLOCKED' ? simulatorIcon('shield')
            : data.verdict === 'ALLOWED' ? simulatorIcon('check')
                : simulatorIcon('alert');

        if (verdictEl) {
            verdictEl.innerHTML = `<span class="verdict-badge ${verdictClass}">${icon} ${data.verdict}</span>`;
        }
    } catch (err) {
        if (verdictEl) {
            verdictEl.innerHTML = `<span class="verdict-badge blocked">${simulatorIcon('alert')}<span>Error</span></span>`;
        }
        showToast(`Test failed for ${ruleId}: ${err.message}`, 'error');
    } finally {
        if (btnElement) {
            btnElement.disabled = false;
            btnElement.removeAttribute('aria-busy');
            btnElement.innerHTML = `${simulatorIcon('play')}<span>Test</span>`;
        }
    }
}

async function testAllRules() {
    const btn = document.getElementById('btn-test-all-rules');
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    btn.innerHTML = `${simulatorIcon('activity', 'icon-spin')}<span>Testing Rules…</span>`;

    try {
        const data = await api('/rules');
        let passed = 0, total = data.rules.length;

        for (const rule of data.rules) {
            await testRule(rule.id, null);
            passed++;
        }
        showToast(`All ${total} rules tested successfully`, 'success');
    } catch (err) {
        showToast(`Error testing rules: ${err.message}`, 'error');
    } finally {
        btn.disabled = false;
        btn.removeAttribute('aria-busy');
        btn.innerHTML = `${simulatorIcon('play')}<span>Test All Rules</span>`;
    }
}

async function testCustomPacket(event) {
    event.preventDefault();
    const resultEl = document.getElementById('custom-packet-result');
    const submitButton = event.currentTarget.querySelector('.test-packet-button');
    resultEl.classList.remove('show');
    submitButton.disabled = true;
    submitButton.setAttribute('aria-busy', 'true');
    submitButton.innerHTML = `${simulatorIcon('activity', 'icon-spin')}<span>Testing Packet…</span>`;

    const body = {
        source_ip: document.getElementById('cp-src-ip').value.trim() || '203.0.113.50',
        dst_ip: document.getElementById('cp-dst-ip').value.trim() || '192.168.1.1',
        src_port: parseInt(document.getElementById('cp-src-port').value) || null,
        dst_port: parseInt(document.getElementById('cp-dst-port').value) || null,
        protocol: document.getElementById('cp-protocol').value,
        max_pps: parseInt(document.getElementById('cp-max-pps').value) || null,
    };

    try {
        const data = await api('/test-custom', { method: 'POST', body: JSON.stringify(body) });
        const verdictClass = data.verdict === 'BLOCKED' ? 'blocked'
            : data.verdict === 'ALLOWED' ? 'allowed' : 'rate-limited';
        const icon = data.verdict === 'BLOCKED' ? simulatorIcon('shield') : data.verdict === 'ALLOWED' ? simulatorIcon('check') : simulatorIcon('alert');

        let html = `<div style="margin-bottom:8px"><span class="verdict-badge ${verdictClass}" style="font-size:0.85rem">${icon} ${data.verdict}</span></div>`;
        html += `<div><strong>Packet:</strong> ${body.source_ip}:${body.src_port || '*'} ${simulatorIcon('arrow', 'inline-icon')} ${body.dst_ip}:${body.dst_port || '*'} (${body.protocol})</div>`;
        if (data.matched_rule) {
            html += `<div><strong>Matched Rule:</strong> ${esc(data.matched_rule.id)} — ${esc(data.matched_rule.description)}</div>`;
        } else {
            html += `<div><strong>Policy:</strong> Default allow (no rule matched)</div>`;
        }
        resultEl.innerHTML = html;
        resultEl.classList.add('show');
    } catch (err) {
        resultEl.innerHTML = `<span style="color:var(--accent-red)">Error: ${esc(err.message)}</span>`;
        resultEl.classList.add('show');
        showToast(`Test failed: ${err.message}`, 'error');
    } finally {
        submitButton.disabled = false;
        submitButton.removeAttribute('aria-busy');
        submitButton.innerHTML = `${simulatorIcon('play')}<span>Test Packet</span>`;
    }
}

// Make globally accessible
window.testRule = testRule;
window.testAllRules = testAllRules;
window.testCustomPacket = testCustomPacket;
window.loadTestableRules = loadTestableRules;

// ============================================================
// Logs
// ============================================================
async function loadLogs() {
    if (logsRequestInProgress) {
        logsReloadQueued = true;
        return;
    }
    logsRequestInProgress = true;
    const search = document.getElementById('log-search').value.trim();
    const eventFilter = document.getElementById('log-severity-filter').value;
    const refreshButton = document.getElementById('btn-refresh-logs');
    const refreshLabel = refreshButton.querySelector('.refresh-label');
    const logViewer = document.getElementById('log-viewer');
    const requestStatus = document.getElementById('log-request-status');
    refreshButton.disabled = true;
    refreshButton.setAttribute('aria-busy', 'true');
    refreshLabel.textContent = 'Loading…';
    logViewer.setAttribute('aria-busy', 'true');
    requestStatus.textContent = 'Loading log entries…';
    requestStatus.classList.remove('error');
    try {
        const params = new URLSearchParams({ lines: '200' });
        if (search) params.set('search', search);
        if (eventFilter) params.set('severity', eventFilter);
        const url = `/logs?${params.toString()}`;
        const data = await api(url);
        renderLogs(data.logs, 'log-viewer', { search, eventFilter });
        lastLogCount = data.total;
        requestStatus.textContent = `${data.total} ${data.total === 1 ? 'entry' : 'entries'} shown`;
    } catch (err) {
        console.error('Failed to load logs:', err);
        logViewer.innerHTML = '';
        const error = document.createElement('div');
        error.className = 'log-empty log-error';
        error.textContent = `Could not load logs: ${err.message}. Try Refresh.`;
        logViewer.appendChild(error);
        requestStatus.textContent = 'Log refresh failed.';
        requestStatus.classList.add('error');
    } finally {
        logsRequestInProgress = false;
        refreshButton.disabled = false;
        refreshButton.removeAttribute('aria-busy');
        refreshLabel.textContent = 'Refresh';
        logViewer.removeAttribute('aria-busy');
        if (logsReloadQueued) {
            logsReloadQueued = false;
            loadLogs();
        }
    }
}

function renderLogs(logs, containerId, filters = {}) {
    const container = document.getElementById(containerId);
    if (!logs.length) {
        const hasFilter = filters.search || filters.eventFilter;
        container.innerHTML = `<div class="log-empty">${hasFilter ? 'No log entries match the current search and filter.' : 'No log entries found.'}</div>`;
        return;
    }
    container.innerHTML = logs.reverse().map(log => {
        const event = log.event || 'info';
        const eventClass = /^[a-z0-9_-]+$/i.test(event) ? event : 'info';
        const time = log.timestamp ? formatTime(log.timestamp) : '--';
        const message = buildLogMessage(log);
        const severityValue = log.severity ? String(log.severity) : '';
        const severityClass = /^[a-z-]+$/i.test(severityValue.toLowerCase()) ? severityValue.toLowerCase() : 'unknown';
        const severity = severityValue ? `<span class="log-severity ${severityClass}">${esc(severityValue)}</span>` : '';
        return `<div class="log-entry ${eventClass}">
            <span class="log-time" title="${esc(log.timestamp || '')}">${esc(time)}</span>
            <span class="log-event ${eventClass}">${esc(event)}</span>
            ${severity}
            <span class="log-message">${esc(message)}</span>
        </div>`;
    }).join('');
}

function buildLogMessage(log) {
    const parts = [];
    if (log.message) parts.push(log.message);
    if (log.reason) parts.push(`reason=${log.reason}`);
    if (log.source_ip) parts.push(`src=${log.source_ip}`);
    if (log.dst_ip) parts.push(`dst=${log.dst_ip}`);
    if (log.src_port) parts.push(`sport=${log.src_port}`);
    if (log.dst_port) parts.push(`dport=${log.dst_port}`);
    if (log.protocol) parts.push(`proto=${log.protocol}`);
    if (log.rule_id) parts.push(`rule=${log.rule_id}`);
    if (log.alert_type) parts.push(`type=${log.alert_type}`);
    if (log.activity) parts.push(`activity=${log.activity}`);
    if (log.sim_type) parts.push(`sim=${log.sim_type} target=${log.target || ''}`);
    const detail = log.details || log.metadata;
    if (detail && typeof detail === 'object') {
        for (const [key, value] of Object.entries(detail)) {
            if (value !== null && value !== undefined && value !== '') {
                parts.push(`${key}=${typeof value === 'object' ? JSON.stringify(value) : value}`);
            }
        }
    }
    return parts.join('  ·  ') || JSON.stringify(log);
}

function formatTime(iso) {
    try {
        const d = new Date(iso);
        return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch { return iso; }
}

document.getElementById('btn-refresh-logs').addEventListener('click', loadLogs);
document.getElementById('log-search').addEventListener('input', debounce(loadLogs, 400));
document.getElementById('log-severity-filter').addEventListener('change', loadLogs);

// ============================================================
// Live Feed (Dashboard)
// ============================================================
async function refreshLiveFeed() {
    try {
        const data = await api('/logs?lines=30');
        if (data.logs.length) {
            renderLogs(data.logs, 'live-log-stream');
        }
    } catch { /* silent */ }
}

function startLiveFeed() {
    if (liveLogInterval) clearInterval(liveLogInterval);
    liveLogInterval = setInterval(() => {
        refreshLiveFeed();
        refreshStatus();
    }, 3000);
}

// ============================================================
// Utilities
// ============================================================
function esc(str) {
    if (str == null) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

function debounce(fn, ms) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), ms);
    };
}

// ============================================================
// Init
// ============================================================
(async function init() {
    await refreshStatus();
    await loadRules();
    await loadGeoRules();
    await refreshLiveFeed();
    startLiveFeed();
})();
