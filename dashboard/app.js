/**
 * app.js — Kavach Dashboard Client
 * 
 * Real-time dashboard for monitoring insider-threat events from the
 * Hyperledger Fabric blockchain via the gateway API and WebSocket feed.
 */

// ─── Config ────────────────────────────────────────────────
const API_BASE = window.location.origin;
const WS_URL = `ws://${window.location.host}/ws`;

// ─── State ─────────────────────────────────────────────────
let events = [];
let alerts = [];
let profiles = [];
let ws = null;
let activeSevFilter = 'all';
let activeTypeFilter = 'all';
let simulating = false;

// ─── DOM References ────────────────────────────────────────
const eventList = document.getElementById('event-list');
const riskList = document.getElementById('risk-list');
const alertList = document.getElementById('alert-list');
const wsStatus = document.getElementById('ws-status');
const eventCountBadge = document.getElementById('event-count-badge');
const alertCountBadge = document.getElementById('alert-count-badge');
const usersBadge = document.getElementById('users-badge');
const simBtn = document.getElementById('sim-btn');

// ─── WebSocket Connection ──────────────────────────────────
function connectWebSocket() {
    ws = new WebSocket(WS_URL);

    ws.onopen = () => {
        wsStatus.textContent = 'WS: Connected';
        wsStatus.style.color = '#10b981';
    };

    ws.onclose = () => {
        wsStatus.textContent = 'WS: Disconnected';
        wsStatus.style.color = '#ef4444';
        // Reconnect after 3s
        setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = () => {
        wsStatus.textContent = 'WS: Error';
        wsStatus.style.color = '#ef4444';
    };

    ws.onmessage = (msg) => {
        try {
            const data = JSON.parse(msg.data);
            handleWSMessage(data);
        } catch (e) {
            console.error('WS parse error:', e);
        }
    };
}

function handleWSMessage(data) {
    switch (data.type) {
        case 'newEvent':
            events.unshift(data.data);
            if (events.length > 500) events.length = 500;
            renderEventList();
            break;
        case 'stats':
            updateStats(data.data);
            break;
        case 'alert':
            alerts.unshift(data.data);
            if (alerts.length > 100) alerts.length = 100;
            renderAlertList();
            break;
        case 'userFlagged':
            fetchRiskProfiles();
            break;
        case 'alertAcknowledged':
            const idx = alerts.findIndex(a => a.id === data.data.id);
            if (idx >= 0) alerts[idx].acknowledged = true;
            renderAlertList();
            break;
    }
}

// ─── Stats ─────────────────────────────────────────────────
function updateStats(stats) {
    animateValue('stat-total-events', stats.totalEvents || 0);
    animateValue('stat-critical-events', stats.criticalEvents || 0);
    animateValue('stat-total-users', stats.totalUsers || 0);
    animateValue('stat-flagged-users', stats.flaggedUsers || 0);
    animateValue('stat-avg-risk', stats.avgRiskScore || 0, true);
}

function animateValue(elementId, newValue, isFloat = false) {
    const el = document.getElementById(elementId);
    const current = isFloat ? parseFloat(el.textContent) : parseInt(el.textContent);
    if (current === newValue) return;

    const duration = 300;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);

        const val = current + (newValue - current) * eased;
        el.textContent = isFloat ? val.toFixed(2) : Math.round(val);

        if (progress < 1) requestAnimationFrame(update);
    }

    requestAnimationFrame(update);
}

// ─── Event Feed ────────────────────────────────────────────
function renderEventList() {
    const filtered = filterEvents();
    eventCountBadge.textContent = `LIVE · ${events.length}`;

    if (filtered.length === 0) {
        eventList.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📡</div>
                <div class="empty-text">No events match current filter</div>
            </div>`;
        return;
    }

    // Only render latest 150 for performance
    const toRender = filtered.slice(0, 150);

    eventList.innerHTML = toRender.map(event => `
        <div class="event-item" onclick="verifyEvent('${event.eventId}')" title="Click to verify on blockchain">
            <div class="event-severity">
                <div class="severity-indicator severity-${event.severity}">
                    ${event.severity}
                </div>
            </div>
            <div class="event-details">
                <div class="event-action">${formatAction(event.action)}</div>
                <div class="event-user">👤 ${event.username || event.userId}</div>
                <div class="event-resource">📁 ${event.resource}</div>
            </div>
            <div class="event-meta">
                <div class="event-time">${formatTime(event.timestamp)}</div>
                <span class="event-classification class-${event.classification}">${event.classification}</span>
                <div class="event-txid">${(event.txId || '').substring(0, 16)}…</div>
            </div>
        </div>
    `).join('');
}

function filterEvents() {
    let filtered = [...events];

    // Severity filter
    if (activeSevFilter !== 'all') {
        const sev = parseInt(activeSevFilter);
        filtered = filtered.filter(e => e.severity === sev);
    }

    // Type filter
    if (activeTypeFilter === 'critical') {
        filtered = filtered.filter(e => e.severity >= 8);
    } else if (activeTypeFilter === 'suspicious') {
        filtered = filtered.filter(e => e.severity >= 5 && e.severity <= 7);
    } else if (activeTypeFilter === 'normal') {
        filtered = filtered.filter(e => e.severity <= 4);
    }

    return filtered;
}

// ─── Risk Profiles ─────────────────────────────────────────
async function fetchRiskProfiles() {
    try {
        const resp = await fetch(`${API_BASE}/api/users`);
        const data = await resp.json();
        profiles = data.profiles || [];
        // Sort by risk score descending
        profiles.sort((a, b) => b.cumulativeRiskScore - a.cumulativeRiskScore);
        renderRiskProfiles();
    } catch (e) {
        console.error('Failed to fetch profiles:', e);
    }
}

function renderRiskProfiles() {
    const activeProfiles = profiles.filter(p => p.lastActivity !== null || p.flagged);
    usersBadge.textContent = `${activeProfiles.length} active`;

    if (activeProfiles.length === 0) {
        riskList.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">👥</div>
                <div class="empty-text">No activity yet</div>
            </div>`;
        return;
    }

    const maxScore = Math.max(...activeProfiles.map(p => p.cumulativeRiskScore), 1);

    riskList.innerHTML = activeProfiles.map(profile => `
        <div class="risk-item">
            <div class="risk-avatar ${profile.threatLevel}">
                ${profile.username ? profile.username.split(' ').map(n => n[0]).join('').substring(0, 2) : '??'}
            </div>
            <div class="risk-info">
                <div class="risk-name">
                    ${profile.username || profile.userId}
                    ${profile.flagged ? '<span class="flagged-badge">🚩 FLAGGED</span>' : ''}
                </div>
                <div class="risk-dept">${profile.department || 'Unknown'} · ${profile.eventCount || 0} events</div>
            </div>
            <div class="risk-score-container">
                <div class="risk-score ${profile.threatLevel}">${profile.cumulativeRiskScore.toFixed(1)}</div>
                <div class="risk-bar">
                    <div class="risk-bar-fill ${profile.threatLevel}" style="width: ${Math.min((profile.cumulativeRiskScore / maxScore) * 100, 100)}%"></div>
                </div>
            </div>
        </div>
    `).join('');
}

// ─── Alerts ────────────────────────────────────────────────
function renderAlertList() {
    alertCountBadge.textContent = alerts.filter(a => !a.acknowledged).length;

    if (alerts.length === 0) {
        alertList.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🔕</div>
                <div class="empty-text">No alerts triggered</div>
            </div>`;
        return;
    }

    alertList.innerHTML = alerts.slice(0, 50).map(alert => `
        <div class="alert-item" style="${alert.acknowledged ? 'opacity: 0.5;' : ''}">
            <div class="alert-icon ${alert.severity >= 8 ? 'critical' : alert.type === 'USER_FLAGGED' || alert.type === 'FLAGGED_USER_ACTIVITY' ? 'flagged' : 'high'}">
                ${alert.severity >= 8 ? '🚨' : alert.type === 'USER_FLAGGED' ? '🚩' : '⚠️'}
            </div>
            <div class="alert-content">
                <div class="alert-message">${alert.message}</div>
                <span class="alert-type ${alert.type}">${formatAlertType(alert.type)}</span>
            </div>
            <div class="alert-time">${formatTime(alert.timestamp)}</div>
        </div>
    `).join('');
}

// ─── Verification Modal ────────────────────────────────────
async function verifyEvent(eventId) {
    const modal = document.getElementById('verify-modal');
    const body = document.getElementById('verify-body');

    modal.classList.add('active');
    body.innerHTML = `
        <div class="loader">
            <div class="loader-dot"></div>
            <div class="loader-dot"></div>
            <div class="loader-dot"></div>
        </div>
        <p style="text-align:center; color: var(--text-muted); margin-top: 1rem;">Verifying on blockchain...</p>
    `;

    try {
        const resp = await fetch(`${API_BASE}/api/verify/${eventId}`);
        const result = await resp.json();

        if (result.verified) {
            const event = result.eventData || {};
            body.innerHTML = `
                <div class="verify-result">
                    <div class="verify-icon">✅</div>
                    <div class="verify-status verified">Integrity Verified</div>
                    <p style="color: var(--text-secondary); font-size: 0.85rem;">
                        This event exists on the immutable blockchain ledger and has not been tampered with.
                    </p>
                    <div class="verify-hash">
                        <strong>SHA-256:</strong><br>${result.sha256Hash}
                    </div>
                    <div class="verify-detail">
                        <span class="verify-label">Event ID</span>
                        <span class="verify-value">${result.eventId}</span>
                        
                        <span class="verify-label">Transaction ID</span>
                        <span class="verify-value">${result.txId || 'N/A'}</span>
                        
                        <span class="verify-label">Block Number</span>
                        <span class="verify-value">${result.blockNumber || 'N/A'}</span>
                        
                        <span class="verify-label">Action</span>
                        <span class="verify-value">${typeof event === 'string' ? JSON.parse(event).action : (event.action || 'N/A')}</span>
                        
                        <span class="verify-label">User</span>
                        <span class="verify-value">${typeof event === 'string' ? JSON.parse(event).username : (event.username || 'N/A')}</span>
                        
                        <span class="verify-label">Severity</span>
                        <span class="verify-value">${typeof event === 'string' ? JSON.parse(event).severity : (event.severity || 'N/A')}</span>
                    </div>
                </div>
            `;
        } else {
            body.innerHTML = `
                <div class="verify-result">
                    <div class="verify-icon">❌</div>
                    <div class="verify-status failed">Verification Failed</div>
                    <p style="color: var(--text-secondary);">${result.error || 'Event not found on blockchain'}</p>
                </div>
            `;
        }
    } catch (e) {
        body.innerHTML = `
            <div class="verify-result">
                <div class="verify-icon">⚠️</div>
                <div class="verify-status failed">Error</div>
                <p style="color: var(--text-secondary);">${e.message}</p>
            </div>
        `;
    }
}

function closeModal() {
    document.getElementById('verify-modal').classList.remove('active');
}

// Close modal on overlay click
document.getElementById('verify-modal').addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-overlay')) closeModal();
});

// ─── Simulation ────────────────────────────────────────────
async function startSimulation() {
    if (simulating) return;
    simulating = true;
    simBtn.disabled = true;
    simBtn.textContent = '⏳ Simulating...';

    const USERS = [
        { userId: 'U001', username: 'Agent Aria Sharma', department: 'Intelligence', classification: 'TOP_SECRET' },
        { userId: 'U002', username: 'Agent Rohan Mehta', department: 'Operations', classification: 'SECRET' },
        { userId: 'U003', username: 'Analyst Priya Nair', department: 'Analysis', classification: 'SECRET' },
        { userId: 'U004', username: 'Tech Vikram Singh', department: 'Cyber', classification: 'CONFIDENTIAL' },
        { userId: 'U005', username: 'Admin Zara Khan', department: 'Administration', classification: 'CONFIDENTIAL' },
        { userId: 'U006', username: 'Agent Dev Patel', department: 'Intelligence', classification: 'TOP_SECRET' },
        { userId: 'U007', username: 'Analyst Maya Reddy', department: 'Analysis', classification: 'SECRET' },
        { userId: 'U008', username: 'Tech Arjun Rao', department: 'Cyber', classification: 'SECRET' }
    ];

    const NORMAL = [
        { action: 'LOGIN', resource: 'auth/portal', severity: 1, classification: 'UNCLASSIFIED' },
        { action: 'FILE_ACCESS', resource: 'docs/daily-briefing.pdf', severity: 1, classification: 'CONFIDENTIAL' },
        { action: 'DATABASE_QUERY', resource: 'db/personnel-schedule', severity: 2, classification: 'CONFIDENTIAL' },
        { action: 'REPORT_GENERATED', resource: 'reports/weekly-summary', severity: 2, classification: 'SECRET' },
        { action: 'VPN_CONNECT', resource: 'network/secure-vpn', severity: 2, classification: 'CONFIDENTIAL' },
        { action: 'BADGE_SCAN', resource: 'facility/main-entrance', severity: 1, classification: 'UNCLASSIFIED' },
    ];

    const SUSPICIOUS = [
        { action: 'BULK_DOWNLOAD', resource: 'classified/operation-files', severity: 6, classification: 'SECRET' },
        { action: 'PRIVILEGE_ESCALATION', resource: 'system/admin-panel', severity: 7, classification: 'SECRET' },
        { action: 'AFTER_HOURS_ACCESS', resource: 'facility/scif-room-b', severity: 5, classification: 'TOP_SECRET' },
        { action: 'USB_DEVICE_CONNECTED', resource: 'hardware/usb-port-3', severity: 5, classification: 'CONFIDENTIAL' },
        { action: 'CRYPTO_KEY_ACCESS', resource: 'crypto/comms-encryption-keys', severity: 7, classification: 'TOP_SECRET' },
    ];

    const CRITICAL = [
        { action: 'DATA_EXFILTRATION', resource: 'classified/ops-plan-alpha.pdf', severity: 10, classification: 'TOP_SECRET' },
        { action: 'UNAUTHORIZED_ACCESS', resource: 'classified/agent-identities.db', severity: 9, classification: 'TOP_SECRET' },
        { action: 'SYSTEM_TAMPERING', resource: 'system/audit-log-config', severity: 10, classification: 'SECRET' },
        { action: 'EVIDENCE_DELETION', resource: 'cases/case-2026-0847', severity: 10, classification: 'SECRET' },
        { action: 'CREDENTIAL_SHARING', resource: 'auth/master-credentials', severity: 9, classification: 'TOP_SECRET' },
    ];

    const totalEvents = 40;
    const flagAt = 24;

    for (let i = 0; i < totalEvents; i++) {
        const user = USERS[Math.floor(Math.random() * USERS.length)];
        const roll = Math.random();
        let template;

        if (roll < 0.6) template = NORMAL[Math.floor(Math.random() * NORMAL.length)];
        else if (roll < 0.85) template = SUSPICIOUS[Math.floor(Math.random() * SUSPICIOUS.length)];
        else template = CRITICAL[Math.floor(Math.random() * CRITICAL.length)];

        try {
            await fetch(`${API_BASE}/api/events`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    userId: user.userId,
                    username: user.username,
                    action: template.action,
                    resource: template.resource,
                    severity: template.severity,
                    department: user.department,
                    classification: template.classification,
                    sourceIp: `10.0.${Math.floor(Math.random() * 4)}.${Math.floor(Math.random() * 255)}`
                })
            });
        } catch (e) {
            console.error('Sim event failed:', e);
        }

        // Flag user mid-simulation
        if (i === flagAt) {
            try {
                await fetch(`${API_BASE}/api/users/U003/flag`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ reason: 'Automated detection: anomalous after-hours classified data access pattern' })
                });
            } catch (e) { /* ignore */ }
        }

        // Refresh risk profiles periodically
        if (i % 5 === 0) fetchRiskProfiles();

        await sleep(800 + Math.random() * 600);
    }

    await fetchRiskProfiles();
    simulating = false;
    simBtn.disabled = false;
    simBtn.textContent = '▶ Run Simulation';
}

// ─── Utilities ─────────────────────────────────────────────
function formatAction(action) {
    return (action || '').replace(/_/g, ' ');
}

function formatTime(ts) {
    if (!ts) return '';
    const d = new Date(ts);
    return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatAlertType(type) {
    return (type || '').replace(/_/g, ' ');
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ─── Filter Event Handlers ─────────────────────────────────
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeTypeFilter = btn.dataset.filter;
        renderEventList();
    });
});

document.querySelectorAll('.sev-filter').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.sev-filter').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeSevFilter = btn.dataset.sev;
        renderEventList();
    });
});

// ─── Keyboard shortcuts ────────────────────────────────────
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
});

// ─── Initialise ────────────────────────────────────────────
async function init() {
    connectWebSocket();

    // Fetch initial data
    try {
        const [statsResp, eventsResp, alertsResp] = await Promise.all([
            fetch(`${API_BASE}/api/stats`),
            fetch(`${API_BASE}/api/events?limit=100`),
            fetch(`${API_BASE}/api/alerts?limit=50`)
        ]);

        const statsData = await statsResp.json();
        updateStats(statsData);

        const eventsData = await eventsResp.json();
        events = eventsData.events || [];
        renderEventList();

        const alertsData = await alertsResp.json();
        alerts = alertsData.alerts || [];
        renderAlertList();
    } catch (e) {
        console.log('Initial data fetch failed (server may not be running):', e.message);
    }

    fetchRiskProfiles();

    // Refresh profiles every 10s
    setInterval(fetchRiskProfiles, 10000);
}

init();
