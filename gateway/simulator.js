/**
 * simulator.js — Kavach Insider-Threat Event Simulator
 * 
 * Generates realistic insider-threat telemetry for demonstration.
 * Simulates a mix of normal activity and suspicious/critical events
 * that mimic real-world insider-threat patterns in a counter-terrorism unit.
 *
 * Usage:
 *   node simulator.js                    # Default: 50 events, medium speed
 *   node simulator.js --events 100       # Custom event count
 *   node simulator.js --speed fast       # fast|medium|slow
 *   node simulator.js --threat-ratio 0.4 # 40% suspicious/critical events
 */

const axios = require('axios');

// ─── Configuration ─────────────────────────────────────────
const args = process.argv.slice(2);
function getArg(name, defaultVal) {
    const idx = args.indexOf(`--${name}`);
    return idx >= 0 && args[idx + 1] ? args[idx + 1] : defaultVal;
}

const API_URL = getArg('url', 'http://localhost:3001');
const TOTAL_EVENTS = parseInt(getArg('events', '50'));
const SPEED = getArg('speed', 'medium');
const THREAT_RATIO = parseFloat(getArg('threat-ratio', '0.3'));

const DELAYS = { fast: 500, medium: 1500, slow: 3000 };
const DELAY = DELAYS[SPEED] || 1500;

// ─── Data Pools ────────────────────────────────────────────

const USERS = [
    { userId: 'U001', username: 'Agent Aria Sharma', department: 'Intelligence', clearance: 'TOP_SECRET' },
    { userId: 'U002', username: 'Agent Rohan Mehta', department: 'Operations', clearance: 'SECRET' },
    { userId: 'U003', username: 'Analyst Priya Nair', department: 'Analysis', clearance: 'SECRET' },
    { userId: 'U004', username: 'Tech Vikram Singh', department: 'Cyber', clearance: 'CONFIDENTIAL' },
    { userId: 'U005', username: 'Admin Zara Khan', department: 'Administration', clearance: 'CONFIDENTIAL' },
    { userId: 'U006', username: 'Agent Dev Patel', department: 'Intelligence', clearance: 'TOP_SECRET' },
    { userId: 'U007', username: 'Analyst Maya Reddy', department: 'Analysis', clearance: 'SECRET' },
    { userId: 'U008', username: 'Tech Arjun Rao', department: 'Cyber', clearance: 'SECRET' }
];

// Normal activities (severity 1-3)
const NORMAL_ACTIONS = [
    { action: 'LOGIN', resource: 'auth/portal', severity: 1, classification: 'UNCLASSIFIED' },
    { action: 'LOGOUT', resource: 'auth/portal', severity: 1, classification: 'UNCLASSIFIED' },
    { action: 'FILE_ACCESS', resource: 'docs/daily-briefing.pdf', severity: 1, classification: 'CONFIDENTIAL' },
    { action: 'FILE_ACCESS', resource: 'docs/training-manual.pdf', severity: 1, classification: 'UNCLASSIFIED' },
    { action: 'DATABASE_QUERY', resource: 'db/personnel-schedule', severity: 2, classification: 'CONFIDENTIAL' },
    { action: 'EMAIL_SENT', resource: 'email/internal', severity: 1, classification: 'UNCLASSIFIED' },
    { action: 'REPORT_GENERATED', resource: 'reports/weekly-summary', severity: 2, classification: 'SECRET' },
    { action: 'SYSTEM_UPDATE', resource: 'system/software-patch', severity: 1, classification: 'UNCLASSIFIED' },
    { action: 'VPN_CONNECT', resource: 'network/secure-vpn', severity: 2, classification: 'CONFIDENTIAL' },
    { action: 'BADGE_SCAN', resource: 'facility/main-entrance', severity: 1, classification: 'UNCLASSIFIED' },
];

// Suspicious activities (severity 4-7)
const SUSPICIOUS_ACTIONS = [
    { action: 'BULK_DOWNLOAD', resource: 'classified/operation-files', severity: 6, classification: 'SECRET' },
    { action: 'PRIVILEGE_ESCALATION', resource: 'system/admin-panel', severity: 7, classification: 'SECRET' },
    { action: 'POLICY_OVERRIDE', resource: 'security/access-controls', severity: 6, classification: 'SECRET' },
    { action: 'EXTERNAL_TRANSFER', resource: 'data/agent-roster.xlsx', severity: 7, classification: 'SECRET' },
    { action: 'USB_DEVICE_CONNECTED', resource: 'hardware/usb-port-3', severity: 5, classification: 'CONFIDENTIAL' },
    { action: 'AFTER_HOURS_ACCESS', resource: 'facility/scif-room-b', severity: 5, classification: 'TOP_SECRET' },
    { action: 'FAILED_AUTH_MULTIPLE', resource: 'auth/classified-portal', severity: 6, classification: 'SECRET' },
    { action: 'DATABASE_QUERY', resource: 'db/informant-database', severity: 7, classification: 'TOP_SECRET' },
    { action: 'NETWORK_SCAN', resource: 'network/internal-subnet', severity: 5, classification: 'CONFIDENTIAL' },
    { action: 'CRYPTO_KEY_ACCESS', resource: 'crypto/comms-encryption-keys', severity: 7, classification: 'TOP_SECRET' },
];

// Critical threats (severity 8-10)
const CRITICAL_ACTIONS = [
    { action: 'DATA_EXFILTRATION', resource: 'classified/ops-plan-alpha.pdf', severity: 10, classification: 'TOP_SECRET' },
    { action: 'UNAUTHORIZED_ACCESS', resource: 'classified/agent-identities.db', severity: 9, classification: 'TOP_SECRET' },
    { action: 'CREDENTIAL_SHARING', resource: 'auth/master-credentials', severity: 9, classification: 'TOP_SECRET' },
    { action: 'SYSTEM_TAMPERING', resource: 'system/audit-log-config', severity: 10, classification: 'SECRET' },
    { action: 'EVIDENCE_DELETION', resource: 'cases/case-2026-0847', severity: 10, classification: 'SECRET' },
    { action: 'UNAUTHORIZED_ACCESS', resource: 'comms/intercepted-chatter.enc', severity: 9, classification: 'TOP_SECRET' },
    { action: 'DATA_EXFILTRATION', resource: 'intel/source-network-map.kml', severity: 10, classification: 'TOP_SECRET' },
    { action: 'SYSTEM_TAMPERING', resource: 'system/intrusion-detection-rules', severity: 8, classification: 'SECRET' },
];

const SOURCE_IPS = [
    '10.0.1.101', '10.0.1.102', '10.0.1.103', '10.0.2.201', '10.0.2.202',
    '10.0.3.50', '10.0.3.51', '192.168.1.100', '172.16.0.45', '10.10.10.99'
];

// ─── Simulator Logic ───────────────────────────────────────

function randomFrom(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

function generateEvent(index) {
    const user = randomFrom(USERS);
    const roll = Math.random();
    let actionPool;

    if (roll < (1 - THREAT_RATIO)) {
        actionPool = NORMAL_ACTIONS;
    } else if (roll < (1 - THREAT_RATIO * 0.3)) {
        actionPool = SUSPICIOUS_ACTIONS;
    } else {
        actionPool = CRITICAL_ACTIONS;
    }

    const actionTemplate = randomFrom(actionPool);

    return {
        userId: user.userId,
        username: user.username,
        action: actionTemplate.action,
        resource: actionTemplate.resource,
        severity: actionTemplate.severity,
        department: user.department,
        classification: actionTemplate.classification,
        sourceIp: randomFrom(SOURCE_IPS),
        metadata: JSON.stringify({
            simulatedEvent: true,
            eventIndex: index,
            sessionId: `SES-${Math.random().toString(36).substring(2, 8).toUpperCase()}`
        })
    };
}

function severityColor(sev) {
    if (sev >= 8) return '\x1b[31m'; // red
    if (sev >= 5) return '\x1b[33m'; // yellow
    if (sev >= 3) return '\x1b[36m'; // cyan
    return '\x1b[32m'; // green
}

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

async function sendEvent(eventData, index) {
    try {
        const response = await axios.post(`${API_URL}/api/events`, eventData);
        const evt = response.data.event;
        const color = severityColor(evt.severity);
        const alertTag = response.data.alert ? ` ${BOLD}\x1b[41m ALERT \x1b[0m` : '';

        console.log(
            `${DIM}[${index}/${TOTAL_EVENTS}]${RESET} ` +
            `${color}SEV ${evt.severity.toString().padStart(2)}${RESET} ` +
            `${BOLD}${evt.action.padEnd(25)}${RESET} ` +
            `${evt.username.padEnd(22)} ` +
            `${DIM}${evt.resource}${RESET}` +
            alertTag
        );
        return true;
    } catch (error) {
        console.error(`\x1b[31m[ERROR] Event ${index}: ${error.message}\x1b[0m`);
        return false;
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function runSimulation() {
    console.log(`
${BOLD}╔════════════════════════════════════════════════════╗
║         KAVACH THREAT SIMULATOR                    ║
╠════════════════════════════════════════════════════╣
║  Events:       ${TOTAL_EVENTS.toString().padEnd(35)}║
║  Speed:        ${SPEED.padEnd(35)}║
║  Threat ratio: ${(THREAT_RATIO * 100).toFixed(0)}%${' '.repeat(32)}║
║  API:          ${API_URL.padEnd(35)}║
╚════════════════════════════════════════════════════╝${RESET}
`);

    let success = 0, failed = 0;

    // Optional: flag one user mid-simulation for enhanced demo
    const flagAtEvent = Math.floor(TOTAL_EVENTS * 0.6);

    for (let i = 1; i <= TOTAL_EVENTS; i++) {
        const eventData = generateEvent(i);
        const result = await sendEvent(eventData, i);
        if (result) success++; else failed++;

        // Flag a user mid-simulation
        if (i === flagAtEvent) {
            console.log(`\n${BOLD}\x1b[41m ⚠ FLAGGING USER U003 — Analyst Priya Nair \x1b[0m`);
            console.log(`${DIM}Reason: Anomalous after-hours classified data access pattern detected${RESET}\n`);
            try {
                await axios.post(`${API_URL}/api/users/U003/flag`, {
                    reason: 'Anomalous after-hours classified data access pattern detected by automated analysis'
                });
            } catch (e) {
                console.error(`Flag request failed: ${e.message}`);
            }
        }

        await sleep(DELAY + Math.random() * 500);
    }

    console.log(`
${BOLD}╔════════════════════════════════════════════════════╗
║         SIMULATION COMPLETE                        ║
╠════════════════════════════════════════════════════╣
║  Sent:     ${success.toString().padEnd(39)}║
║  Failed:   ${failed.toString().padEnd(39)}║
╚════════════════════════════════════════════════════╝${RESET}
`);

    // Print final stats
    try {
        const statsResp = await axios.get(`${API_URL}/api/stats`);
        const stats = statsResp.data;
        console.log(`${BOLD}Ledger Statistics:${RESET}`);
        console.log(`  Total Events:    ${stats.totalEvents}`);
        console.log(`  Critical Events: ${stats.criticalEvents}`);
        console.log(`  Total Users:     ${stats.totalUsers}`);
        console.log(`  Flagged Users:   ${stats.flaggedUsers}`);
        console.log(`  Avg Risk Score:  ${stats.avgRiskScore}`);
    } catch (e) {
        console.log('Could not fetch final stats.');
    }
}

runSimulation().catch(console.error);
