/**
 * server.js — Kavach Gateway API
 * 
 * Express REST server that bridges the web dashboard, the Hyperledger Fabric
 * blockchain (or mock), and the Splunk SIEM. Exposes endpoints for event
 * logging, querying, user flagging, risk analysis, and integrity verification.
 * Also serves a WebSocket feed for real-time dashboard updates.
 */

require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });

const express = require('express');
const cors = require('cors');
const http = require('http');
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');

const MockBlockchain = require('./mockBlockchain');
const SplunkForwarder = require('./splunkForwarder');

// ─── Config ────────────────────────────────────────────────
const PORT = process.env.GATEWAY_PORT || 3001;
const SPLUNK_HEC_URL = process.env.SPLUNK_HEC_URL || '';
const SPLUNK_HEC_TOKEN = process.env.SPLUNK_HEC_TOKEN || '';
const SPLUNK_INDEX = process.env.SPLUNK_INDEX || 'kavach_events';

// ─── Init ──────────────────────────────────────────────────
const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

const blockchain = new MockBlockchain();
const splunk = new SplunkForwarder(SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN, SPLUNK_INDEX);

// Track alerts for the dashboard
const alerts = [];

app.use(cors());
app.use(express.json());

// Serve dashboard static files
app.use(express.static(require('path').join(__dirname, '../dashboard')));

// ─── WebSocket ─────────────────────────────────────────────
const wsClients = new Set();

wss.on('connection', (ws) => {
    wsClients.add(ws);
    console.log(`[WS] Client connected (total: ${wsClients.size})`);

    // Send current stats on connect
    ws.send(JSON.stringify({ type: 'stats', data: blockchain.getLedgerStats() }));

    ws.on('close', () => {
        wsClients.delete(ws);
        console.log(`[WS] Client disconnected (total: ${wsClients.size})`);
    });
});

function broadcast(type, data) {
    const msg = JSON.stringify({ type, data, timestamp: new Date().toISOString() });
    for (const ws of wsClients) {
        if (ws.readyState === 1) ws.send(msg);
    }
}

// ─── API Routes ────────────────────────────────────────────

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        service: 'kavach-gateway',
        blockchain: 'mock',
        splunk: splunk.getStats(),
        uptime: process.uptime()
    });
});

/**
 * POST /api/events — Log a new insider-threat event
 * Body: { userId, username, action, resource, severity, metadata?, sourceIp?, department?, classification? }
 */
app.post('/api/events', async (req, res) => {
    try {
        const { userId, username, action, resource, severity,
            metadata, sourceIp, department, classification } = req.body;

        // Validation
        if (!userId || !action || !severity) {
            return res.status(400).json({ error: 'userId, action, and severity are required' });
        }
        if (severity < 1 || severity > 10) {
            return res.status(400).json({ error: 'severity must be between 1 and 10' });
        }

        // Check if user is flagged
        const profile = blockchain.getUserRiskProfile(userId);
        const flaggedUser = profile ? profile.flagged : false;

        // Log to blockchain
        const event = blockchain.logEvent({
            eventId: `EVT-${uuidv4().substring(0, 8).toUpperCase()}`,
            userId, username, action, resource,
            severity: parseInt(severity),
            timestamp: new Date().toISOString(),
            metadata: metadata || '{}',
            sourceIp: sourceIp || req.ip,
            department: department || (profile ? profile.department : 'Unknown'),
            classification: classification || 'UNCLASSIFIED'
        });

        // Forward to Splunk with flagged status
        const splunkResult = await splunk.forwardEvent({ ...event, flaggedUser });

        // Generate alert if high severity or flagged user
        let alert = null;
        if (severity >= 7 || flaggedUser) {
            alert = {
                id: `ALERT-${uuidv4().substring(0, 6).toUpperCase()}`,
                eventId: event.eventId,
                userId: event.userId,
                username: event.username,
                action: event.action,
                severity: event.severity,
                type: flaggedUser ? 'FLAGGED_USER_ACTIVITY' : (severity >= 8 ? 'CRITICAL_SEVERITY' : 'HIGH_SEVERITY'),
                message: flaggedUser
                    ? `Flagged user ${event.username} performed ${event.action}`
                    : `High severity event (${severity}/10): ${event.action} by ${event.username}`,
                timestamp: event.timestamp,
                acknowledged: false
            };
            alerts.unshift(alert);
            if (alerts.length > 100) alerts.length = 100; // keep last 100
        }

        // Broadcast to WebSocket clients
        broadcast('newEvent', event);
        broadcast('stats', blockchain.getLedgerStats());
        if (alert) broadcast('alert', alert);

        res.status(201).json({
            event,
            splunk: splunkResult,
            alert: alert || null
        });

    } catch (error) {
        console.error('[API] Error logging event:', error.message);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/events — Query events with optional filters
 * Query params: userId, minSeverity, limit
 */
app.get('/api/events', (req, res) => {
    try {
        let events;
        const { userId, minSeverity, limit } = req.query;

        if (userId) {
            events = blockchain.queryEventsByUser(userId);
        } else if (minSeverity) {
            events = blockchain.queryEventsBySeverity(parseInt(minSeverity));
        } else {
            events = blockchain.queryAllEvents();
        }

        if (limit) {
            events = events.slice(0, parseInt(limit));
        }

        res.json({ count: events.length, events });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/events/user/:userId — All events for a specific user
 */
app.get('/api/events/user/:userId', (req, res) => {
    try {
        const events = blockchain.queryEventsByUser(req.params.userId);
        res.json({ count: events.length, events });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/events/severity/:level — Events at or above severity
 */
app.get('/api/events/severity/:level', (req, res) => {
    try {
        const events = blockchain.queryEventsBySeverity(parseInt(req.params.level));
        res.json({ count: events.length, events });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/users/:userId/flag — Flag a user as suspicious
 * Body: { reason }
 */
app.post('/api/users/:userId/flag', (req, res) => {
    try {
        const { reason } = req.body;
        if (!reason) {
            return res.status(400).json({ error: 'reason is required' });
        }

        const profile = blockchain.flagUser(req.params.userId, reason);

        // Forward flag event to Splunk
        splunk.forwardEvent({
            eventType: 'USER_FLAGGED',
            userId: req.params.userId,
            username: profile.username,
            reason,
            severity: 10,
            timestamp: new Date().toISOString(),
            classification: 'SECRET'
        });

        // Create alert
        const alert = {
            id: `ALERT-${uuidv4().substring(0, 6).toUpperCase()}`,
            userId: profile.userId,
            username: profile.username,
            type: 'USER_FLAGGED',
            severity: 10,
            message: `User ${profile.username} has been flagged: ${reason}`,
            timestamp: new Date().toISOString(),
            acknowledged: false
        };
        alerts.unshift(alert);

        broadcast('userFlagged', profile);
        broadcast('alert', alert);
        broadcast('stats', blockchain.getLedgerStats());

        res.json({ profile, alert });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/users/:userId/risk — Get user risk profile
 */
app.get('/api/users/:userId/risk', (req, res) => {
    try {
        const profile = blockchain.getUserRiskProfile(req.params.userId);
        if (!profile) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(profile);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/users — Get all user risk profiles
 */
app.get('/api/users', (req, res) => {
    try {
        const profiles = blockchain.getAllUserRiskProfiles();
        res.json({ count: profiles.length, profiles });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/verify/:eventId — Verify event integrity on-chain
 */
app.get('/api/verify/:eventId', (req, res) => {
    try {
        const result = blockchain.verifyEventIntegrity(req.params.eventId);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/stats — Dashboard statistics
 */
app.get('/api/stats', (req, res) => {
    try {
        const stats = blockchain.getLedgerStats();
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/alerts — Recent alerts
 */
app.get('/api/alerts', (req, res) => {
    const limit = parseInt(req.query.limit) || 50;
    res.json({ count: alerts.length, alerts: alerts.slice(0, limit) });
});

/**
 * POST /api/alerts/:id/acknowledge — Acknowledge an alert
 */
app.post('/api/alerts/:id/acknowledge', (req, res) => {
    const alert = alerts.find(a => a.id === req.params.id);
    if (!alert) return res.status(404).json({ error: 'Alert not found' });
    alert.acknowledged = true;
    broadcast('alertAcknowledged', alert);
    res.json(alert);
});

/**
 * GET /api/splunk/status — Splunk forwarder status
 */
app.get('/api/splunk/status', (req, res) => {
    res.json(splunk.getStats());
});

// ─── Start ─────────────────────────────────────────────────
server.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗  ██╗ █████╗ ██╗   ██╗ █████╗  ██████╗██╗  ██╗        ║
║   ██║ ██╔╝██╔══██╗██║   ██║██╔══██╗██╔════╝██║  ██║        ║
║   █████╔╝ ███████║██║   ██║███████║██║     ███████║         ║
║   ██╔═██╗ ██╔══██║╚██╗ ██╔╝██╔══██║██║     ██╔══██║        ║
║   ██║  ██╗██║  ██║ ╚████╔╝ ██║  ██║╚██████╗██║  ██║        ║
║   ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ║
║                                                              ║
║   Insider Threat Monitoring System                           ║
║                                                              ║
║   Gateway API:  http://localhost:${PORT}                       ║
║   Dashboard:    http://localhost:${PORT}                       ║
║   WebSocket:    ws://localhost:${PORT}/ws                      ║
║   Splunk HEC:   ${splunk.enabled ? 'Connected' : 'Not configured'}                              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    `);
});

module.exports = { app, server };
