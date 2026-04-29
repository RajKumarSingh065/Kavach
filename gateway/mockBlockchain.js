/**
 * mockBlockchain.js
 * 
 * In-memory mock of the Hyperledger Fabric blockchain for demo and
 * development without requiring a live Fabric network. Mirrors the
 * InsiderThreatContract Java chaincode logic exactly, so the gateway
 * can be tested end-to-end before deploying the real network.
 * 
 * Swap this module for fabricClient.js when connecting to a live network.
 */

const { v4: uuidv4 } = require('uuid');

class MockBlockchain {
    constructor() {
        this.events = new Map();
        this.profiles = new Map();
        this.txCounter = 0;

        // Seed user profiles (mirrors InsiderThreatContract.initLedger)
        this._seedProfiles();
    }

    _seedProfiles() {
        const seedUsers = [
            { userId: 'U001', username: 'Agent Aria Sharma', department: 'Intelligence', clearanceLevel: 'TOP_SECRET' },
            { userId: 'U002', username: 'Agent Rohan Mehta', department: 'Operations', clearanceLevel: 'SECRET' },
            { userId: 'U003', username: 'Analyst Priya Nair', department: 'Analysis', clearanceLevel: 'SECRET' },
            { userId: 'U004', username: 'Tech Vikram Singh', department: 'Cyber', clearanceLevel: 'CONFIDENTIAL' },
            { userId: 'U005', username: 'Admin Zara Khan', department: 'Administration', clearanceLevel: 'CONFIDENTIAL' },
            { userId: 'U006', username: 'Agent Dev Patel', department: 'Intelligence', clearanceLevel: 'TOP_SECRET' },
            { userId: 'U007', username: 'Analyst Maya Reddy', department: 'Analysis', clearanceLevel: 'SECRET' },
            { userId: 'U008', username: 'Tech Arjun Rao', department: 'Cyber', clearanceLevel: 'SECRET' }
        ];

        for (const user of seedUsers) {
            this.profiles.set(user.userId, {
                ...user,
                cumulativeRiskScore: 0,
                eventCount: 0,
                criticalEventCount: 0,
                flagged: false,
                flagReason: null,
                flaggedAt: null,
                lastActivity: null,
                threatLevel: 'LOW'
            });
        }
    }

    /**
     * Mirrors InsiderThreatContract.logEvent()
     */
    logEvent(eventData) {
        this.txCounter++;
        const txId = `tx_${Date.now()}_${this.txCounter}`;
        const riskScore = Math.round(Math.pow(eventData.severity, 1.5) / 10.0 * 100) / 100;

        const event = {
            eventId: eventData.eventId || `EVT-${uuidv4().substring(0, 8).toUpperCase()}`,
            userId: eventData.userId,
            username: eventData.username,
            action: eventData.action,
            resource: eventData.resource,
            severity: eventData.severity,
            riskScore,
            timestamp: eventData.timestamp || new Date().toISOString(),
            metadata: eventData.metadata || '{}',
            sourceIp: eventData.sourceIp || '10.0.0.1',
            department: eventData.department || 'Unknown',
            classification: eventData.classification || 'UNCLASSIFIED',
            txId,
            blockNumber: this.txCounter,
            verified: true
        };

        this.events.set(event.eventId, event);
        this._updateProfile(event);

        return event;
    }

    _updateProfile(event) {
        let profile = this.profiles.get(event.userId);
        if (!profile) {
            profile = {
                userId: event.userId,
                username: event.username,
                department: event.department,
                clearanceLevel: event.classification,
                cumulativeRiskScore: 0,
                eventCount: 0,
                criticalEventCount: 0,
                flagged: false,
                flagReason: null,
                flaggedAt: null,
                lastActivity: null,
                threatLevel: 'LOW'
            };
        }

        profile.eventCount++;
        if (event.severity >= 8) profile.criticalEventCount++;

        const riskContribution = Math.pow(event.severity, 1.5) / 10.0;
        const frequencyMultiplier = 1.0 + (profile.eventCount / 100.0);
        profile.cumulativeRiskScore = Math.round((profile.cumulativeRiskScore + riskContribution * frequencyMultiplier) * 100) / 100;
        profile.lastActivity = event.timestamp;

        // Update threat level
        if (profile.flagged) profile.threatLevel = 'CRITICAL';
        else if (profile.cumulativeRiskScore >= 50) profile.threatLevel = 'CRITICAL';
        else if (profile.cumulativeRiskScore >= 25) profile.threatLevel = 'HIGH';
        else if (profile.cumulativeRiskScore >= 10) profile.threatLevel = 'MEDIUM';
        else profile.threatLevel = 'LOW';

        this.profiles.set(event.userId, profile);
    }

    queryEventsByUser(userId) {
        return Array.from(this.events.values())
            .filter(e => e.userId === userId)
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }

    queryEventsBySeverity(minSeverity) {
        return Array.from(this.events.values())
            .filter(e => e.severity >= minSeverity)
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }

    queryAllEvents() {
        return Array.from(this.events.values())
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }

    flagUser(userId, reason) {
        const profile = this.profiles.get(userId);
        if (!profile) throw new Error(`User profile not found: ${userId}`);
        profile.flagged = true;
        profile.flagReason = reason;
        profile.flaggedAt = new Date().toISOString();
        profile.threatLevel = 'CRITICAL';
        this.profiles.set(userId, profile);
        return profile;
    }

    getUserRiskProfile(userId) {
        return this.profiles.get(userId) || null;
    }

    getAllUserRiskProfiles() {
        return Array.from(this.profiles.values());
    }

    verifyEventIntegrity(eventId) {
        const event = this.events.get(eventId);
        if (!event) return { eventId, verified: false, error: 'Event not found' };

        // Simple hash simulation using JSON content
        const crypto = require('crypto');
        const hash = crypto.createHash('sha256')
            .update(JSON.stringify(event))
            .digest('hex');

        return {
            eventId,
            verified: true,
            sha256Hash: hash,
            txId: event.txId,
            blockNumber: event.blockNumber,
            eventData: event
        };
    }

    getLedgerStats() {
        const events = Array.from(this.events.values());
        const profiles = Array.from(this.profiles.values());

        return {
            totalEvents: events.length,
            criticalEvents: events.filter(e => e.severity >= 8).length,
            highEvents: events.filter(e => e.severity >= 5 && e.severity < 8).length,
            mediumEvents: events.filter(e => e.severity >= 3 && e.severity < 5).length,
            lowEvents: events.filter(e => e.severity < 3).length,
            totalUsers: profiles.length,
            flaggedUsers: profiles.filter(p => p.flagged).length,
            activeUsers: profiles.filter(p => p.lastActivity !== null).length,
            avgRiskScore: profiles.length > 0
                ? Math.round(profiles.reduce((sum, p) => sum + p.cumulativeRiskScore, 0) / profiles.length * 100) / 100
                : 0
        };
    }
}

module.exports = MockBlockchain;
