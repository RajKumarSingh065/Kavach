/**
 * splunkForwarder.js
 * 
 * Forwards blockchain events to Splunk via the HTTP Event Collector (HEC).
 * Each event is enriched with severity classification and threat-hunting
 * metadata before being sent to the kavach_events index.
 */

const axios = require('axios');

class SplunkForwarder {
    constructor(hecUrl, hecToken, index = 'kavach_events') {
        this.hecUrl = hecUrl;
        this.hecToken = hecToken;
        this.index = index;
        this.enabled = !!(hecUrl && hecToken);
        this.stats = { sent: 0, failed: 0, lastError: null };
    }

    /**
     * Classify the event for Splunk alert rules
     */
    classifyThreat(event) {
        const tags = [];
        
        if (event.severity >= 8) tags.push('CRITICAL_SEVERITY');
        else if (event.severity >= 5) tags.push('ELEVATED_SEVERITY');
        
        // After-hours detection (outside 06:00-22:00)
        if (event.timestamp) {
            const hour = new Date(event.timestamp).getHours();
            if (hour < 6 || hour >= 22) tags.push('AFTER_HOURS');
        }

        // Classify actions
        const criticalActions = ['DATA_EXFILTRATION', 'UNAUTHORIZED_ACCESS', 'CREDENTIAL_SHARING', 
                                  'SYSTEM_TAMPERING', 'EVIDENCE_DELETION'];
        const suspiciousActions = ['BULK_DOWNLOAD', 'PRIVILEGE_ESCALATION', 'POLICY_OVERRIDE',
                                    'EXTERNAL_TRANSFER', 'USB_DEVICE_CONNECTED'];
        
        if (criticalActions.includes(event.action)) tags.push('CRITICAL_ACTION');
        if (suspiciousActions.includes(event.action)) tags.push('SUSPICIOUS_ACTION');

        // Classification access
        if (event.classification === 'TOP_SECRET' || event.classification === 'SECRET') {
            tags.push('CLASSIFIED_ACCESS');
        }

        if (event.flaggedUser) tags.push('FLAGGED_USER_ACTIVITY');

        return tags;
    }

    /**
     * Send an event to Splunk HEC
     */
    async forwardEvent(event) {
        if (!this.enabled) {
            console.log('[Splunk] Forwarding disabled — no HEC URL/token configured');
            return { success: false, reason: 'disabled' };
        }

        const threatTags = this.classifyThreat(event);
        
        const splunkPayload = {
            event: {
                ...event,
                threatTags,
                threatLevel: this.getThreatLevel(event.severity),
                source: 'kavach-blockchain',
                eventType: 'insider_threat_log'
            },
            sourcetype: '_json',
            index: this.index,
            time: event.timestamp ? new Date(event.timestamp).getTime() / 1000 : Date.now() / 1000
        };

        try {
            const response = await axios.post(this.hecUrl, splunkPayload, {
                headers: {
                    'Authorization': `Splunk ${this.hecToken}`,
                    'Content-Type': 'application/json'
                },
                timeout: 5000
            });
            this.stats.sent++;
            return { success: true, code: response.status };
        } catch (error) {
            this.stats.failed++;
            this.stats.lastError = error.message;
            console.error(`[Splunk] Forward failed: ${error.message}`);
            return { success: false, error: error.message };
        }
    }

    /**
     * Send a batch of events
     */
    async forwardBatch(events) {
        const results = [];
        for (const event of events) {
            results.push(await this.forwardEvent(event));
        }
        return results;
    }

    getThreatLevel(severity) {
        if (severity >= 8) return 'CRITICAL';
        if (severity >= 5) return 'HIGH';
        if (severity >= 3) return 'MEDIUM';
        return 'LOW';
    }

    getStats() {
        return { ...this.stats, enabled: this.enabled };
    }
}

module.exports = SplunkForwarder;
