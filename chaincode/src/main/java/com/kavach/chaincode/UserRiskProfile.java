package com.kavach.chaincode;

import com.google.gson.Gson;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

/**
 * Aggregated risk profile for a user inside the counter-terrorism unit.
 * Stored on-chain and updated with each new event. Used for real-time
 * risk scoring and insider-threat detection.
 */
@DataType()
public class UserRiskProfile {

    private static final Gson GSON = new Gson();

    @Property()
    private String userId;

    @Property()
    private String username;

    @Property()
    private double cumulativeRiskScore;

    @Property()
    private int eventCount;

    @Property()
    private int criticalEventCount;   // severity >= 8

    @Property()
    private boolean flagged;

    @Property()
    private String flagReason;

    @Property()
    private String flaggedAt;         // ISO-8601 timestamp

    @Property()
    private String lastActivity;      // ISO-8601 timestamp

    @Property()
    private String department;

    @Property()
    private String clearanceLevel;    // UNCLASSIFIED, CONFIDENTIAL, SECRET, TOP_SECRET

    public UserRiskProfile() {}

    public UserRiskProfile(String userId, String username, String department, String clearanceLevel) {
        this.userId = userId;
        this.username = username;
        this.department = department;
        this.clearanceLevel = clearanceLevel;
        this.cumulativeRiskScore = 0.0;
        this.eventCount = 0;
        this.criticalEventCount = 0;
        this.flagged = false;
    }

    /**
     * Updates the risk profile with a new event's contribution.
     * Risk formula weighs severity exponentially — higher severity events
     * contribute disproportionately more risk.
     */
    public void addEvent(int severity, String timestamp) {
        this.eventCount++;
        if (severity >= 8) {
            this.criticalEventCount++;
        }
        // Exponential risk: severity^1.5 / 10 gives range ~0.03 (sev 1) to ~3.16 (sev 10)
        double riskContribution = Math.pow(severity, 1.5) / 10.0;
        // Frequency multiplier: more events from same user increases suspicion
        double frequencyMultiplier = 1.0 + (this.eventCount / 100.0);
        this.cumulativeRiskScore += riskContribution * frequencyMultiplier;
        // Round to 2 decimals
        this.cumulativeRiskScore = Math.round(this.cumulativeRiskScore * 100.0) / 100.0;
        this.lastActivity = timestamp;
    }

    /**
     * Returns the threat level based on cumulative risk score.
     */
    public String getThreatLevel() {
        if (flagged) return "CRITICAL";
        if (cumulativeRiskScore >= 50.0) return "CRITICAL";
        if (cumulativeRiskScore >= 25.0) return "HIGH";
        if (cumulativeRiskScore >= 10.0) return "MEDIUM";
        return "LOW";
    }

    // --- Getters & Setters ---

    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public double getCumulativeRiskScore() { return cumulativeRiskScore; }
    public void setCumulativeRiskScore(double cumulativeRiskScore) { this.cumulativeRiskScore = cumulativeRiskScore; }

    public int getEventCount() { return eventCount; }
    public void setEventCount(int eventCount) { this.eventCount = eventCount; }

    public int getCriticalEventCount() { return criticalEventCount; }
    public void setCriticalEventCount(int criticalEventCount) { this.criticalEventCount = criticalEventCount; }

    public boolean isFlagged() { return flagged; }
    public void setFlagged(boolean flagged) { this.flagged = flagged; }

    public String getFlagReason() { return flagReason; }
    public void setFlagReason(String flagReason) { this.flagReason = flagReason; }

    public String getFlaggedAt() { return flaggedAt; }
    public void setFlaggedAt(String flaggedAt) { this.flaggedAt = flaggedAt; }

    public String getLastActivity() { return lastActivity; }
    public void setLastActivity(String lastActivity) { this.lastActivity = lastActivity; }

    public String getDepartment() { return department; }
    public void setDepartment(String department) { this.department = department; }

    public String getClearanceLevel() { return clearanceLevel; }
    public void setClearanceLevel(String clearanceLevel) { this.clearanceLevel = clearanceLevel; }

    // --- Serialisation ---

    public String toJSON() {
        return GSON.toJson(this);
    }

    public static UserRiskProfile fromJSON(String json) {
        return GSON.fromJson(json, UserRiskProfile.class);
    }
}
