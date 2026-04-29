package com.kavach.chaincode;

import com.google.gson.Gson;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

/**
 * Represents a single insider-threat event stored on the blockchain ledger.
 * Every sensitive action performed inside the counter-terrorism unit is
 * captured as a ThreatEvent and committed immutably.
 */
@DataType()
public class ThreatEvent {

    private static final Gson GSON = new Gson();

    @Property()
    private String eventId;

    @Property()
    private String userId;

    @Property()
    private String username;

    @Property()
    private String action;       // e.g. FILE_ACCESS, DATA_EXPORT, LOGIN, PRIVILEGE_CHANGE

    @Property()
    private String resource;     // e.g. "classified/ops-plan-alpha.pdf"

    @Property()
    private int severity;        // 1 (routine) – 10 (critical breach)

    @Property()
    private double riskScore;    // cumulative risk contribution

    @Property()
    private String timestamp;    // ISO-8601

    @Property()
    private String metadata;     // free-form JSON for extra context

    @Property()
    private String txId;         // Fabric transaction ID (set after commit)

    @Property()
    private String sourceIp;

    @Property()
    private String department;

    @Property()
    private String classification; // UNCLASSIFIED, CONFIDENTIAL, SECRET, TOP_SECRET

    public ThreatEvent() {}

    public ThreatEvent(String eventId, String userId, String username,
                       String action, String resource, int severity,
                       double riskScore, String timestamp, String metadata,
                       String sourceIp, String department, String classification) {
        this.eventId = eventId;
        this.userId = userId;
        this.username = username;
        this.action = action;
        this.resource = resource;
        this.severity = severity;
        this.riskScore = riskScore;
        this.timestamp = timestamp;
        this.metadata = metadata;
        this.sourceIp = sourceIp;
        this.department = department;
        this.classification = classification;
    }

    // --- Getters & Setters ---

    public String getEventId() { return eventId; }
    public void setEventId(String eventId) { this.eventId = eventId; }

    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }

    public String getResource() { return resource; }
    public void setResource(String resource) { this.resource = resource; }

    public int getSeverity() { return severity; }
    public void setSeverity(int severity) { this.severity = severity; }

    public double getRiskScore() { return riskScore; }
    public void setRiskScore(double riskScore) { this.riskScore = riskScore; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getMetadata() { return metadata; }
    public void setMetadata(String metadata) { this.metadata = metadata; }

    public String getTxId() { return txId; }
    public void setTxId(String txId) { this.txId = txId; }

    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }

    public String getDepartment() { return department; }
    public void setDepartment(String department) { this.department = department; }

    public String getClassification() { return classification; }
    public void setClassification(String classification) { this.classification = classification; }

    // --- Serialisation ---

    public String toJSON() {
        return GSON.toJson(this);
    }

    public static ThreatEvent fromJSON(String json) {
        return GSON.fromJson(json, ThreatEvent.class);
    }
}
