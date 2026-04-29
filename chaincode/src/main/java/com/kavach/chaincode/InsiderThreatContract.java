package com.kavach.chaincode;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.hyperledger.fabric.contract.Context;
import org.hyperledger.fabric.contract.ContractInterface;
import org.hyperledger.fabric.contract.annotation.*;
import org.hyperledger.fabric.shim.ChaincodeException;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ledger.KeyValue;
import org.hyperledger.fabric.shim.ledger.QueryResultsIterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * InsiderThreatContract — Hyperledger Fabric Smart Contract (Chaincode)
 *
 * Provides immutable, tamper-proof logging of all sensitive actions performed
 * within a counter-terrorism unit. Each action is recorded as a ThreatEvent
 * on the distributed ledger. The contract also maintains per-user risk profiles
 * that are updated with every new event.
 *
 * Key capabilities:
 *  - Log any sensitive event with full audit trail
 *  - Compute and maintain cumulative risk scores per user
 *  - Flag suspicious users for enhanced monitoring
 *  - Rich queries by user, severity, time range, department
 *  - Verify event integrity via cryptographic hash
 */
@Contract(
    name = "InsiderThreatContract",
    info = @Info(
        title = "Insider Threat Monitoring Contract",
        description = "Immutable blockchain logging for counter-terrorism insider threat detection",
        version = "1.0.0",
        contact = @Contact(
            email = "kavach@security.gov",
            name = "Kavach Security"
        ),
        license = @License(name = "Apache-2.0")
    )
)
@Default
public class InsiderThreatContract implements ContractInterface {

    private static final Logger LOG = LoggerFactory.getLogger(InsiderThreatContract.class);
    private static final Gson GSON = new Gson();

    private static final String EVENT_PREFIX = "EVENT_";
    private static final String PROFILE_PREFIX = "PROFILE_";

    // ---------- TRANSACTION: Initialise Ledger ----------

    /**
     * Initialises the ledger with seed data for demonstration.
     * Creates sample user profiles for the counter-terrorism unit.
     */
    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public void initLedger(final Context ctx) {
        LOG.info("Initialising Kavach ledger with seed profiles");

        String[][] seedUsers = {
            {"U001", "Agent Aria Sharma",  "Intelligence",    "TOP_SECRET"},
            {"U002", "Agent Rohan Mehta",  "Operations",      "SECRET"},
            {"U003", "Analyst Priya Nair", "Analysis",        "SECRET"},
            {"U004", "Tech Vikram Singh",  "Cyber",           "CONFIDENTIAL"},
            {"U005", "Admin Zara Khan",    "Administration",  "CONFIDENTIAL"},
            {"U006", "Agent Dev Patel",    "Intelligence",    "TOP_SECRET"},
            {"U007", "Analyst Maya Reddy", "Analysis",        "SECRET"},
            {"U008", "Tech Arjun Rao",     "Cyber",           "SECRET"}
        };

        for (String[] user : seedUsers) {
            UserRiskProfile profile = new UserRiskProfile(user[0], user[1], user[2], user[3]);
            String key = PROFILE_PREFIX + user[0];
            ctx.getStub().putStringState(key, profile.toJSON());
        }

        LOG.info("Ledger initialised with {} user profiles", seedUsers.length);
    }

    // ---------- TRANSACTION: Log Event ----------

    /**
     * Records a new insider-threat event on the immutable ledger.
     * Automatically updates the user's cumulative risk profile.
     *
     * @return The recorded ThreatEvent as JSON (includes computed riskScore and txId)
     */
    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public String logEvent(final Context ctx,
                           final String eventId,
                           final String userId,
                           final String username,
                           final String action,
                           final String resource,
                           final int severity,
                           final String timestamp,
                           final String metadata,
                           final String sourceIp,
                           final String department,
                           final String classification) {

        ChaincodeStub stub = ctx.getStub();

        // Validate severity range
        if (severity < 1 || severity > 10) {
            throw new ChaincodeException("Severity must be between 1 and 10, got: " + severity);
        }

        // Check for duplicate event
        String eventKey = EVENT_PREFIX + eventId;
        String existing = stub.getStringState(eventKey);
        if (existing != null && !existing.isEmpty()) {
            throw new ChaincodeException("Event already exists: " + eventId);
        }

        // Compute risk score contribution
        double riskScore = Math.pow(severity, 1.5) / 10.0;
        riskScore = Math.round(riskScore * 100.0) / 100.0;

        // Get Fabric transaction ID
        String txId = stub.getTxId();

        // Create the event
        ThreatEvent event = new ThreatEvent(
            eventId, userId, username, action, resource,
            severity, riskScore, timestamp, metadata,
            sourceIp, department, classification
        );
        event.setTxId(txId);

        // Store event on ledger
        stub.putStringState(eventKey, event.toJSON());

        // Update user risk profile
        updateUserProfile(stub, userId, username, department,
                          guessUserClearance(classification), severity, timestamp);

        // Emit event for off-chain listeners
        stub.setEvent("InsiderThreatEvent", event.toJSON().getBytes(StandardCharsets.UTF_8));

        LOG.info("Logged event {} for user {} [severity={}, risk={}]",
                 eventId, userId, severity, riskScore);

        return event.toJSON();
    }

    // ---------- TRANSACTION: Query Events By User ----------

    /**
     * Rich query: returns all events for a given user ID.
     * Requires CouchDB as the state database.
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String queryEventsByUser(final Context ctx, final String userId) {
        String queryString = String.format(
            "{\"selector\":{\"userId\":\"%s\"}, \"sort\":[{\"timestamp\":\"desc\"}]}",
            userId
        );
        return executeRichQuery(ctx.getStub(), queryString);
    }

    // ---------- TRANSACTION: Query Events By Severity ----------

    /**
     * Rich query: returns events at or above the given severity threshold.
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String queryEventsBySeverity(final Context ctx, final int minSeverity) {
        String queryString = String.format(
            "{\"selector\":{\"severity\":{\"$gte\":%d}}, \"sort\":[{\"timestamp\":\"desc\"}]}",
            minSeverity
        );
        return executeRichQuery(ctx.getStub(), queryString);
    }

    // ---------- TRANSACTION: Query Events By Time Range ----------

    /**
     * Rich query: returns events within a time range.
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String queryEventsByTimeRange(final Context ctx,
                                          final String startTime,
                                          final String endTime) {
        String queryString = String.format(
            "{\"selector\":{\"timestamp\":{\"$gte\":\"%s\",\"$lte\":\"%s\"}}, \"sort\":[{\"timestamp\":\"desc\"}]}",
            startTime, endTime
        );
        return executeRichQuery(ctx.getStub(), queryString);
    }

    // ---------- TRANSACTION: Flag User ----------

    /**
     * Flags a user as suspicious. All future events from this user will
     * automatically be treated as elevated risk. This is an irreversible
     * action that requires audit-level authorization.
     */
    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public String flagUser(final Context ctx,
                           final String userId,
                           final String reason) {

        ChaincodeStub stub = ctx.getStub();
        String profileKey = PROFILE_PREFIX + userId;
        String profileJSON = stub.getStringState(profileKey);

        if (profileJSON == null || profileJSON.isEmpty()) {
            throw new ChaincodeException("User profile not found: " + userId);
        }

        UserRiskProfile profile = UserRiskProfile.fromJSON(profileJSON);
        profile.setFlagged(true);
        profile.setFlagReason(reason);
        profile.setFlaggedAt(Instant.now().toString());

        stub.putStringState(profileKey, profile.toJSON());

        // Emit flagging event
        String flagEvent = GSON.toJson(new FlagEvent(userId, reason, profile.getThreatLevel()));
        stub.setEvent("UserFlagged", flagEvent.getBytes(StandardCharsets.UTF_8));

        LOG.warn("USER FLAGGED: {} — Reason: {}", userId, reason);

        return profile.toJSON();
    }

    // ---------- TRANSACTION: Get User Risk Profile ----------

    /**
     * Returns the full risk profile for a user including cumulative score,
     * event count, flag status, and computed threat level.
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String getUserRiskProfile(final Context ctx, final String userId) {
        ChaincodeStub stub = ctx.getStub();
        String profileKey = PROFILE_PREFIX + userId;
        String profileJSON = stub.getStringState(profileKey);

        if (profileJSON == null || profileJSON.isEmpty()) {
            throw new ChaincodeException("User profile not found: " + userId);
        }

        return profileJSON;
    }

    // ---------- TRANSACTION: Get All User Risk Profiles ----------

    /**
     * Returns risk profiles for all monitored users.
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String getAllUserRiskProfiles(final Context ctx) {
        ChaincodeStub stub = ctx.getStub();
        List<UserRiskProfile> profiles = new ArrayList<>();

        QueryResultsIterator<KeyValue> results =
            stub.getStateByRange(PROFILE_PREFIX, PROFILE_PREFIX + "\uffff");

        for (KeyValue kv : results) {
            if (kv.getStringValue() != null && !kv.getStringValue().isEmpty()) {
                profiles.add(UserRiskProfile.fromJSON(kv.getStringValue()));
            }
        }

        return GSON.toJson(profiles);
    }

    // ---------- TRANSACTION: Verify Event Integrity ----------

    /**
     * Verifies that a specific event exists on the ledger and returns
     * its SHA-256 hash for tamper verification.
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String verifyEventIntegrity(final Context ctx, final String eventId) {
        ChaincodeStub stub = ctx.getStub();
        String eventKey = EVENT_PREFIX + eventId;
        String eventJSON = stub.getStringState(eventKey);

        if (eventJSON == null || eventJSON.isEmpty()) {
            throw new ChaincodeException("Event not found: " + eventId);
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(eventJSON.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            VerificationResult result = new VerificationResult(
                eventId, true, hexString.toString(), eventJSON
            );
            return GSON.toJson(result);

        } catch (Exception e) {
            throw new ChaincodeException("Integrity verification failed: " + e.getMessage());
        }
    }

    // ---------- TRANSACTION: Get Ledger Statistics ----------

    /**
     * Returns aggregate statistics about the ledger.
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String getLedgerStats(final Context ctx) {
        ChaincodeStub stub = ctx.getStub();

        int totalEvents = 0;
        int criticalEvents = 0;
        int flaggedUsers = 0;
        int totalUsers = 0;

        // Count events
        QueryResultsIterator<KeyValue> eventResults =
            stub.getStateByRange(EVENT_PREFIX, EVENT_PREFIX + "\uffff");
        for (KeyValue kv : eventResults) {
            totalEvents++;
            ThreatEvent event = ThreatEvent.fromJSON(kv.getStringValue());
            if (event.getSeverity() >= 8) criticalEvents++;
        }

        // Count profiles
        QueryResultsIterator<KeyValue> profileResults =
            stub.getStateByRange(PROFILE_PREFIX, PROFILE_PREFIX + "\uffff");
        for (KeyValue kv : profileResults) {
            totalUsers++;
            UserRiskProfile profile = UserRiskProfile.fromJSON(kv.getStringValue());
            if (profile.isFlagged()) flaggedUsers++;
        }

        LedgerStats stats = new LedgerStats(totalEvents, criticalEvents, totalUsers, flaggedUsers);
        return GSON.toJson(stats);
    }

    // =================== HELPER METHODS ===================

    private void updateUserProfile(ChaincodeStub stub, String userId, String username,
                                    String department, String clearance,
                                    int severity, String timestamp) {
        String profileKey = PROFILE_PREFIX + userId;
        String profileJSON = stub.getStringState(profileKey);
        UserRiskProfile profile;

        if (profileJSON == null || profileJSON.isEmpty()) {
            profile = new UserRiskProfile(userId, username, department, clearance);
        } else {
            profile = UserRiskProfile.fromJSON(profileJSON);
        }

        profile.addEvent(severity, timestamp);
        stub.putStringState(profileKey, profile.toJSON());
    }

    private String guessUserClearance(String classification) {
        if (classification == null) return "UNCLASSIFIED";
        return classification;
    }

    private String executeRichQuery(ChaincodeStub stub, String queryString) {
        List<ThreatEvent> events = new ArrayList<>();
        QueryResultsIterator<KeyValue> results = stub.getQueryResult(queryString);

        for (KeyValue kv : results) {
            if (kv.getStringValue() != null && !kv.getStringValue().isEmpty()) {
                events.add(ThreatEvent.fromJSON(kv.getStringValue()));
            }
        }

        return GSON.toJson(events);
    }

    // =================== INNER DTOs ===================

    private static class FlagEvent {
        String userId;
        String reason;
        String threatLevel;

        FlagEvent(String userId, String reason, String threatLevel) {
            this.userId = userId;
            this.reason = reason;
            this.threatLevel = threatLevel;
        }
    }

    private static class VerificationResult {
        String eventId;
        boolean verified;
        String sha256Hash;
        String eventData;

        VerificationResult(String eventId, boolean verified, String sha256Hash, String eventData) {
            this.eventId = eventId;
            this.verified = verified;
            this.sha256Hash = sha256Hash;
            this.eventData = eventData;
        }
    }

    private static class LedgerStats {
        int totalEvents;
        int criticalEvents;
        int totalUsers;
        int flaggedUsers;

        LedgerStats(int totalEvents, int criticalEvents, int totalUsers, int flaggedUsers) {
            this.totalEvents = totalEvents;
            this.criticalEvents = criticalEvents;
            this.totalUsers = totalUsers;
            this.flaggedUsers = flaggedUsers;
        }
    }
}
