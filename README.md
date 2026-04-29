# Kavach — Immutable Blockchain Logs for Insider-Threat Monitoring

> **Kavach** (कवच, "Shield") is a demonstration system that uses **Hyperledger Fabric** to create an immutable, tamper-proof audit trail of every sensitive action performed inside a counter-terrorism unit — and routes high-severity events into **Splunk SIEM** for active threat-hunting.

---

## Architecture

```
┌──────────────┐     REST      ┌─────────────────┐      gRPC     ┌─────────────────────┐
│   Dashboard  │◄────────────►│   Gateway API    │◄────────────►│  Hyperledger Fabric  │
│ (HTML/CSS/JS)│   WebSocket   │   (Node.js)      │              │  Java Chaincode      │
└──────────────┘               └────────┬─────────┘              │  CouchDB State DB    │
                                        │ HEC POST               └─────────────────────┘
                                        ▼
                               ┌─────────────────┐
                               │   Splunk SIEM    │
                               │  Saved Searches  │
                               │  Alert Rules     │
                               └─────────────────┘
```

| Component | Technology | Port |
|---|---|---|
| Dashboard | Vanilla HTML/CSS/JS | 3001 |
| Gateway API | Node.js + Express + WebSocket | 3001 |
| Splunk Web | Splunk Free (Docker) | 8000 |
| Splunk HEC | HTTP Event Collector | 8088 |
| Fabric Orderer | HLF 2.5 | 7050 |
| Fabric Peers | HLF 2.5 | 7051, 9051 |

---

## Quick Start (Demo Mode)

The demo uses a mock blockchain layer — no Docker needed for basic testing.

```bash
# 1. Install gateway dependencies
cd gateway
npm install

# 2. Start the server (serves dashboard + API)
npm start

# 3. Open dashboard
# → http://localhost:3001

# 4. Run the threat simulator (separate terminal)
node simulator.js --events 50 --speed fast
```

---

## Full Stack (with Splunk)

```bash
# 1. Start Splunk SIEM
cd splunk
docker-compose -f docker-compose.splunk.yaml up -d

# 2. Wait for Splunk to initialise (~60s), then open:
# → http://localhost:8000  (admin / KavachAdmin@2026)

# 3. Start the gateway (separate terminal)
cd gateway
npm install && npm start

# 4. Run simulation
node simulator.js --events 100 --speed medium

# 5. In Splunk, search: index=kavach_events
```

---

## Full Stack (with Fabric Network)

```bash
# 1. Start Fabric network
cd network
docker-compose up -d

# 2. Deploy chaincode (requires fabric-tools)
cd chaincode
gradle build
# ... peer lifecycle chaincode install/approve/commit

# 3. Switch gateway from mock to real Fabric
# Edit gateway/server.js: replace MockBlockchain with FabricClient
```

---

## Java Chaincode Transactions

| Transaction | Type | Description |
|---|---|---|
| `initLedger` | Submit | Seed 8 user profiles |
| `logEvent` | Submit | Record event + update risk score |
| `queryEventsByUser` | Evaluate | CouchDB rich query by userId |
| `queryEventsBySeverity` | Evaluate | Filter by minimum severity |
| `queryEventsByTimeRange` | Evaluate | Filter by time window |
| `flagUser` | Submit | Flag user as suspicious |
| `getUserRiskProfile` | Evaluate | Get user's cumulative risk |
| `getAllUserRiskProfiles` | Evaluate | All user profiles |
| `verifyEventIntegrity` | Evaluate | SHA-256 hash verification |
| `getLedgerStats` | Evaluate | Aggregate statistics |

---

## Splunk Saved Searches

| Search Name | Schedule | Severity |
|---|---|---|
| Critical Severity Alert | Every 2 min | Critical |
| Anomalous Hours Access | Every 5 min | High |
| Bulk Data Access Pattern | Every 3 min | Critical |
| Privilege Escalation | Every 5 min | High |
| Flagged User Activity | Every 2 min | Critical |
| Classified Document Access | Every 5 min | High |
| System Tampering Detection | Every 2 min | Critical |

---

## Risk Scoring Algorithm

```
riskContribution = severity^1.5 / 10
frequencyMultiplier = 1 + (eventCount / 100)
cumulativeRisk += riskContribution × frequencyMultiplier
```

| Threat Level | Risk Score | Trigger |
|---|---|---|
| LOW | < 10 | Normal operations |
| MEDIUM | 10 – 24.99 | Elevated monitoring |
| HIGH | 25 – 49.99 | Active investigation |
| CRITICAL | ≥ 50 or Flagged | Immediate response |

---

## Project Structure

```
Kavach/
├── .env                          # Environment variables
├── README.md
├── chaincode/                    # Java Smart Contract
│   ├── build.gradle
│   └── src/main/java/com/kavach/chaincode/
│       ├── InsiderThreatContract.java
│       ├── ThreatEvent.java
│       └── UserRiskProfile.java
├── gateway/                      # Node.js API Server
│   ├── package.json
│   ├── server.js
│   ├── mockBlockchain.js
│   ├── splunkForwarder.js
│   └── simulator.js
├── dashboard/                    # Web UI
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── splunk/                       # Splunk SIEM Config
│   ├── docker-compose.splunk.yaml
│   └── savedsearches.conf
└── network/                      # Fabric Network (Docker)
    └── docker-compose.yaml
```
