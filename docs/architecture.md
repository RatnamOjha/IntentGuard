# IntentGuard architecture

## System context

IntentGuard sits between autonomous agents and financial tools. Agents never
call protected systems directly. The core architecture fulfills the five
challenge tasks; intent passports, human approval, and execution leases are
differentiators layered on top.

```mermaid
flowchart LR
    CM["Card Member"] --> IS["Intent and Consent Service"]
    IS --> IP["Signed Intent Passport"]

    AA["Autonomous Agent Fleet"] --> GW["IntentGuard Enforcement Gateway"]
    IP --> GW

    subgraph Runtime["Runtime Enforcement Plane"]
        GW --> ID["Agent Identity and Registry"]
        GW --> PDP["OPA Policy Decision Service"]
        GW --> BR["Budget Reservation Engine"]
        GW --> RV["Revocation and Fleet Stop"]
        GW --> RA["Risk Evaluation"]
    end

    PDP -->|"Allow / Deny / Review"| GW
    BR --> Redis[("Redis")]
    RV --> Redis
    ID --> PG[("PostgreSQL")]

    GW -->|"Review"| HA["Human Approval Queue"]
    HA --> GW

    GW -->|"Allow"| KMS["Lease Signer / KMS"]
    KMS -->|"Signed execution lease"| API["Banking and Payment Connectors"]
    API -->|"Execution result"| GW
    GW -->|"Commit / Release"| BR

    subgraph Control["Governance Control Plane"]
        UI["React Operator Dashboard"] --> PC["Policy Authoring and Versioning"]
        UI --> RV
        UI --> HA
        PC -->|"Versioned Rego bundles"| PDP
    end

    GW -.-> AE["Audit Event Pipeline"]
    PDP -.-> AE
    BR -.-> AE
    RV -.-> AE
    HA -.-> AE
    API -.-> AE
    AE --> ES[("Append-Only Event Store")]
    AE --> OBS["Prometheus / Grafana"]
    AE --> SPL["Splunk Export"]
```

## Evaluation sequence

```mermaid
sequenceDiagram
    participant Agent
    participant Gateway as IntentGuard Gateway
    participant Identity as Identity Registry
    participant Policy as OPA Policy Engine
    participant State as Risk/Budget State
    participant Audit as Audit Ledger
    participant Tool as Protected API

    Agent->>Gateway: Proposed action + intent ID
    Gateway->>Identity: Verify agent and status
    Gateway->>Policy: Evaluate identity, permission, and intent context
    Policy->>State: Check spend, velocity, and risk
    State-->>Policy: Current exposure
    Policy-->>Gateway: Allow / Deny / Review + findings
    Gateway->>Audit: Append decision event
    alt Allowed
        Gateway->>Tool: Execute action
        Tool-->>Gateway: Result
        Gateway->>Audit: Append execution event
    else Denied
        Gateway-->>Agent: Block reason
    else Human review
        Gateway-->>Agent: Approval pending
    end
```

## Mandatory task-to-component mapping

### 1. Granular permission model

- Agent registry stores identity, owner, status, environment, and capability
  grants.
- Rego policies evaluate action, resource, amount, merchant category, region,
  time window, delegation scope, and customer intent.
- The gateway fails closed if identity or policy evaluation is unavailable.

### 2. Dynamic spend caps

- PostgreSQL stores budget definitions and durable reconciliation data.
- Redis performs atomic reservation, commit, and release operations.
- Supported scopes include per action, per agent, shared fleet, customer, and
  rolling time window.
- Reservations prevent concurrent agents from collectively overspending.

### 3. Revocation and emergency stop

- Redis stores per-agent revocation epochs and fleet-stop state.
- Every request checks current revocation state before execution.
- Short-lived leases carry the agent epoch so connectors can reject stale
  authorization after a revocation.

### 4. Operator dashboard

- Configure and version policies.
- Assign permissions and budgets.
- Observe agent health, decisions, and spend.
- Approve or reject high-risk actions.
- Revoke one agent or stop the fleet.
- Search and replay audit events.

### 5. Testing and optimization

- Unit tests cover individual policies and boundary conditions.
- Integration tests cover gateway, OPA, Redis, PostgreSQL, and connectors.
- Load tests measure p50, p95, and p99 policy-enforcement latency.
- Adversarial tests cover bypass attempts, stale leases, races, and outages.
- Audit verification confirms completeness and hash-chain integrity.

## Decision contract

Every evaluation returns:

- outcome: `allow`, `deny`, or `review`;
- stable policy finding codes;
- a plain-language explanation;
- remaining budget;
- the applied policy version;
- a hash-chained audit event.

## Trust boundaries

1. Agent output is always untrusted input.
2. Customer intent must be independently authenticated.
3. The policy engine is deterministic for the same inputs and state.
4. An LLM may help interpret intent, but cannot bypass policy enforcement.
5. Protected APIs accept requests only from the governance gateway.
6. Revocation and the emergency stop are checked at evaluation time.

## Prototype evolution

The current implementation keeps state in memory for fast iteration. The
prototype will replace this with:

- PostgreSQL for agents, intents, policies, and approvals;
- Redis for low-latency budgets, counters, and revocation state;
- OPA/Rego for externally configurable policy-as-code;
- an append-only event store for audit history;
- FastAPI for the governance gateway;
- React and TypeScript for the operator and reviewer interfaces.

