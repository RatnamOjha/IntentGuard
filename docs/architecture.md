# IntentGuard architecture

## System context

IntentGuard sits between autonomous agents and financial tools. Agents never
call protected systems directly.

```mermaid
flowchart LR
    CM["Card Member"] --> IA["Intent Authenticator"]
    IA --> IP["Signed Intent Passport"]

    subgraph Fleet["Financial Agent Fleet"]
        TA["Travel Agent"]
        SA["Servicing Agent"]
        BA["Benefits Agent"]
    end

    IP --> PG["IntentGuard Policy Gateway"]
    Fleet --> PG

    PG --> ID["Agent Identity Registry"]
    PG --> PE["Policy Engine"]
    PG --> RB["Risk and Budget State"]
    PG --> AQ["Human Approval Queue"]
    PG --> AL["Tamper-Evident Audit Ledger"]

    PG -->|"Allow"| TOOLS["Protected Financial APIs"]
    PG -->|"Deny"| Fleet
    PG -->|"Review"| AQ
```

## Evaluation sequence

```mermaid
sequenceDiagram
    participant Agent
    participant Gateway as IntentGuard Gateway
    participant Identity as Identity Registry
    participant Policy as Policy Engine
    participant State as Risk/Budget State
    participant Audit as Audit Ledger
    participant Tool as Protected API

    Agent->>Gateway: Proposed action + intent ID
    Gateway->>Identity: Verify agent and status
    Gateway->>Policy: Evaluate permissions and intent
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
- OPA or Cedar for externally configurable policy-as-code;
- an append-only event store for audit history;
- FastAPI for the governance gateway;
- React for the operator and reviewer interfaces.

