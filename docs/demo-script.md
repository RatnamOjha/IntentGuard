# IntentGuard 90-second demo script

## Preparation

Run the local production-like stack and confirm every service is healthy:

```powershell
./scripts/stack.ps1 up
./scripts/stack.ps1 status
```

Open the operator console at `http://localhost:3000`. Keep the policy editor,
approval queue, and audit trail within one scroll. If Docker is unavailable,
use `./scripts/start-demo.ps1`; say clearly that this is the in-memory demo.

## Narration and actions

### 0–15 seconds: the problem

“An AI agent being authenticated is not enough. IntentGuard checks whether this
exact financial action matches authenticated customer intent, the agent’s
permission envelope, live budget, derived risk, and current revocation state.”

Show the three-agent fleet and the healthy enforcement chain.

### 15–35 seconds: allowed execution

Select Atlas and submit a low-value refundable hotel request. Point to the
identity, intent, permission, budget, and risk stages. Explain that allow creates
an atomic budget reservation and a short-lived signed execution lease; the
protected connector verifies it before committing spend.

### 35–50 seconds: deterministic denial

Submit a request above the signed intent ceiling or with non-refundable terms.
Point to the stable finding code and unchanged committed budget.

“The model can propose this action, but it cannot override the policy result.”

### 50–65 seconds: human review

Submit a high-risk request and open the approval queue. Approve it with the
reviewer identity, highlighting separation of duties and the newly issued
lease. Mention that rejection creates a final denial and releases authority.

### 65–78 seconds: emergency control

Activate the fleet stop. Explain that it increments the fleet epoch, releases
outstanding holds, and causes connectors to reject leases issued before the
stop. Resume the fleet and state that old leases stay invalid.

### 78–90 seconds: evidence

Open the audit section and evaluation evidence.

“The chain verifies against a separately held checkpoint. The committed
evaluation runs 44 named correctness, security, and reliability scenarios, 31
acceptance controls, and 12 LLM-containment cases with zero observed budget
overspend.”

## Offline terminal fallback

```powershell
.venv/Scripts/python.exe examples/travel_agent.py
```

This runs valid, review, intent-denied, terms-denied, and provider-failure
bookings without an API key or external provider. Explain each transition from
proposal to authorization, approval, connector execution, commit/release, and
audit.

## Capture checklist

1. Fleet overview and enforcement metrics.
2. Decision trace showing a blocked request and finding.
3. Approval queue showing a pending review.
4. Audit trail and integrity status.

Do not show access tokens, `.env` files, local passwords, raw customer prompts,
or third-party account identifiers in screenshots or recordings.
