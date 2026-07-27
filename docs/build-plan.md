# IntentGuard build plan

## Product boundary

IntentGuard is a governance layer, not a general-purpose agent framework. It
intercepts actions, evaluates policy and budgets, issues bounded authorization,
and records what happened. Mock agents and banking connectors exist only to
demonstrate enforcement.

## Target production technology choices

The executable first-round prototype intentionally uses the FastAPI gateway,
deterministic Python policy engine, and in-memory state. The technologies below
are the locked production path and are shown as roadmap—not running
integrations—in the operator console.

- React 19, TypeScript, and Vite
- FastAPI and Python
- Open Policy Agent with Rego policies
- PostgreSQL
- Redis
- Prometheus and Grafana
- Splunk-compatible event export
- Docker Compose for local development
- AWS as the production deployment path

We will not implement both OPA and Cedar, both React and Angular, or both AWS
and Azure. The challenge list is illustrative, and using redundant technologies
would reduce prototype quality.

## Required capabilities

### Permission model

- Register, activate, deactivate, and revoke an agent.
- Grant action and resource scopes.
- Add contextual restrictions for amount, region, time, merchant, and customer.
- Version, test, publish, and roll back policies.
- Explain every allow, deny, or review outcome.

### Dynamic budgets

- Per-action maximum.
- Per-agent daily and rolling-window cap.
- Shared fleet budget.
- Atomic reservation before execution.
- Commit on success and release on failure.
- Live remaining-budget display.

### Revocation and emergency stop

- Revoke one agent with immediate effect.
- Restore an agent through an explicit operator action.
- Stop or resume the entire fleet.
- Reject leases issued before the current revocation epoch.
- Record the operator, reason, and time for every control action.

### Operator experience

- Fleet overview.
- Agent detail and permission editor.
- Budget configuration.
- Live activity stream.
- Human approval inbox.
- Audit search and decision replay.
- Clearly guarded emergency-stop interaction.

### Evaluation

- Policy decisions against a deterministic adversarial acceptance suite.
- Budget race-condition and overspend tests.
- Revocation propagation time.
- Separate in-process policy-engine and browser-to-FastAPI p50, p95, and p99
  latency.
- Audit completeness and chain verification.
- Failure-mode behavior when OPA, Redis, or PostgreSQL is unavailable.

## API milestones

### Milestone 1: governance data

- `POST /v1/agents`
- `GET /v1/agents`
- `POST /v1/intents`
- `POST /v1/policies/validate`
- `POST /v1/policies/publish`

### Milestone 2: runtime enforcement

- `POST /v1/actions/evaluate`
- `POST /v1/actions/{request_id}/execute`
- `POST /v1/budgets/reserve`
- `POST /v1/budgets/{reservation_id}/commit`
- `POST /v1/budgets/{reservation_id}/release`

### Milestone 3: fleet controls

- `POST /v1/agents/{agent_id}/revoke`
- `POST /v1/agents/{agent_id}/restore`
- `POST /v1/fleet/stop`
- `POST /v1/fleet/resume`
- `GET /v1/audit/events`

## Demonstration agents

1. Travel agent: searches and books flights within authenticated constraints.
2. Servicing agent: requests fee reversals and replacement cards.
3. Benefits agent: initiates claims or benefit activation.

These agents create realistic policy variation while keeping the project
focused on the shared governance layer.

## Finale acceptance criteria

- All three agents route protected actions through IntentGuard.
- A compliant action executes successfully.
- Permission and intent violations are denied with explanations.
- Concurrent actions cannot exceed a shared budget.
- High-risk actions enter the approval queue.
- Revocation blocks the next action from one agent.
- Fleet stop blocks every agent.
- Operators can inspect and verify a complete audit trail.
- The dashboard shows measurable enforcement latency and fleet health.
