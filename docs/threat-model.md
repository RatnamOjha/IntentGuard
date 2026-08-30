# IntentGuard threat model

Scope: the code on `main`. OPA/Rego provides versioned declarative decisions;
Python owns repository-backed state and an authenticated FastAPI gateway.
PostgreSQL, local OPA enforcement, OpenTelemetry tracing, Prometheus metrics,
and structured JSON logs are implemented. Redis-backed distributed rate
windows are implemented when configured; broader Redis coordination, Splunk,
KMS-backed signing, and AWS remain roadmap and defend nothing today.

## What IntentGuard defends against

Each control below is held open by a named test in
[`tests/test_adversarial.py`](../tests/test_adversarial.py).

| Attack | Control | Test class |
| --- | --- | --- |
| Executing something other than what was authorized | The reservation and lease bind the authorized amount, currency, and attributes. A used `request_id` re-sent with different data is refused and audited; the tampered payload sent fresh is denied on merit; a lease cannot be moved to another reservation. | `IntentTamperingTest` |
| Replaying an unexpired lease after revocation | Revocation releases outstanding holds, and `commit_reservation` re-checks it at execution time. Restoring the agent does not resurrect the old lease. | `ReplayAfterRevocationTest` |
| Spending the same headroom twice across a check/execute gap | `authorize_action` holds the funds under the engine lock rather than observing them; `record_execution` re-checks live exposure and refuses. | `BudgetTimeOfCheckTimeOfUseTest` |
| Concurrent requests each under the cap, summing above it | Budget mutation is serialized on one `RLock`. 20 barrier-released threads, 50 iterations, commit exactly 9,000 against a 10,000 cap every time. | `ConcurrentSpendRaceTest` |
| Executing work already in flight when the kill switch is pulled | `stop_fleet` bumps a fleet epoch and releases held reservations. Leases carry their issuing epoch, so pre-stop authorizations stay rejected even after the fleet resumes. | `FleetEpochBypassTest` |
| Spending against another customer's authorization | `IntentPassport` carries a `customer_id`, and when an authenticated caller supplies `ActionRequest.customer_id` the engine requires the cited intent to belong to that customer, denying with `INTENT_CUSTOMER_MISMATCH`. The field is optional, so it only binds where a caller establishes who is acting. | `CrossCustomerIntentTest` |
| An agent grading its own risk to skip human approval | The gateway derives risk from the registered intent envelope, live budget exposure, authorization velocity, refundability, and deviation from the authorized attributes. The agent's declared score may only raise the effective score, never lower it, and an under-declaration that would have skipped review is recorded as `RISK_SCORE_UNDER_DECLARED`. | `SelfReportedRiskTest` |
| Rewriting decision history | SHA-256 hash chain. Payload mutation, field mutation, deletion of a middle event, and reordering are all detected; `first_invalid_link()` names where the chain breaks. | `AuditChainTamperingTest` |
| Deleting the newest events to hide an attack | The expected length and head hash are held in a checkpoint outside the chain, so truncation -- which a bare hash chain cannot see -- is rejected. | `AuditChainTamperingTest` |
| Prompt injection causing direct execution | The model has one proposal-only tool. Its output is schema validated and always evaluated by the deterministic policy engine; the 12-case LLM evaluation includes direct, indirect, override, cross-customer, and multi-turn attacks. | `LlmEvaluationTest`, `InjectedInstructionTest` |

## What it does not defend against

Blunt list. These remain outside the controls implemented today.

- **A malicious or coerced authorized operator.** JWT authentication and roles
  keep anonymous callers out, verified subjects replace self-asserted actor
  names, and a submitter cannot review their own request. They do not prevent
  two colluding authorized users, a compromised identity provider, or an admin
  token from abusing valid privileges.
- **A compromised model provider or successful prompt injection.** Proposal
  validation and the policy boundary prevent direct execution and policy
  bypass, but do not guarantee that the model will produce a useful proposal.
  Provider transport still exposes prompts to the selected provider; operators
  must choose an appropriate data-processing arrangement.
- **A compromised policy store.** PostgreSQL is authoritative in durable mode.
  Anyone who can write to it can change budgets, permissions, or revocation;
  database access controls and encryption are deployment responsibilities.
- **A compromised OPA executable or policy author.** Rego is validated and
  versioned, changes are attributable, and rollback is immediate, but an
  authorized malicious policy can still grant unsafe behavior. Production
  requires signed bundles, protected review workflow, and binary provenance.
- **An attacker who can write to both the ledger and its checkpoint.** The
  hash chain detects edits, and the separately held checkpoint now detects
  truncation of the newest events. But the checkpoint lives in the same
  process: an attacker who rebuilds the chain from genesis *and* updates the
  checkpoint defeats both. Nothing is signed, and storage is not append-only.
  A signed, externally stored checkpoint is the fuller answer.
- **An unprotected alternative provider path.** The included booking connector
  refuses unsigned, expired, stale, or mismatched leases. A separately deployed
  provider endpoint that remains directly reachable could still bypass it.
- **Risk calibration.** The derived score is a fixed, deterministic weighting
  (see `PolicyEngine.RISK_WEIGHT_*`). It is not a trained model and has no
  counterparty reputation, device, or cross-agent context. It bounds what the
  agent can hide, not what a well-resourced attacker can construct.
- **Identity-provider compromise.** Agent and customer IDs are taken from
  signed token claims and checked against submitted resource IDs. A stolen
  token or compromised signing key can still impersonate its subject until the
  token expires; there is no token revocation or proof-of-possession support.
- **Consent-service compromise.** Intent passports are Ed25519 signed and bound
  to issuer, audience, customer, agent, action, limits, attributes, time window,
  key ID, and one-time nonce. A compromised consent-service private key can
  still mint apparently authentic consent until its public key is revoked.
- **Database unavailability.** Durable mode fails closed when PostgreSQL cannot
  be reached. There is no automatic fallback to process-local state.
- **Restarts in demo mode.** Without `INTENTGUARD_DATABASE_URL`, state remains
  intentionally ephemeral and the audit chain restarts at genesis.
- **Long-term storage growth.** Principal rate limits, body caps, reservation
  and approval bounds, audit pagination, and connector circuit breaking now
  constrain request-path amplification. Authorization and audit history remain
  append-only, so deployments still need the documented immutable archive
  process and capacity monitoring.
- **Side channels.** Nothing is constant-time. Decision latency is observable
  and varies with which check fails.
- **Observability is not an audit authority.** Prometheus, Tempo, Grafana, and
  stdout logs are operational signals, not tamper-evident evidence. An attacker
  controlling the host can suppress or forge them; the audit chain remains the
  investigation record.
- **A hostile host.** Process memory access, or moving the system clock,
  defeats lease and intent expiry.

## Trust boundaries

There are now two enforced boundaries: the **authenticated API caller** and the
**agent's proposed action**. The gateway validates RS256 tokens against a JWKS,
checks role and ownership claims, and supplies actor identities to the engine.
Action amount, currency, action, attributes, `intent_id`, and `risk_score`
remain untrusted and are checked against registered policy and intent.
Client-supplied `occurred_at` is recorded but never used for evaluation; the
engine stamps its own time.

Everything else is inside the trust boundary and is assumed honest: the
identity provider and its signing keys, the gateway process, the policy engine,
the configured state repository, the audit ledger, the host and its clock, and authorized
operator-console sessions.

The protected booking connector sits outside the gateway and independently
verifies signed execution capabilities. Its provider adapter is trusted not to
expose another direct execution route around that boundary.

## Assumptions the design depends on

1. The configured identity provider protects signing keys and issues accurate
   role, customer, and agent claims.
2. Connectors refuse to execute without a valid, unexpired lease bound to the
   current fleet epoch.
3. The derived risk weighting is calibrated for the operator's tolerance. An
   agent cannot go below it, but the operator chooses where the bar sits.
4. Bearer tokens are transported over TLS and kept out of logs and storage.
5. The host clock is monotonic and roughly correct.
6. Every production gateway replica uses the same migrated PostgreSQL database.
7. In-memory state is used only for local demonstrations and tests.

The distance between assumptions 1, 3, and 4 and a production deployment is the
honest distance between this prototype and something that could hold real money.
