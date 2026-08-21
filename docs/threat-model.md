# IntentGuard threat model

Scope: the code on `main`. In-memory state, a single FastAPI process, and a
deterministic Python policy engine. PostgreSQL, Redis, OPA, Prometheus, Splunk,
KMS-backed signing, and AWS are roadmap and defend nothing today.

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
| An agent grading its own risk to skip human approval | The gateway derives risk from the registered intent envelope, live budget exposure, authorization velocity, refundability, and deviation from the authorized attributes. The agent's declared score may only raise the effective score, never lower it, and an under-declaration that would have skipped review is recorded as `RISK_SCORE_UNDER_DECLARED`. | `SelfReportedRiskTest` |
| Rewriting decision history | SHA-256 hash chain. Payload mutation, field mutation, deletion of a middle event, and reordering are all detected; `first_invalid_link()` names where the chain breaks. | `AuditChainTamperingTest` |

## What it does not defend against

Blunt list. None of these are mitigated today.

- **No authentication or authorization on any endpoint.** Every route in
  `src/intentguard/api.py` is open. Anyone who can reach the port can register
  agents, rewrite policy, revoke, stop or resume the fleet, approve their own
  high-risk action, and reset all state. CORS restricts browsers only; it is
  not a control against a non-browser client.
- **A malicious or coerced operator.** No separation of duties. `operator` and
  `reviewer` are self-asserted strings, not identities. An operator can raise a
  budget and then spend it, or approve their own high-risk action.
- **A compromised policy store.** State is process memory. Anyone who can write
  to it changes budgets, permissions, or revocation directly, with no integrity
  check between the engine and its own state.
- **An attacker who can write to the audit ledger.** The hash chain detects
  edits by someone who does not recompute it. It does not survive an attacker
  who can rebuild the chain from genesis, and it does not detect truncation of
  the tail: deleting the newest events still verifies, because nothing signs
  the head. There is no external checkpoint, no signature, and no append-only
  storage.
- **A connector that ignores the gateway.** IntentGuard is only enforcing where
  the downstream system refuses to act without a valid lease. A payment or
  booking system that accepts a direct call bypasses every control here.
- **Risk calibration.** The derived score is a fixed, deterministic weighting
  (see `PolicyEngine.RISK_WEIGHT_*`). It is not a trained model and has no
  counterparty reputation, device, or cross-agent context. It bounds what the
  agent can hide, not what a well-resourced attacker can construct.
- **Self-asserted agent identity.** `agent_id` is an unverified string. There
  are no agent credentials, so one agent can act as another.
- **Unsigned intent.** `IntentPassport` is registered over the open API and
  stored as a plain object. "Authenticated customer intent" means intent that
  was registered, not intent that is cryptographically bound to a customer.
- **More than one process.** The concurrency guarantee comes from an in-process
  lock. Two replicas share no state, so budgets, revocations, and the fleet
  stop are per-process. Horizontal scale would need the roadmap Redis.
- **Restarts.** All state is lost on exit. Budgets reset, revocations are
  forgotten, and the audit chain restarts at genesis.
- **Resource exhaustion.** Authorizations, reservations, leases, spend keys,
  and audit events accumulate without eviction, and there is no rate limiting.
  Sustained traffic exhausts memory.
- **Side channels.** Nothing is constant-time. Decision latency is observable
  and varies with which check fails.
- **A hostile host.** Process memory access, or moving the system clock,
  defeats lease and intent expiry.

## Trust boundaries

The only real boundary is between the **agent's proposed action** and the
**engine**. Everything on the request — amount, currency, action, attributes,
`intent_id`, `agent_id`, `risk_score` — is untrusted input and is checked
against registered policy and intent. Client-supplied `occurred_at` is recorded
but never used for evaluation; the engine stamps its own time.

Everything else is inside the trust boundary and is assumed honest: the gateway
process, the policy engine, the in-memory state, the audit ledger, the host and
its clock, the operator console, and — because there is no authentication —
anyone who can reach the API.

The protected connector sits outside and is assumed cooperative. It is expected
to present a lease and to refuse to act without one, and nothing in this
repository can force it to.

## Assumptions the design depends on

1. The gateway is reachable only by trusted callers on a trusted network.
2. Connectors refuse to execute without a valid, unexpired lease bound to the
   current fleet epoch.
3. The derived risk weighting is calibrated for the operator's tolerance. An
   agent cannot go below it, but the operator chooses where the bar sits.
4. Agent and operator identity are established somewhere else.
5. The host clock is monotonic and roughly correct.
6. One gateway process owns all budget state.
7. Losing state on restart is acceptable for a prototype.

The distance between assumptions 1, 3, and 4 and a production deployment is the
honest distance between this prototype and something that could hold real money.
