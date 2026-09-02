# ADR 005: Replace whole-state load/save with per-entity persistence

- Status: Proposed — four items in "Risks needing approval" require sign-off,
  one of them a demonstrated defect in the current implementation
- Date: 2026-09-02
- Supersedes the persistence half of ADR 002; ADR 004 depends on this landing first

## Context

`docs/evidence/state-load-curve-2026-09-02.txt` measured a single `authorize`
at 4.1 s against 20,005 rows of history, versus 2.6 ms empty, growing linearly.
Cost at 20k rows splits 681 ms raw SQL / 597 ms `_decode` / 1,346 ms
`deepcopy(state)` inside `save()`.

This ADR designs the replacement. It is a design only; nothing here is
implemented.

---

## 1. Current state lifecycle

Every mutating public method on `PolicyEngine` follows the same shape:

```
  caller
    │
    ▼
  with self._lock:                          in-process RLock, one replica only
    │
    ├─ _refresh_state_unlocked()            repository.load()
    │     └── SELECT * FROM agent_policies          (no WHERE, no LIMIT)
    │         SELECT * FROM customer_intents        (no WHERE, no LIMIT)
    │         SELECT * FROM authorization_leases    (no WHERE, no LIMIT)  ← unbounded
    │         SELECT * FROM authorization_records   (no WHERE, no LIMIT)  ← unbounded
    │         SELECT * FROM approval_requests       (no WHERE, no LIMIT)
    │         SELECT * FROM agent_revocations
    │         SELECT * FROM authorization_counters
    │         SELECT ... FROM governance_metadata WHERE singleton = TRUE
    │         _decode() every row into dataclasses
    │         self._baseline = deepcopy(state)            ← O(history)
    │
    ├─ mutate plain dicts / sets in memory
    │     self._agents, self._intents, self._leases, self._authorizations,
    │     self._approvals, self._revoked_agents, self._revocation_epochs,
    │     self._authorization_counts, self._fleet_stopped, self._fleet_epoch
    │
    ├─ budget_ledger.reserve/commit/release        ← separate pool, own transaction
    ├─ audit_ledger.append(...)                    ← separate pool, own transaction
    │
    └─ _persist_state_unlocked()            repository.save(whole snapshot)
          └── one transaction:
              diff every dict against self._baseline
              INSERT ... ON CONFLICT DO UPDATE for anything that differs
              DELETE for anything that vanished
              self._baseline = deepcopy(state)             ← O(history) again
```

Twenty call sites invoke `_refresh_state_unlocked()`; fourteen invoke
`_persist_state_unlocked()`. `commit_reservation` and `release_reservation`
refresh but never persist — they mutate only the budget and audit ledgers,
which are already per-entity and durable.

### What the state actually holds

| Collection | Grows with | Pruned? | How `authorize` uses it |
|---|---|---|---|
| `_authorizations` | one row per request, forever | **never** | one point lookup by `request_id` |
| `_leases` | one row per allow, forever | **never** | one point lookup by `lease_id` (commit only) |
| `_approvals` | one row per REVIEW | never | count of `PENDING`, and one lookup |
| `_agents` | agent count | n/a | one lookup by `agent_id` |
| `_intents` | intent count | never | one lookup by `intent_id` |
| `_revoked_agents` | agent count | n/a | one membership test |
| `_authorization_counts` | agents × days | never | one lookup by `(agent_id, date)` |
| `_fleet_stopped` / `_fleet_epoch` | constant | n/a | read, and incremented on stop |

Confirmed by grep: there is no `pop`, `del`, or `discard` for `_authorizations`
or `_leases` anywhere in `policy_engine.py`. `_revoked_agents.discard` exists
(`restore_agent`) and is the only removal in the whole state.

**Every hot-path access is a point lookup or a bounded aggregate.** Nothing in
`authorize_action` needs more than one row from either unbounded table.

---

## 2. Why `load()` / `save()` are required today

They are not required by the domain. They are required by one implementation
choice: `PolicyEngine` keeps its state in plain Python dicts and reads them
with `dict` syntax in roughly forty places. A dict cannot be partially
populated, so the only way to make a dict correct before a decision is to fill
it completely.

The three consequences that follow:

1. **Correctness across replicas needs a fresh read.** Replica B must see a
   lease replica A issued, so `_refresh_state_unlocked()` runs at the top of
   every operation rather than once at startup. Load frequency is therefore
   per-request, not per-process.
2. **Writes need a diff.** Because the engine hands back a whole snapshot,
   `save()` cannot know what changed without comparing against a baseline —
   hence `self._baseline` and the `deepcopy` that maintains it.
3. **The unit of atomicity is the snapshot.** All state writes for one
   operation land in one transaction because they are one `save()` call.

Point (3) is the only property worth preserving. Points (1) and (2) are costs
paid to keep dicts.

---

## 3. Proposed per-entity persistence model

Follow the pattern `budget.py` already established and Decisions #7 endorsed: a
protocol, an in-memory implementation, a Postgres implementation, one shared
contract test class run against both.

`StateRepository` becomes per-entity. Every method is a point lookup, a bounded
query, or an atomic write:

```python
class StateRepository(Protocol):
    # --- agents -------------------------------------------------------
    def get_agent(self, agent_id: str) -> AgentProfile | None: ...
    def put_agent(self, agent: AgentProfile) -> None: ...
    def list_agents(self) -> tuple[AgentProfile, ...]: ...        # bounded by agent count

    # --- intents ------------------------------------------------------
    def get_intent(self, intent_id: str) -> IntentPassport | None: ...
    def put_intent(self, intent: IntentPassport) -> None: ...
    def query_intents(self, *, customer_id: str | None, agent_id: str | None,
                      limit: int) -> tuple[IntentPassport, ...]: ...

    # --- authorizations (idempotency) ---------------------------------
    def get_authorization(
        self, request_id: str
    ) -> tuple[ActionRequest, AuthorizationResult] | None: ...
    def claim_authorization(
        self, request_id: str, request: ActionRequest, result: AuthorizationResult
    ) -> bool: ...                    # INSERT ... ON CONFLICT DO NOTHING; True if we won
    def put_authorization(
        self, request_id: str, request: ActionRequest, result: AuthorizationResult
    ) -> None: ...                    # unconditional update, for approve/reject

    # --- leases -------------------------------------------------------
    def get_lease(self, lease_id: str) -> AuthorizationLease | None: ...
    def put_lease(self, lease: AuthorizationLease) -> None: ...

    # --- approvals ----------------------------------------------------
    def get_approval(self, request_id: str) -> HumanApproval | None: ...
    def put_approval(self, approval: HumanApproval) -> None: ...
    def count_pending_approvals(self) -> int: ...
    def query_approvals(self, *, limit: int) -> tuple[HumanApproval, ...]: ...

    # --- revocation ---------------------------------------------------
    def is_revoked(self, agent_id: str) -> bool: ...
    def revoke_agent(self, agent_id: str) -> int: ...   # atomic epoch increment
    def restore_agent(self, agent_id: str) -> bool: ...
    def revoked_agents(self) -> frozenset[str]: ...     # bounded by agent count

    # --- velocity counters --------------------------------------------
    def increment_authorization_count(self, agent_id: str, day: date) -> int: ...
    def authorization_count(self, agent_id: str, day: date) -> int: ...

    # --- fleet and policy metadata ------------------------------------
    def metadata(self) -> GovernanceMetadata: ...
    def stop_fleet(self) -> GovernanceMetadata: ...     # atomic epoch increment
    def resume_fleet(self) -> GovernanceMetadata: ...
    def set_policy_version(self, version: str, revision: int) -> None: ...

    # --- unit of work --------------------------------------------------
    def transaction(self) -> ContextManager[None]: ...
    def close(self) -> None: ...
```

`GovernanceState` and `empty_state()` are deleted. So are
`_refresh_state_unlocked` and `_persist_state_unlocked`.

### `PolicyEngine` keeps a repository, never a snapshot

`state_repository` stops being optional and defaults to
`InMemoryStateRepository()`, exactly as `budget_ledger` defaults to
`InMemoryBudgetLedger()`. That deletes every `if self.state_repository is None`
branch and leaves one code path. `PolicyEngine()` with no arguments keeps
working, entirely in memory, with identical behaviour — the in-memory
repository holds the same dicts the engine holds today, behind the same lock.

The engine's decision logic — `_evaluate_unlocked`, `_evaluate_rego_unlocked`,
`_derive_risk`, `_check`, `_check_required_attributes`, `_conflicting_fields`,
`_same_idempotent_request` — is not touched. What changes is only how those
functions obtain the agent, intent, revocation flag and counter they read.

### Rejected: a Mapping façade over the repository

The minimal-diff alternative is to replace `self._authorizations` with an
object implementing `__getitem__` / `get` / `values` that issues queries
underneath, leaving `PolicyEngine`'s body untouched. Rejected for three
reasons:

- `sum(... for approval in self._approvals.values())` in `authorize_action`
  would silently stay a full-table read. The façade hides which accesses are
  cheap.
- `self._authorization_counts[key] += 1` cannot be made atomic behind a
  Mapping interface — `__getitem__` then `__setitem__` is a read-modify-write
  by construction.
- It puts network I/O behind dict syntax while `self._lock` is held, which
  makes lock-hold time invisible at the call site.

---

## 4. Mutation mapping

Every current state mutation, and what replaces it.

| Method | Today | Becomes |
|---|---|---|
| `register_agent` | `_agents[id] = agent`; save-all | `put_agent(agent)` — `INSERT … ON CONFLICT DO UPDATE` |
| `register_intent` | `_intents[id] = intent`; save-all | `put_intent(intent)` |
| `update_agent_policy` | `_agents[id] = updated`; `_policy_revision += 1`; save-all | `put_agent(updated)` + `set_policy_version(…)`, one transaction |
| `revoke_agent` | `_revoked_agents.add`; `_revocation_epochs[id] = get(id,0)+1`; save-all | `revoke_agent(id)` → `UPDATE … SET revocation_epoch = revocation_epoch + 1` returning the new value |
| `restore_agent` | `_revoked_agents.discard`; save-all | `restore_agent(id)` → `DELETE FROM agent_revocations WHERE agent_id = %s` |
| `stop_fleet` | `_fleet_stopped = True`; `_fleet_epoch += 1`; save-all | `stop_fleet()` → `UPDATE … SET fleet_stopped = TRUE, fleet_epoch = fleet_epoch + 1 RETURNING fleet_epoch` |
| `resume_fleet` | `_fleet_stopped = False`; save-all | `resume_fleet()` |
| `authorize_action` idempotency read | `_authorizations.get(id)` after full load | `get_authorization(id)` — PK lookup |
| `authorize_action` pending count | `sum(… for … in _approvals.values())` | `count_pending_approvals()` — indexed aggregate |
| `authorize_action` DENY / queue-full write | `_authorizations[id] = …`; save-all | `claim_authorization(id, …)` |
| `authorize_action` REVIEW write | `_approvals[id] = …`; `_authorizations[id] = …`; save-all | `put_approval(…)` + `claim_authorization(…)`, one transaction |
| `_issue_authorization_unlocked` | `_authorization_counts[(a,d)] += 1`; `_leases[id] = lease`; `_authorizations[id] = …`; save-all | `increment_authorization_count(a, d)` (atomic) + `put_lease(lease)` + `claim_authorization(…)`, one transaction |
| `approve_action` | `_approvals[id] = replace(…)`; then issue; save-all | `put_approval(…)` + the issue writes, one transaction |
| `reject_action` | `_approvals[id] = …`; `_authorizations[id] = …`; save-all | `put_approval(…)` + `put_authorization(…)`, one transaction |
| `commit_reservation` | reads `_leases[id]`, `_revoked_agents`, `_fleet_*`; no save | `get_lease(id)`, `is_revoked(a)`, `metadata()` — three point reads, still no state write |
| `release_reservation` | reads only | `metadata()` + ledger call; no state write |
| `evaluate` / `_evaluate_unlocked` | reads `_agents`, `_intents`, `_revoked_agents`, `_fleet_*` | `get_agent`, `get_intent`, `is_revoked`, `metadata()` |
| `_derive_risk` | `_authorization_counts[(a,d)]` | `authorization_count(a, d)` |
| `list_agent_states` | iterates `_agents` | `list_agents()` — bounded |
| `list_intents` | filters `_intents.values()` in Python | `query_intents(customer_id=…, agent_id=…)` — indexed |
| `list_approvals` | sorts `_approvals.values()` | `query_approvals(limit=…)` — indexed, paginated |
| `record_execution` | reads `_agents`; no state write | `get_agent(id)`; unchanged otherwise |
| `fleet_stopped` / `fleet_epoch` properties | full load, read one field | `metadata()` — one row |

Three atomic-increment conversions are marked in bold intent above:
`revoke_agent`, `stop_fleet` and `increment_authorization_count`. Each is a
read-modify-write today. See §12.

---

## 5. Transaction and concurrency analysis

### What is atomic today

Less than the code reads as. One `authorize_action` that reaches ALLOW already
spans **at least four independent transactions**:

1. `budget_ledger.reserve(...)` — its own pool, its own `BEGIN`, commits first
2. `audit_ledger.append("policy.evaluated", …)` — its own pool, autocommit
3. `audit_ledger.append("budget.reserved", …)` — another autocommit
4. `repository.save(...)` — one transaction covering all state writes

A crash between (1) and (4) already leaves a held reservation with no
authorization record. The in-process `RLock` hides this from a single-replica
test but does nothing across replicas.

### What the design preserves

Only property (4): all *state* writes for one operation land in one
transaction. `repository.transaction()` gives the engine an explicit unit of
work, opened at the top of each mutating method and covering exactly the writes
`save()` covers today. Ordering is unchanged — budget first, then state — so no
state transaction is held open across a call into the budget pool, which would
invite a cross-pool deadlock.

**Cross-ledger atomicity is not achieved today and is not achieved here.** The
honest fix is one connection shared by budget, state and audit for the duration
of an operation, which is possible once the shared pool exists but is a larger
change touching `budget.py`, `audit.py` and `persistence.py` together. Deferred
deliberately, and named in the threat model rather than implied away.

### What the design strengthens

`claim_authorization` replaces check-then-write with
`INSERT … ON CONFLICT DO NOTHING RETURNING request_id`. Exactly one caller wins
the row; the loser re-reads and returns the winner's result. This closes a race
that is open today — see §12, item 1.

### Lock-hold time

`self._lock` currently guards dict mutation, which is free. Under the redesign
it would guard network round trips. Because Postgres is now the authority for
every shared value, the `RLock` is no longer load-bearing for cross-replica
correctness — it only prevents two threads in one process interleaving. It
stays (removing it is a separate change with its own risk) but each critical
section shrinks from "load 20k rows, mutate, write 20k rows" to "a handful of
point queries", so contention falls rather than rises.

---

## 6. Required indexes

Existing primary keys already serve every point lookup:
`authorization_records(request_id)`, `authorization_leases(lease_id)`,
`approval_requests(request_id)`, `agent_policies(agent_id)`,
`customer_intents(intent_id)`, `agent_revocations(agent_id)`,
`authorization_counters(agent_id, budget_date)`.

What is missing is that the fields the bounded queries filter on live **inside
the JSONB payload**, so they cannot be indexed as they stand. Migration `0006`
promotes them to stored generated columns, which cannot drift from the payload
because Postgres derives them:

```sql
ALTER TABLE approval_requests
  ADD COLUMN status TEXT
    GENERATED ALWAYS AS (payload -> 'status' ->> 'value') STORED,
  ADD COLUMN created_at TIMESTAMPTZ;          -- plain column, set on insert

CREATE INDEX approval_requests_pending_idx
  ON approval_requests (status) WHERE status = 'pending';
CREATE INDEX approval_requests_recent_idx
  ON approval_requests (created_at DESC);

ALTER TABLE customer_intents
  ADD COLUMN customer_id TEXT GENERATED ALWAYS AS (payload ->> 'customer_id') STORED,
  ADD COLUMN agent_id    TEXT GENERATED ALWAYS AS (payload ->> 'agent_id')    STORED;

CREATE INDEX customer_intents_owner_idx ON customer_intents (customer_id, agent_id);

ALTER TABLE authorization_records ADD COLUMN created_at TIMESTAMPTZ;
CREATE INDEX authorization_records_recent_idx ON authorization_records (created_at DESC);

ALTER TABLE authorization_leases ADD COLUMN expires_at TIMESTAMPTZ;
CREATE INDEX authorization_leases_expiry_idx ON authorization_leases (expires_at);
```

`expires_at` on intents is deliberately **not** a generated column: the payload
stores it as `{"$datetime": "..."}` and casting text to `timestamptz` is STABLE,
not IMMUTABLE, so Postgres rejects it in a generated column. Expiry filtering
stays in Python over the already-narrowed `(customer_id, agent_id)` result,
which is bounded by one customer's intent count.

---

## 7. Keeping history queryable without loading it

The engine stops reading history entirely. Nothing on the authorization path
enumerates `authorization_records` or `authorization_leases` — both are reached
only by primary key.

History remains available to operators through two paths that already exist or
are cheap to add:

- **The audit ledger**, which already exposes
  `as_dicts(after_sequence=…, limit=…)` — keyset pagination over an ordered
  primary key, never a full scan. This is the Decisions feed Stage 4 needs.
- **Paginated record queries**, added behind `created_at DESC` indexes, for the
  console to show a request's stored decision. Bounded by `limit`, never loaded
  into engine state.

**Pruning stops being urgent.** Today history must be small because it is
loaded in full; a primary-key lookup is O(log n), so a table of ten million
authorization records costs the same as one of ten thousand. Retention becomes
a storage-cost decision rather than a latency one, which matters because
deleting an authorization record silently weakens idempotency for any request
replayed after the horizon. `AuditRetentionPolicy` already exists as the place
to express that when someone chooses to.

---

## 8. Interaction with the ADR 004 `org_id` boundary

The two designs compose cleanly, and this one should land first.

- Every accessor gains `AND org_id = %s` from the value the repository was
  constructed with. Point lookups stay point lookups against composite keys
  `(org_id, request_id)`, `(org_id, lease_id)`, and so on. No new query shapes.
- The engine still never learns organisations exist, which is ADR 004's
  central decision.
- **ADR 004's stated memory cost disappears.** That ADR notes that N cached
  engines hold N full state snapshots. After this change an engine holds *no*
  snapshot — only a repository handle — so the per-org engine cache becomes
  cheap and its eviction policy stops being a correctness concern. ADR 004's
  "Consequences" section should be amended when this lands.
- The shared connection-pool registry that ADR 004 requires is needed by this
  change too, for a different reason: per-entity operations issue more, smaller
  queries, so pool efficiency matters more. Building it once serves both.
- Ordering: doing tenancy first would mean writing `org_id` into `load()` and
  `save()` and then deleting both. Doing persistence first means tenancy is a
  predicate added to methods that already exist.

---

## 9. Complexity of `authorize_action`, before and after

Let `R` = authorization records, `L` = leases, `P` = approvals, `A` = agents,
`I` = intents, all cumulative; `H` = an agent's outstanding holds, bounded by
`max_outstanding_reservations` (default 20); `Q` = pending approvals, bounded by
`max_pending_approvals` (default 500).

| | Today | Proposed |
|---|---|---|
| State read | `O(R + L + P + A + I)` rows fetched and `_decode`d | `O(log R)` + `O(log A)` + `O(log I)` + `O(1)` metadata |
| Baseline maintenance | `O(R + L + P + A + I)` `deepcopy`, twice per call | none |
| Budget | `O(H)` | `O(H)` unchanged |
| Approval capacity check | `O(P)` Python scan | `O(log Q)` indexed aggregate |
| State write | diff over all collections, `O(R + L + P + A + I)` | `O(log R)` — at most three row writes |
| **Total** | **`O(total history)`** | **`O(log history)`** |

Measured today: 2.6 ms at 6 rows, 4,111 ms at 20,005 rows. The proposed shape
has no term that grows with accumulated rows, so the target is a flat curve —
which is what the regression test in §11 asserts, rather than a latency number
this document would otherwise be inventing.

---

## 10. Files and functions that change

**`src/intentguard/persistence.py`** — the bulk of the work. Delete
`GovernanceState`, `empty_state`, `PostgresStateRepository.load`/`.save`/
`_sync_metadata`/`_sync_payloads`/`_sync_authorizations`, and the `_baseline`
field. Add the per-entity protocol, a rewritten `InMemoryStateRepository`
(dicts plus an `RLock`, semantically identical to today's engine dicts), a
rewritten `PostgresStateRepository`, and `GovernanceMetadata`. Keep `_encode` /
`_decode` unchanged — the payload format does not change, which is what lets
migration `0006` be additive.

**`src/intentguard/policy_engine.py`** — state access only. Remove
`_refresh_state_unlocked`, `_persist_state_unlocked`, and the nine instance
dicts/sets. Default `state_repository` to `InMemoryStateRepository()`. Rewrite
the ~40 dict accesses listed in §4 as repository calls. `_evaluate_unlocked`,
`_evaluate_rego_unlocked`, `_derive_risk`, `_check`,
`_check_required_attributes`, `_conflicting_fields`, `_same_idempotent_request`,
`_to_budget_reservation`, `_deny_for_budget_unlocked` and the risk-weight
constants are untouched.

**`src/intentguard/pool.py`** (new) — `shared_pool(conninfo)`, a memoised
`ConnectionPool` registry. Callers in `audit.py:204`, `budget.py:384`,
`persistence.py:176`, `intent.py:268`, `intent.py:335`, `policy.py:95`,
`execution_lease.py:97` and `booking_connector.py:191` switch to it.

**`migrations/0006_per_entity_state.sql`** (new) — the generated columns and
indexes in §6. Additive; no existing row is rewritten.

**`src/intentguard/api.py`** — likely unchanged. `configured_engine()` already
injects the repository; only the construction call changes if the signature
does. Handlers are untouched.

**Unchanged:** `audit.py` logic, `budget.py` logic, `models.py`, `policy.py`
logic, `abuse.py`, `agent.py`, `observability.py`, `prototype/`.

---

## 11. Test plan

**Regression — this is the test whose absence let the problem ship.**
Seed 50,000 authorization records and leases, then assert `authorize` median
latency at 50,000 rows is within a small constant factor of the same measurement
at 1,000 rows. Asserting a *ratio* rather than an absolute millisecond figure
keeps it meaningful on slower CI hardware. Skipped without Postgres, like the
existing ledger tests.

**Contract.** Extend `tests/test_persistence.py`'s `SharedStateContract` to
cover every new protocol method, run against both `InMemoryStateRepository` and
`PostgresStateRepository`, in the style Decisions #7 established. The three
existing contract tests — lease issued by one instance committed by another,
fleet stop and revocation seen after restart, approval and idempotency
surviving restart — must pass unchanged. They are the semantic guarantee.

**Concurrency**, in the style of `PolicyEngineConcurrencyTest` in
`tests/test_budget_ledger.py`: real OS processes and a `multiprocessing.Barrier`,
not threads.

- *Idempotency race*: N processes call `authorize_action` with the **same**
  `request_id` simultaneously. Assert exactly one reservation is created and
  every process receives the same `lease_id`. This test fails against the
  current implementation — see §12, item 1.
- *Fleet epoch*: N processes call `stop_fleet` simultaneously; assert the final
  epoch equals N.
- *Velocity counter*: N processes authorize for one agent simultaneously;
  assert `authorization_count` equals N.
- *Budget cap under the new path*: re-run the existing 8-process cap test
  unchanged, confirming the ledger's guarantee is untouched.

**Full suite.** All 241 existing tests pass. Any test that must change is a
signal the redesign altered behaviour and needs justifying individually.

**Live run.** `./scripts/start-demo.sh` plus a real authorize/commit cycle
against Postgres, because starting the app has caught things CI did not.

---

## 12. Risks needing explicit approval before implementation

### Risk 1 — the redesign silently fixes a live idempotency race (**pre-existing defect**)

`authorize_action` reads `self._authorizations.get(request_id)` and, on a miss,
issues a new reservation and lease. Across two replicas that is check-then-act
with no shared guard: both refresh, both miss, both call
`budget_ledger.reserve()` with a freshly generated `reservation_id`, both
succeed if headroom allows, and both write `authorization_records` for the same
`request_id` under `ON CONFLICT DO UPDATE`.

The daily cap still holds — both reservations are counted against it — but the
idempotency guarantee does not. **One `request_id` can hold two reservations
and produce two committed payments.** The in-process `RLock` prevents this
within one replica and does nothing across the multi-replica deployment the
project documents.

**Demonstrated, not inferred.** Eight replicas in separate OS processes, one
shared Postgres, all calling `authorize_action` with the same `request_id`
behind a barrier:

```
authorization_records rows for that request_id : 1
distinct lease_ids handed back to callers      : 8
reservations rows for that request_id          : 8
budget_days (committed, reserved)              : (0.0000, 800.0000)
```

Every replica returned ALLOW with its own reservation and its own signed lease.
800 is held against the cap for a single 100 request, and each of those eight
leases is independently committable through `commit_reservation` — the status
check that prevents replay is per *reservation*, and there are eight of them.
One `request_id` therefore authorizes up to eight refunds.

The single `authorization_records` row is the `ON CONFLICT DO UPDATE` in
`_sync_authorizations` collapsing eight writes into one, which is why the
idempotency table looks correct while the money does not.

Approval needed on: whether to write the failing test and fix this as a
standalone change *before* the redesign, so the fix is visible and attributable
rather than arriving as a side effect of a large refactor. My recommendation is
yes — the finding is worth more as its own commit.

### Risk 2 — atomic counters change risk scores under concurrency (**behaviour change**)

`_authorization_counts[(agent, date)] += 1` is a read-modify-write, and
`save()` merges it with:

```sql
authorization_count = GREATEST(existing, EXCLUDED.authorization_count)
```

Concurrent increments therefore converge to the **maximum** of the replicas'
local values, not their sum. Two replicas that each observe 5 and write 6 leave
the counter at 6 when seven authorizations occurred.

That counter feeds `_derive_risk` via `RISK_POINTS_PER_PRIOR_AUTHORIZATION`, so
today an agent spreading requests across replicas accumulates less velocity
risk than one going serially — the escalation-to-review control under-fires for
exactly the traffic pattern most worth escalating. The same lost update affects
`_fleet_epoch` in `stop_fleet`: two concurrent stops leave epoch at 1 rather
than 2.

Replacing both with `SET x = x + 1` is the correct behaviour and is what the
per-entity model naturally gives. **It is still a behaviour change**: velocity
scores rise under concurrent load, so some actions that return ALLOW today will
return REVIEW after the change, and the approval queue will see traffic it does
not see now. Test fixtures that assert a specific risk score under concurrency
may move.

Approval needed on: accepting more REVIEW decisions as the correct outcome. I
recommend yes, and recommend landing it as its own commit with the risk-score
delta measured, so the change in review volume is a number rather than a
surprise.

### Risk 3 — cross-ledger atomicity stays unsolved

Budget, state and audit remain three transactions per operation. This design
does not make it worse and does not fix it. A crash mid-operation can still
leave a reservation with no authorization record. Approval needed only on
accepting this as out of scope; the alternative is a single shared connection
per operation across all three ledgers, which is a larger change I would not
bundle here.

### Risk 4 — `restore_agent` loses the revocation epoch

`restore_agent` discards the agent from `_revoked_agents` but leaves
`_revocation_epochs[agent_id]` intact. The two repositories then disagree:

- `PostgresStateRepository.save` runs `DELETE FROM agent_revocations` for any
  agent that left `revoked_agents`, so the epoch is gone from the database. The
  next `load()` does not restore it, and a re-revocation starts again at 1.
- `InMemoryStateRepository.save` deep-copies the whole state including
  `revocation_epochs`, so the epoch survives and a re-revocation continues at 2.

The shared contract test does not cover a revoke → restore → revoke cycle, which
is why the divergence is invisible today. The redesign has to pick one, and
whichever it picks is a behaviour change for one of the two implementations.

Approval needed on the intended semantics. My recommendation: keep the row and
set an `active` flag, preserving monotonic epochs, because an epoch that can
repeat weakens the lease-invalidation check in `commit_reservation`.

---

## Verification

Done when: the §11 regression test shows authorize latency flat between 1,000
and 50,000 rows; all 241 existing tests pass unchanged; the three concurrency
tests pass; and `scripts/measure-state-load-curve.py` re-run against the new
implementation produces a flat curve to append to
`docs/evidence/state-load-curve-2026-09-02.txt`.
