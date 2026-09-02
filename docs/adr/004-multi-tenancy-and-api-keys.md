# ADR 004: Own organisation identity in Postgres and scope tenancy at the repository boundary

- Status: Accepted
- Date: 2026-09-02

## Context

ADR 001 established authentication; ADR 002 made engine state durable. Neither
introduced a tenant. Today `grep -riE 'org(anisation|anization)?_id|tenant'`
over `src/` and `migrations/` returns nothing: every agent, intent, lease,
approval, policy version and audit event in the database belongs to one
implicit tenant. A second design partner cannot be onboarded without one
reading the other's decisions.

Three properties of the current code decide the shape of the fix.

**State is a whole-snapshot interface.** `StateRepository`
(`src/intentguard/persistence.py:53`) is `load()` / `save(state)`, not a set of
per-entity queries. `PostgresStateRepository.load` reads six tables with no
`WHERE` and no `LIMIT`, and `PolicyEngine` calls it at the top of every
governed operation — `authorize_action`, `commit_reservation`,
`release_reservation`, `approve_action` and `reject_action` among twenty call
sites. There are no queries to add an `org_id` predicate to; there is one query
per table that reads everything.

**The audit chain is global and singleton-keyed.** `audit_events` is
`sequence BIGINT PRIMARY KEY` over one sequence, and `audit_metadata` is a
`singleton BOOLEAN PRIMARY KEY ... CHECK (singleton)` row holding one
checkpoint. `governance_metadata` uses the same singleton pattern for fleet
stop and policy version. The schema asserts single tenancy structurally.

**Backends open their own connection pools.** There are eight
`ConnectionPool(...)` constructions across `audit.py`, `budget.py`,
`persistence.py`, `intent.py`, `policy.py`, `execution_lease.py` and
`booking_connector.py`, each `min_size=1, max_size=8`. One fully configured
`PolicyEngine` already holds six. Any design that instantiates an engine per
organisation multiplies that count directly.

One further constraint is easy to miss: `migrations/0005` creates
`one_published_policy` as a unique partial index on `(status) WHERE status =
'published'`. It permits exactly one published policy across the entire
installation. Left alone, the second organisation to publish a policy gets a
unique-violation.

## Decision

### 1. Organisation identity lives in our Postgres, not in the identity provider

An `organizations` table is the authority for tenancy. Keycloak remains
operator SSO only: a validated token yields a `subject`, and `org_members` maps
that subject to an organisation and a set of roles. No `org_id` claim is read
from a token.

This keeps tenancy independent of any IdP's claim shape, and it means an
organisation can exist before anyone from it has logged in — which is what
issuing a design partner an API key on day one requires.

Identifiers are opaque `org_` prefixed text, matching the existing `res_` and
`lease_` convention, so an organisation cannot be guessed by name.

### 2. Tenancy is enforced at the repository boundary, not inside `PolicyEngine`

Every Postgres backend takes `org_id` at construction and applies it to every
statement it issues. `PolicyEngine` is not modified and never learns that
organisations exist; it continues to operate on the one tenant's state its
repositories hand it.

```
PostgresStateRepository(url, org_id=...)   → WHERE org_id = %s on all six loads,
                                             org_id on every insert and delete
PostgresAuditLedger(url, org_id=...)       → its own chain and checkpoint
PostgresBudgetLedger(url, org_id=...)      → per-org caps
PostgresPolicyRepository(url, org_id=...)  → per-org published policy
```

This satisfies the Stage 2 constraint of not touching `PolicyEngine` internals,
and it keeps all 241 existing tests constructing engines exactly as they do
now: the `org_id` parameter defaults to the default organisation created by the
migration.

### 3. One `PolicyEngine` per organisation, cached, over shared pools

`create_app` gains `engine_for(org_id)` in place of a single `app.state.engine`,
backed by a bounded LRU with a TTL. Handlers resolve the engine from
`principal.org_id`.

Because engine-per-org multiplies pool count, a module-level pool registry
keyed by connection string becomes mandatory, not an optimisation. All eight
construction sites move to `shared_pool(conninfo)`. Without this, roughly
sixteen organisations exhaust a default Postgres `max_connections` of 100 on
idle connections alone.

### 4. The audit chain is per organisation, with a per-organisation genesis

`audit_events` becomes `PRIMARY KEY (org_id, sequence)`; `audit_metadata` is
keyed by `org_id` instead of `singleton`. Each organisation gets an independent
sequence, head hash and event count, so an organisation can verify its own
history without being shown anyone else's events.

`audit_metadata` also gains a `genesis_hash` column. New organisations derive
theirs as `sha256("intentguard-audit-genesis:" + org_id)`; the default
organisation is backfilled with the existing `repeat('0', 64)` so its chain
continues to verify unchanged. The ledger reads its genesis from the row rather
than a constant.

`org_id` is deliberately **not** part of the hash input. Adding it would
require recomputing the hash of every existing event, which destroys the one
property a hash chain exists to provide. The per-organisation genesis achieves
the same end: an event copied from one organisation's chain into another's
carries the source organisation's genesis in its `previous_hash` and fails at
the first link.

### 5. API keys authenticate machine callers

An `api_keys` table holds `key_id`, `org_id`, `prefix`, `key_hash`, granted
roles, optional bound `agent_id` and `customer_id`, `created_at`,
`last_used_at`, `expires_at` and `revoked_at`.

Keys are formatted `ig_<env>_<32 chars base32>`, so a leaked key is
greppable by secret scanners and identifiable on sight. Verification looks the
row up by indexed `prefix`, then compares SHA-256 of the presented key against
`key_hash` with `hmac.compare_digest`.

SHA-256 rather than a password KDF is deliberate. Argon2 and bcrypt exist to
make brute force of low-entropy human-chosen secrets expensive; the secret here
is 160 bits from `secrets.token_bytes`, where the brute-force margin is already
astronomical, and this hash sits on the per-request authorization path where a
100ms KDF would dominate the 6.9ms p50 the gateway currently reports.

`last_used_at` is written at most once per 60 seconds per key, so an active
agent does not turn every authorization into an extra write.

Keys carry roles from the same vocabulary as tokens, and both produce the same
`Principal`. An agent key is issued with the `agent` role only, so it can
authorize, commit and release but cannot stop the fleet or edit policy.

### 6. Schema changes

Eighteen existing tables gain `org_id`: `agents`, `budget_days`,
`reservations`, `governance_metadata`, `agent_policies`, `customer_intents`,
`approval_requests`, `authorization_records`, `authorization_leases`,
`agent_revocations`, `authorization_counters`, `audit_events`,
`audit_metadata`, `intent_signing_keys`, `intent_nonces`,
`lease_signing_keys`, `connector_executions`, `policy_versions`.

Primary keys that were globally unique become composite, so two organisations
may each have an agent named `support-bot`. `one_published_policy` is rebuilt
on `(org_id) WHERE status = 'published'`.

`migrations/0006` is additive and backfills every existing row into a single
default organisation before applying `NOT NULL`, so an installed database
migrates without data loss and without a behaviour change.

## Consequences

- Two organisations cannot see each other's agents, decisions, approvals,
  policies or audit events, and each verifies its own chain independently.
- A design partner integrates with a key rather than a Keycloak realm, which is
  what makes Stage 6's "integrate in an afternoon" true rather than aspirational.
- `PolicyEngine` and its 1,495 lines are untouched, and the 23 test sites that
  construct one directly keep working against the default organisation.
- **This does not fix the whole-snapshot load.** Each request still reloads one
  organisation's entire state. Per request it improves — a small organisation no
  longer scans every organisation's rows — but N cached engines hold N
  snapshots in memory. At design-partner scale this is fine; the growth curve is
  being measured separately before deciding whether to replace `load()`/`save()`
  with per-entity queries.
- `GET /v1/audit/status` reads the full event list twice (once for `events`,
  once inside `verify()` via `first_invalid_link`). Per-org chains shrink each
  scan but do not bound it.
- An operator belonging to two organisations must select one; the first
  implementation binds a subject to exactly one organisation and returns 403
  otherwise, deferring multi-org membership until a partner asks for it.
- `booking_connector` keeps its own unscoped `connector_executions` table in
  this change. It is a simulated provider standing outside the trust boundary,
  not a store of tenant governance state; scoping it is tracked separately.

## Alternatives considered

- **Thread `org_id` through `PolicyEngine`.** Rejected: it rewrites the largest
  file in the codebase, changes every test, and violates the Stage 2 constraint,
  to reach the same isolation that a repository parameter reaches.
- **Postgres row-level security.** Attractive, and the natural fit if the
  application used per-entity queries. It does not help a `load()` that already
  reads whole tables, and it puts the security boundary in a place the test
  suite can only exercise against a live database, where today a large part
  of the Postgres-guarded suite skips or errors when one is absent.
- **`org_id` as a Keycloak claim.** Rejected per the decision above: it couples
  tenancy to an IdP that ADR 001 chose for operator SSO, and leaves no way to
  create an organisation before its first human login.
- **One global chain with an `org_id` column and filtered reads.** Rejected:
  an organisation could not verify its own history without the hashes of
  everyone else's events, which is precisely the property a buyer's auditor asks
  about.
- **Argon2id for API key hashing.** Rejected for the entropy and latency
  reasons above. Revisit if keys ever become user-chosen.

## Verification

Done when, and each covered by a test:

- an unauthenticated request gets 401, and a request with a revoked or expired
  key gets 401;
- two organisations each register an agent with the same `agent_id` and neither
  sees the other's agents, decisions, approvals or audit events;
- an agent API key cannot stop the fleet or publish a policy;
- each organisation's audit chain verifies independently, and an event moved
  between organisations is rejected at the first link;
- both organisations can hold a published policy simultaneously;
- a fleet stop in one organisation does not halt another;
- the existing 241 tests pass unchanged against the default organisation.
