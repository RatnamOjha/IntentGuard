# ADR 002: Keep authoritative governance state in PostgreSQL

- Status: Accepted
- Date: 2026-08-30

## Context

Process-local state is fast and convenient, but replicas disagree after a
restart or concurrent update. Governance state must survive reconstruction and
enforce one shared budget across every gateway instance. Redis is useful for
ephemeral coordination, but eviction or an outage must not erase authority.

## Decision

PostgreSQL is the source of truth for agents, intents, policy versions,
approvals, authorization and idempotency records, budget reservations, leases,
revocation epochs, fleet state, velocity counters, connector executions, and
audit checkpoints. The budget reservation check and write are atomic in SQL:

```text
committed + reserved + requested <= daily budget
```

Repository protocols isolate the domain engine from storage. In-memory
implementations remain available for deterministic tests and offline demos.
Redis is used for distributed sliding-window rate limits and may later
accelerate notifications or coordination, but it is never authoritative.

## Consequences

- Multiple gateway processes share budget exposure, revocations, approvals,
  leases, and idempotent outcomes.
- Database unavailability makes readiness fail and affected operations fail
  closed.
- Schema changes require ordered, idempotent migrations.
- The in-memory mode is deliberately a single-process demonstration mode, not
  evidence of multi-replica durability.

## Alternatives considered

- Redis as the primary store: rejected because eviction and persistence modes
  complicate the authority boundary.
- Event sourcing for every state transition: valuable at larger scale, but too
  much operational surface for this slice.
- Per-replica state with eventual reconciliation: incompatible with a hard
  financial budget invariant.

## Verification

`tests/test_budget_ledger.py` exercises cross-process contention against real
PostgreSQL. `tests/test_persistence.py` proves restart and cross-instance lease,
revocation, fleet, approval, and idempotency behavior.
