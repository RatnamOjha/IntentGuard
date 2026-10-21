# ADR 007: Retain the current stack and deliver the refund workflow in stages

- Status: Accepted
- Date: 2026-10-21
- Scope: Restart sequencing and technology choice
- Related: ADR 004 (tenancy), ADR 005 (persistence), ADR 006 (remedies)

## Context

The restart review considered whether Python was holding the product back.
The repository already implements authentication, signed consent, authorization,
budget reservations, revocation, policy versioning, and audit verification.
Replacing their language would require re-establishing those behaviors without
resolving the main gaps in the refund workflow.

The committed [state-load measurements](../evidence/state-load-curve-2026-09-02.txt)
show authorization growing from 2.6 ms at six seeded rows per table to 4,111 ms
at 20,005. These are historical local measurements, not a current deployment
benchmark. The current source still loads whole tables and deep-copies the state
on governed operations. That work grows with history in any language.

The OPA adapter also writes a temporary file and launches a subprocess per
evaluation. Tenant identity is wired, but governance repositories and published
policy remain shared. Neither issue requires replacing Python.

## Decision

Keep Python/FastAPI for enforcement, PostgreSQL for authoritative state,
OPA/Rego for configured declarative policy, and the existing React/TypeScript
console. Preserve in-memory implementations for offline tests and demonstrations.
No framework migration or additional infrastructure is part of this restart.

Work in small, reviewable changes, recording the problem, decision, alternatives,
consequences, implementation status, and verification as each boundary changes.
Tracked ADRs hold durable architectural decisions. Local `Workflow.md` and
`Decisions.md` hold progress and working notes; they are gitignored and are not
the only record of a decision needed by another contributor.

The delivery order is:

1. Reconcile ADR 006 with one proposed remedy, enforced compensation bounds,
   recorded alternatives, and explicit case escalation.
2. Close the demonstrated claim omission in the conversational refund path and
   require context on refund actions governed by remedy policy.
3. Complete shared database pool management, tenant isolation, and per-company
   policy. Treat these as one isolation milestone with incremental changes;
   a scoped policy table alone does not make the service multi-tenant.
4. Replace whole-state persistence under ADR 005 before meaningful volume.
   Its historical race findings already fixed in the source must not be
   reimplemented from stale text. Resolve revocation-epoch semantics explicitly.
5. Implement remedy intervals, budget scopes, durable cases, and protected
   refund execution under ADR 006 in independently tested changes.

Tenant isolation before the larger persistence refactor preserves the earlier
delivery tradeoff: some scoped snapshot queries will later be replaced. Neither
multi-tenant rollout nor volume rollout is justified by the identity work alone.

Measure durable authorization latency after correcting the access pattern.
Then evaluate persistent OPA integration if subprocess overhead matters.
Reconsider the backend language only if profiling identifies a remaining
language/runtime limitation against a concrete workload and service objective.

## Alternatives

- **Rewrite in TypeScript, Go, or Rust now:** rejected; no measured language
  bottleneck justifies rebuilding the existing authorization contracts.
- **Build compensation features before fixing omitted claims:** rejected;
  additional claim-based controls would still be skipped by that path.
- **Complete every infrastructure concern before a working refund slice:**
  rejected; delivery should demonstrate one complete, bounded workflow while
  keeping explicit gates for tenant isolation and production volume.

## Verification and consequences

Each implementation change runs the tests relevant to its boundary. Persistence
and budget changes require real PostgreSQL and cross-process checks; in-memory
tests are not evidence of database isolation or crash consistency. Refund
integration requires a running authorize/execute/reconcile check, not just an
ALLOW response or an internal budget commit.

The restart review passed 157 targeted backend tests and frontend TypeScript
checking. It did not rerun the full PostgreSQL suite or deployment stack, and
does not establish current production readiness.

This ADR changes sequencing and records the stack decision. It introduces no
runtime feature and authorizes no public deployment or real payment.
