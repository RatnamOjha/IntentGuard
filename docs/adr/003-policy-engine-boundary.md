# ADR 003: Separate declarative policy decisions from stateful authorization

- Status: Accepted
- Date: 2026-08-30

## Context

IntentGuard needs reviewable policy-as-code without moving budget transactions,
cryptographic capability issuance, approvals, or audit side effects into the
policy evaluator. A model-generated proposal must never become permission by
itself.

## Decision

OPA/Rego is the policy decision point for pure, declarative rules. The Python
`PolicyEngine` remains the policy enforcement point and owns authenticated
state lookup, derived risk, atomic budget reservation, human-review lifecycle,
lease signing, revocation checks, and audit events.

The engine passes a normalized input document to OPA and receives an
`allow`, `deny`, or `review` result with stable findings. Published Rego
versions are validated before activation and support dry run, comparison, and
rollback. If OPA is configured but unavailable or returns invalid output, the
gateway fails closed before reserving money.

The LLM planner remains outside both boundaries. It can propose a typed action,
but only the deterministic authorization path can produce an execution lease.

## Consequences

- Policy changes are reviewable and versioned without duplicating transactional
  domain logic in Rego.
- The engine can preserve hard invariants even when policies evolve.
- OPA is a runtime dependency in policy-as-code mode, so its health and latency
  must be monitored.
- Policy inputs and outputs form a contract that requires compatibility tests.

## Alternatives considered

- Put all logic in Python: simpler deployment, but weaker policy review and
  operator workflow.
- Put reservations and approvals in Rego: rejected because OPA evaluation
  should be side-effect free.
- Let the LLM choose the final decision: rejected because model output is
  untrusted and nondeterministic.

## Verification

`policies/authorization.rego`, `tests/test_policy_as_code.py`, and
`tests/test_agent.py` cover the native policy matrix, lifecycle operations,
OPA outage behavior, and the proposal-versus-permission boundary.
