# ADR 008: Require claim context on refund settlement actions

- Status: Implemented; verification recorded below
- Date: 2026-10-21
- Implements the first code slice of ADR 006
- Extends ADR 003's enforcement boundary

## Problem

The refund desk supplied `RefundClaim`, but the conversational planner's
`ProposedAction` had no claim field. Both evaluators treated an absent claim as
permission to skip remedy rules. A direct caller could omit the same field.

A 100 INR refund with a photoless defect claim was denied because policy allowed
only shipping refund; the same action without that claim was allowed inside its
agent, intent, and budget ceilings. The general ceilings remained enforced, but
the newer claim rules were optional on exactly the actions they governed.

## Decision

Require a structured claim for `refund_order`, `refund_shipping`, and
`issue_goodwill_credit`. A missing or null claim produces the blocking finding
`CLAIM_REQUIRED`, a DENY decision, and no reservation, execution lease, or risk
approval entry. High declared risk does not turn missing context into an
approvable payment. The denial is audited and follows existing idempotency rules.

Keep `claim` optional on the generic request type. Booking, payment, and other
unrelated actions retain their existing contracts. Service rescheduling is not
newly subjected to refund rules in this slice.

Enforce the requirement in the built-in engine and the bundled Rego policy.
Also enforce it when consuming a Rego result in Python: a durable installation
may still have an older published policy, which a source-file update does not
replace. This guard can only restrict that result and cannot grant authority.
The applied policy version and evaluator remain recorded; the extra blocking
finding explains the enforcement-layer refusal.

Move the existing HTTP claim payload validator into `claims.py` and share it
with model output validation. Both paths use the same conversion into
`RefundClaim`. Closed reason/evidence enums, bounded references, and rejection
of unknown fields remain in place. Order value must be positive and finite.
Evidence kinds are derived from cited artifacts, never accepted as a separate
model-controlled evidence list.

Extend the model tool schema, validated proposal, and agent-to-engine request to
carry the claim. Increment the prompt version to `financial-proposal-v4`.
The prompt tells the model to leave context absent when required facts are
missing rather than invent an order value, delivery age, or evidence reference.
Prompt guidance is not enforcement: omission is still denied by the engine.

The scripted planner does not invent these facts. A bare scripted refund request
now produces a contextual denial. The refund desk remains the offline path for
supplying a structured case. Model-backed planning can extract explicitly
provided context, subject to the shared schema and deterministic remedy policy.

## Alternatives

- **Require the claim only in the HTTP schema:** rejected; direct engine and
  agent callers would still bypass it, and omission would not be a policy
  decision with an audit record.
- **Add an optional claim to the planner without an enforcement guard:**
  rejected; the model or direct caller could continue omitting it.
- **Update only bundled Rego:** rejected; stored policies would keep the hole.
- **Assume order value equals the proposed refund or invent evidence:** rejected;
  missing context is a reason to refuse, not permission to manufacture facts.

## Compatibility and limits

This intentionally changes claim-less refund settlements from ALLOW/REVIEW to
DENY. Clients must supply `reason`, `order_value`, and `days_since_delivery`;
the applicable remedy policy may additionally require evidence citations.
Malformed supplied claims remain HTTP 422 or a planner validation failure.
An omitted claim is a valid HTTP 200 policy denial, not an infrastructure error.

Existing issued authorizations are not rewritten and leases are not retroactively
revoked by this change. Existing request IDs continue to return their historical
outcomes; a corrected proposal needs a new ID. Pending approvals are re-evaluated
and cannot newly issue a lease for a claim-less refund.

Claims and artifact references are still assertions. This change neither checks
merchant records nor verifies that a photo exists or supports the claim. It
does not implement compensation floors, funded alternatives, durable case
escalation, or automatic notification. Those remain ADR 006 work. A denial here
must not be described as a human-review case already created.

## Verification

`tests/test_required_claims.py` exercises direct engine calls, authenticated HTTP,
the scripted planner, model tool-call responses, and the HTTP chat endpoint
against built-in and OPA evaluation. It covers missing/null context, malformed
claims, evidence citations, complaint exclusion from audit, persistence codec
round trips, valid refund/shipping/credit proposals, and older published Rego.

The stock policy's native tests also cover a missing entire claim object and a
null claim. Existing risk-review fixtures now supply a valid claim so the
permissiveness matrix continues to exercise ALLOW, REVIEW, and DENY.

Execution results and test-environment limitations are recorded in
[the verification report](../evidence/required-claims-2026-10-21.md): 393 backend
tests run, 391 passed and 2 intentional skips; native Rego, unified evaluation,
frontend type checking, and a real loopback HTTP check passed. No live model or
real payment was used for these deterministic checks.
