# ADR 006: One proposed remedy, enforced compensation bounds, and recorded alternatives

- Status: Accepted design direction; required-claim omission fixed in ADR 008,
  remaining implementation pending
- Created: 2026-09-22
- Revised: 2026-10-21
- Replaces this ADR's original review-threshold and recursive-fallback proposal
- Depends on tenant isolation and per-company policy from ADR 004
- Persistence work remains governed by ADR 005

## Context and current implementation

The product controls incorrect compensation in either direction when an AI
support agent proposes a settlement. It must respect the company's policy,
customer consent, agent authority, and available budgets.

The current implementation has ceilings, one claim-selected `Remedy(kind, cap)`,
and per-agent daily budgets. It has no compensation floor, alternative-remedy
set, remedy-specific budget pots, shared company ceiling, or customer-dispute
workflow. Organization identity exists, but governance repositories and the
published policy remain shared. These are implementation gaps, not guarantees
established by accepting this document.

The refund desk submits structured claims. At the restart review,
`GovernedAgent` did not: its proposal type had no claim and its actions skipped
claim-specific rules. [ADR 008](008-required-refund-claim-context.md) closes that
omission for refund settlements and carries model claims through shared
validation. Independent verification of merchant facts remains unimplemented.

The 30-second default in `PolicyEngine.authorize_action` is an execution lease
and internal budget-reservation lifetime. It is not a bank hold or an offer
acceptance deadline. Human approval currently waits without a reservation and
re-evaluates before issuing fresh authority. A future customer-choice workflow
could use that separation too; guaranteed offers would need additional design.

## 1. The agent proposes one remedy

Use Model A for the first complete refund workflow. The agent proposes one
remedy and amount; the engine authorizes only that exact proposal. The ordinary
path is proposal, authorization, protected execution, and outcome recording.
The engine never silently substitutes a different action or changes the amount.

Policy also enumerates the alternatives for the case. They support audits and
human review, without becoming a customer-facing choice menu. Model B is deferred
because it adds offer state, acceptance, expiry, and customer experience work,
not because a short execution lease makes it impossible.

An authorization is not proof of payment or proof that a customer saw an offer.
The connector records execution outcomes; the customer-facing integration must
record what was actually communicated. Customer dissatisfaction opens a case for
human review, including after a completed settlement.

## 2. Separate compensation from authority and funding

For each policy-eligible remedy, compute a compensation interval from the
organization's versioned policy and the facts required by that policy:

```text
policy_floor <= proposed_amount <= policy_cap

authority_cap = min(policy_cap, agent_action_limit, matching_intent_limit)
fundable_cap  = min(authority_cap, applicable_budget_headroom)
```

The last expression is only an availability observation until an atomic
reservation succeeds. The budget dimension and monetary currency must match.

Do not reduce `policy_floor` because the agent has a small spending limit or
because a budget is nearly empty. If `policy_floor > fundable_cap`, there is no
currently fundable autonomous settlement for that remedy. Escalation is the
result; reducing the customer's policy entitlement is not.

A floor narrows the set of payments the agent may execute. It does not raise a
ceiling or require the engine to issue a payment. The previous version's claim
that enforcing a floor inherently forces spending is withdrawn.

No default such as `floor = 0.5 * effective_cap` is adopted. An agent's spending
limit is not a measure of appropriate compensation. Exact thresholds and claim
rules must come from the merchant's policy, with explicit policy versions.

### Trusted facts and omitted claims

Agent claims remain assertions. Merchant order value, prior compensation,
delivery facts, evidence verification, and any customer-request exception need
identified sources when policy relies on them. A photo reference by itself is
not verified evidence of a defect.

Refund actions subject to remedy policy must not opt out by omitting a claim.
Missing required context must produce a non-executable result. When required
facts cannot be verified, escalate for evidence resolution; do not silently
fall back to ceilings-only authorization.

An agent assertion that "the customer asked for less" cannot suppress the
floor. Any such exception must be explicitly permitted by merchant policy and
supported by authenticated customer input. The engine must not infer consent
to store credit from consent to a cash refund.

### Monetary representation

Use exact decimal values or integer minor units throughout policy evaluation,
including the OPA boundary. The current conversion of `Decimal` to `float` is
not the contract for the new compensation bounds. Quantize computed lower
bounds upward and upper bounds downward to the currency's supported minor unit;
if they cross, the interval is infeasible. Reject unsupported currencies rather
than assuming two decimal places. This requires implementation and boundary tests.

## 3. Action decisions and case escalation are separate

Keep one action decision: `ALLOW`, `DENY`, or `REVIEW`. A separate case-escalation
record states why a person needs to look. Do not return two simultaneous action
decisions or reuse an approval of a risky payment to override a hard constraint.

| Situation | Action result | Case handling |
|---|---|---|
| In range, authorized, funded, below review thresholds | ALLOW with one reservation and lease | Record the proposal and outcome |
| In range and otherwise valid, but risk requires approval | REVIEW without funds held | Existing approval flow, revalidated on approval |
| Below the policy floor | DENY, `REMEDY_BELOW_FLOOR` | Escalate undercompensation; no payment |
| Above the cap or wrong remedy | DENY with the relevant constraint | Record alternatives; any correction is a new proposal |
| No candidate can meet its floor and funding constraints | DENY, `NO_FUNDED_REMEDY` | Escalate with each candidate's blockers |
| Required claim context is absent or unverified | DENY with a typed context finding | Resolve evidence before a new proposal |
| Customer disputes an offer or completed settlement | Existing decision remains historical | Open a dispute linked to the case and original action |

The new finding names and escalation fields are proposed contracts, not existing
API fields. Human escalation must be durable and deduplicated per case/reason;
repeated agent submissions must not create an unbounded queue of duplicate cases.

A reviewer can resolve facts or propose another settlement within their own
verified authority. They cannot approve a denied action through the existing
risk-approval endpoint. Any policy exception needs an explicit, attributable
policy change or separately designed exception authority; none is implicit here.
A follow-up payment must account for compensation already issued on the case.

If case escalation cannot be persisted, the action stays non-executable and the
integration receives an operational failure. Do not claim a human was notified
merely because an audit event was written. Slack delivery is separate work.

## 4. Record alternatives without reserving them

Replace the proposed recursive fallback with a finite, policy-ordered collection
of remedy assessments. Each remedy appears once. The assessment separates:

- policy eligibility and compensation floor/cap;
- the agent and matching customer intent's authority;
- funding available at evaluation time;
- blockers and human-review requirements.

The set is complete relative to that policy version and the recorded facts. It
is not a statement that every possible business remedy was considered or that
agent-supplied facts are true.

For an authorized caller and valid case, persist the assessment with the selected
proposal, evaluation time, policy version, fact references/provenance, currency,
and relevant budget scopes. Record the later reservation outcome separately:
a budget race may invalidate the availability observed during evaluation.

Call the subset meeting all execution prerequisites **available at evaluation
time**, not "reserved" or "guaranteed". Only the selected proposal reserves
budget. Alternatives consume no funds and confer no execution capability.
On escalation, display the historical assessment and a newly evaluated one,
clearly distinguished. Never rewrite the historical decision to reflect today.

Use typed reason codes and identifiers, not raw complaint text in the immutable
audit record. Operator-visible alternatives follow organization and case access
controls. Identity/ownership failures do not expose another customer's options;
fleet stop or revocation produces no executable fallback. An unavailable policy
or state store fails closed, never a partial set presented as complete.

The audit can identify systematic low offers. Customer take-up of alternatives
requires actual offer-and-choice observations and cannot be inferred from this
record alone. Missing customer complaints are not proof of satisfaction.

## 5. Each remedy consumes an explicitly defined budget

Credit is a liability, not a free fallback. Model a budget pot as a ledger scope
with organization, currency, period, and an explicit remedy-to-pot mapping.
A pot is not a separate physical database. Cash refund and shipping refund may
share a cash pot; credit has its own configured liability pot. Every executable
remedy must map to a controlled pot.

Enforce applicable agent, pot, and company-wide caps together. Reservation must
atomically satisfy every applicable cap, or leave no hold in any scope. Release,
expiry, and commit resolve all scopes consistently; changing remedy cannot
reset the company's total exposure or an agent's existing spend.

For the first version, charge cash and fixed-value store credit at face value in
the same currency. Do not assume credit costs less than its face value merely
because some customers might not redeem it. Do not aggregate currencies without
an explicit conversion policy.

A percentage discount on a future basket is a different instrument. It needs a
maximum liability and redemption rules; it is deferred rather than disguised as
fixed-value store credit. Policy may define a fixed credit amount derived from
a verified eligible refund amount, but no universal 50% ratio is selected.

The funding snapshot is advisory; the ledger's conditional atomic write is the
spending authority. If a reservation loses a race, deny that proposal and record
the funding failure. Do not automatically settle with the next alternative.

## 6. Switching remedies requires fresh authority

A different remedy is a different action, submitted with a new request ID and a
link to the same case and previous proposal. It must pass every check anew:
identity, action permission, matching signed intent, current policy, evidence,
compensation bounds, risk, budgets, revocation, and fleet status.

Today an intent names exactly one action. A refund intent cannot be relabeled
as credit consent. If no matching intent exists, the alternative is marked as
requiring consent and cannot execute. Extending signed consent to a set of
remedies would be a separate trust-boundary decision.

An outstanding hold on a superseded proposal must be resolved before replacing
it. Request-ID idempotency does not prevent settling the same order twice with
two new IDs: the complete refund workflow also needs trusted case/order binding
and cumulative compensation accounting before handling real payments.

Keep the 30-second execution default for now. Do not lengthen it to accommodate
human deliberation. Real connector work must explicitly handle expiry and
ambiguous provider outcomes; a provider timeout is not proof no payment occurred.

## Alternatives and consequences

- **Customer chooses a guaranteed funded menu:** deferred; requires offer and
  reservation semantics beyond this first workflow.
- **Advisory low-compensation warnings on ALLOW:** rejected; the proposed
  settlement could still execute outside the configured range.
- **Review threshold derived from the effective spending cap:** replaced;
  tightening an agent's authority must not lower appropriate compensation.
- **Reserve all alternatives:** rejected; unchosen options would consume budget.
- **Recursive fallback:** replaced by explicit assessments, making every
  candidate and blocker auditable without implying automatic execution.
- **Rewrite the backend language:** unnecessary for this feature; see ADR 007.

This work is a policy-model, ledger, case-workflow, API, and console change. It
is not just an audit-schema extension. Per-company policy and tenant isolation
must be in place before exposing these assessments to multiple organizations.

## Delivery and verification

Implement in separately reviewable changes:

1. Close optional-claim omission on governed refund paths, including chat;
   document and test the required-context boundary.
2. Complete organization-scoped repositories and published policy, with shared
   connection pools. Replace whole-history state loading before volume rollout.
3. Add exact-money remedy intervals and the finite assessment model to both
   evaluators and persistence codecs. Select business thresholds from merchant
   policy, not demonstration values.
4. Add budget scopes and atomic multi-scope reservations before enabling funded
   alternatives. Retain existing idempotency and revocation protections.
5. Add durable case escalation, historical/current alternatives in the console,
   and protected refund execution with outcome reconciliation.

Acceptance tests must prove:

- omitting required claim context cannot produce a refund lease through either
  direct authorization or the agent path;
- amounts below the floor and above the cap cannot execute; equality at valid
  boundaries passes all other checks normally;
- reducing authority or available budget below the policy floor escalates
  without reducing that floor;
- agent assertions cannot widen trusted authority, forge fact provenance, or
  suppress a floor through a claimed customer preference;
- each policy-eligible remedy is assessed with typed blockers, and only the
  selected remedy reserves funds;
- consent to one action does not authorize another remedy;
- a funding race cannot exceed agent, pot, or company caps or leave partial holds;
- revocation, fleet stop, identity failure, and dependency failure cannot yield
  an executable fallback;
- risk approval cannot override a floor, missing context, or a budget refusal;
- dispute/escalation records survive restart and remain isolated by tenant;
- a historical assessment remains unchanged when current funding differs;
- new case submissions and remedy switches cannot duplicate compensation;
- monetary boundaries remain exact through Rego, JSON, and database round trips;
- both evaluators satisfy the tested permissiveness invariant for the supported
  policy configurations. A fixed test matrix is not a proof for arbitrary
  merchant-authored Rego; production must use the configured policy authority.

The design revision itself changed no runtime behavior. Implementation slices
are recorded separately, starting with ADR 008. Missing implementation must
remain visible in the workflow and release notes until verified.
