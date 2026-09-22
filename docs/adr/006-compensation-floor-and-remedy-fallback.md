# ADR 006: A compensation floor, and falling back when the budget is exhausted

- Status: **Proposed — design only, nothing implemented.** Five decisions need
  sign-off; decision 1 changes what kind of authority IntentGuard asserts and
  should be read first
- Date: 2026-09-22
- Extends the claim/remedy model added in `cb24a67` / `d0c186d`
- Does not alter ADR 004 (tenancy) or ADR 005 (persistence)

## Context

Stage 0 closed on 22 September with the wedge confirmed and restated. The
problem is not "AI agents issuing refunds". It is **the wrong amount**, in
either direction, when an agent settles a case autonomously. As the buyers put
it:

1. Given the circumstances of a case, determine the appropriate compensation.
2. Do not overcompensate.
3. **Do not undercompensate.**
4. Respect daily and company-level refund limits.
5. **When the refund budget is exhausted, fall back to an alternative remedy** —
   e.g. a discount on the next purchase, sized from the eligible refund amount.

Rules 1, 2 and 4 are what the engine already is. Rules 3 and 5 have no
representation in it, and neither is a small addition. This ADR defines both
before any code is written.

### What the engine does today

Every control is a ceiling. `authorization.rego:132`:

```rego
effective_cap := min([policy_remedy.cap, input.agent.max_action_amount, input.intent.max_amount])
```

and the governing property, stated in `models.RefundClaim`:

> *a claim may narrow the remedy, never widen it*

`Remedy` carries `kind` and a single `cap`. `Decision` is `ALLOW | DENY |
REVIEW`. Budget exhaustion is terminal — `DAILY_BUDGET_EXCEEDED`
(`policy_engine.py:673`) is a blocking finding, and the response says what was
refused, not what could be offered instead.

So the engine can currently answer *"may this much leave?"* and cannot answer
either *"was that too little?"* or *"what else could we do?"*.

---

## 1. What "do not undercompensate" actually means

This is the decision that matters, and it is not symmetrical with
overcompensation.

**Refusing to overpay withholds authority. Requiring a minimum asserts an
obligation to pay.** Today IntentGuard can only ever reduce what leaves the
company; every failure mode is "less money moved than the agent wanted". A
floor makes the engine the reason money leaves — and a bug in a floor is a bug
that *spends*. That is a different product, legally and operationally, and it
deserves to be named rather than absorbed as "one more rule".

Three readings of rule 3 were considered. They are not variations; they are
different products.

### Reading A — a hard floor the engine enforces (**rejected**)

The engine returns `DENY` when the proposed amount is *below* a computed
minimum, forcing the agent to offer more.

Rejected, for three reasons.

*It breaks the narrowing property.* The floor would have to be computed from
the claim, and the claim is an agent assertion. An agent wanting to force a
larger settlement asserts a more serious claim — which is precisely the
self-service escalation `RefundClaim`'s docstring exists to prevent. The
asymmetry that makes agent-supplied claims safe is that they can only ever
reduce. A floor derived from them removes it.

*It makes refusal incoherent.* A `DENY` today means "this must not happen". A
`DENY` for undercompensation means "this must happen, but bigger" — the agent's
only correct response is to re-propose a *larger* payment, so the engine's
refusal becomes an instruction to spend. Nothing in the decision vocabulary,
the audit trail or the console reads that way.

*It is unsafe under exactly the conditions it is meant for.* If a floor is
enforced and the budget is exhausted, the two rules contradict: rule 3 demands
at least X, rule 4 forbids any X. Something must give, and an engine that can
be talked into either violating a budget or blocking every settlement is worse
than one that does neither.

### Reading B — a floor as an advisory signal (**rejected**)

Return `ALLOW` but attach a non-blocking finding saying the settlement looks
low.

Rejected as the worst of both: it creates the obligation in the audit trail —
"the system said this was too little and it was paid anyway" — while enforcing
nothing. That is a liability record, not a control.

### Reading C — undercompensation is a *review* trigger, not a denial (**chosen**)

> **A proposal materially below the remedy policy would have permitted routes
> to human review. The engine never requires a payment; it requires a human
> when an agent settles unusually low.**

This is chosen because it keeps every property the current design rests on:

- **The narrowing rule survives untouched.** A richer claim still cannot
  increase what may be paid. It can only make an unusually small settlement
  more conspicuous, and the outcome of conspicuousness is a person looking, not
  money moving.
- **The decision vocabulary already has the right word.** `REVIEW` means "a
  human must decide", which is exactly the correct response to "this agent is
  offering £5 on a £200 defect claim". No new decision value is needed.
- **It cannot contradict the budget.** Review is orthogonal to funds; an
  exhausted budget and a low settlement can both be true and the case simply
  goes to a person.
- **It matches what the buyers described.** The fear is an agent quietly
  settling cases badly and nobody noticing. A queue entry answers that; a forced
  payment does not.

**The floor is therefore a detection threshold, not an obligation.** It is
worth being blunt in the documentation: IntentGuard does not guarantee
customers are compensated enough. It guarantees a human sees the cases where
they may not have been.

### The threshold

`REMEDY_MATERIALLY_BELOW_POLICY`, raised when:

```
proposed_amount < floor_ratio × effective_cap
```

with `floor_ratio` per-organisation policy (proposed default `0.5`), and the
finding suppressed entirely when:

- `effective_cap` is zero (nothing was permitted, so nothing is low), or
- the proposal exactly matches a lower remedy the policy itself named — an
  agent correctly offering `shipping_refund` is not undercompensating, it is
  complying, or
- the customer asked for less than policy permits, where that is representable.

The last exclusion matters and is currently **not representable**: the engine
has no field for "what the customer asked for". Without it, an agent honouring
a customer's modest request is indistinguishable from an agent shortchanging
them. See open question 1.

---

## 2. Falling back when the refund budget is exhausted

Rule 5 asks for something the model cannot express: *deny the refund, but allow
a different remedy, sized from the refund that was eligible.*

Today `DAILY_BUDGET_EXCEEDED` is blocking and the response carries no
alternative. The remedy ladder that already exists — `refund_to_source` →
`store_credit` → `shipping_refund` → `none` — is selected by the **claim**, not
by **budget state**, so nothing currently degrades.

### The shape chosen

> **`Remedy` gains an optional `fallback`. When a blocking finding is one the
> ladder can degrade past, the decision stays `DENY` for the proposed action
> and carries a fully-specified alternative the agent may propose instead.**

```
Remedy(
    kind=REFUND_TO_SOURCE, cap=200.00,
    fallback=Remedy(kind=STORE_CREDIT, cap=100.00, fallback=None),
)
```

Three properties this must hold, and they are the whole design:

**The fallback is an envelope, not an instruction.** Identical to the existing
`Remedy` contract — it says what *would* be permitted, and the agent must come
back with a new `ActionRequest` proposing it. The engine never issues a
settlement the agent did not ask for. Anything else makes IntentGuard the payer
rather than the authorizer.

**A fallback is computed under every constraint the original was.** It is
min'd with `agent.max_action_amount` and `intent.max_amount` exactly as
`effective_cap` is. A degraded remedy must never be a route to an amount the
original could not have reached — otherwise "exhaust the refund budget" becomes
an escalation technique.

**Store credit is not free.** This is the trap in rule 5 and the reason it
needs an ADR rather than a patch. A next-purchase discount is a real liability;
it is simply a *different* one, drawn against a different pot. If credit is
issued without a budget of its own, "refund budget exhausted" becomes a bypass
of the only spending control the product has, and an agent that wants to keep
settling need only exhaust the refund budget first. **A fallback remedy must be
reserved against its own ledger**, or the daily cap means nothing after the
first exhaustion. See decision 4.

### Which findings may degrade, and which may not

Not every refusal has a lesser form. Degrading past the wrong one converts a
control into a suggestion.

| Blocking finding | Degrades? | Why |
|---|---|---|
| `DAILY_BUDGET_EXCEEDED` | **Yes** | Funds for *this* remedy are out; the claim is still valid |
| `REMEDY_CAP_EXCEEDED` | **Yes**, to the cap | Policy named a smaller figure; offering it is compliance |
| `AGENT_ACTION_LIMIT` | **Yes**, to the limit | Same shape — authority exists, at a lower number |
| `REMEDY_NOT_PERMITTED` | **Yes** | Policy already names the permitted remedy |
| `CLAIM_NOT_RECOGNISED` | **No** | Nothing about the claim was authorised at all |
| `INTENT_CUSTOMER_MISMATCH` | **No** | The caller is not who they claim; degrade nothing |
| `AGENT_REVOKED`, fleet stop | **No** | The kill switch has no lesser form. Ever |
| `INTENT_EXPIRED` | **No** | Authority has lapsed; a smaller lapsed authority is still lapsed |
| Risk-driven `REVIEW` | **No** | Already a human's decision, not a funding problem |

The rule behind the table: **degrade only when authority exists and the
constraint is quantitative.** Where the refusal is about *identity, validity or
revocation*, there is nothing to degrade to.

### How the discount is calculated

The buyers' example is "a 50% discount on the next purchase, based on the
eligible refund amount". Written out:

```
eligible        = effective_cap of the ORIGINAL remedy
                  (already min'd with agent limit and intent)
fallback_cap    = min(
                      fallback_ratio × eligible,       # 0.5 by default, per-org
                      fallback_remedy_policy_cap,      # the ladder's own cap
                      agent.max_action_amount,
                      intent.max_amount,
                      remaining_fallback_budget        # its own ledger, decision 4
                  )
```

`eligible` is deliberately the **pre-budget** cap, not the remaining budget.
The discount is sized by what the customer was *owed*, which is the buyers'
stated intent, and not by how much happened to be left in the pot — otherwise
the last customer of the day gets a worse offer than the first for reasons that
have nothing to do with their case.

`fallback_ratio` being below 1.0 is what makes this cheaper than the refund it
replaces, which is the commercial point. It is policy, per organisation, and
should be expressible per claim reason.

---

## 3. When neither the preferred remedy nor the alternative is available

The case you asked to have pinned down, and the one most likely to be reached
in production — a busy day where both pots are empty.

**The decision is `DENY`, with an explicit and typed statement that nothing is
available, and escalation to human review rather than silence.**

Specifically:

1. The ladder is walked to exhaustion. `Remedy.fallback` is `None` and
   `kind` is `NONE` with `cap` zero.
2. A distinct finding is raised — `NO_REMEDY_AVAILABLE` — carrying a typed
   `FindingContext`, never prose, naming which ladder rungs were attempted and
   which constraint stopped each. An operator must be able to read "refund:
   daily budget exhausted; credit: credit budget exhausted" without decoding it.
3. **The case is routed to human review**, not merely refused. A customer with
   a valid claim and no available remedy is a business problem, not a policy
   outcome, and it is exactly the case a support lead needs to see. This is a
   `REVIEW` *alongside* the denial of the proposed action — the agent is told
   no, and a human is told why.
4. The audit event records the full attempted ladder, so "we ran out of money
   on the 14th and these 40 customers got nothing" is reconstructable.

**Deliberately excluded:** any notion of borrowing against tomorrow's budget,
queuing the settlement for automatic retry, or partial payment of what remains.
Each converts a refusal into a deferred commitment, and the product's core claim
is that a refusal is final and legible. A human may choose to do any of those;
the engine may not do them unattended.

---

## 4. Decisions requiring sign-off

**Decision 1 — undercompensation is a review trigger, never a denial.**
The engine never requires a payment. It requires a human when a settlement is
materially below what policy would have permitted. Accepting this means
accepting plainly that *IntentGuard does not guarantee customers are paid
enough* — it guarantees a person sees the cases where they may not have been.
Reject this and we are building reading A, which breaks the narrowing property.

**Decision 2 — `Remedy` gains an optional recursive `fallback`.**
An envelope, never an instruction; the agent must re-propose. Capped under
every constraint the original was.

**Decision 3 — only quantitative refusals degrade.**
Per the table in §2. Revocation, fleet stop, identity mismatch and expiry have
no lesser form.

**Decision 4 — a fallback remedy requires its own budget ledger.**
Without it, exhausting the refund budget is a bypass of the only spending
control the product has. This is the largest implementation item in the ADR: it
means a second ledger dimension keyed by remedy kind, not a single
`daily_budget` per agent. **If this is rejected, rule 5 should not be built at
all** — an uncapped fallback is worse than no fallback.

**Decision 5 — exhausting the ladder escalates as well as denies.**
`NO_REMEDY_AVAILABLE`, typed context naming each rung and its blocker, routed to
review.

---

## 5. Open questions

1. **What the customer asked for is not representable.** The undercompensation
   check needs to distinguish "the agent shortchanged them" from "they asked for
   less". `RefundClaim` has no field for a requested amount, and adding one
   raises its own question: it would be agent-supplied, so it can only ever be
   used to *suppress* a review, never to raise a cap. That is a safe direction,
   but it is one more agent-controlled input and wants its own review.

2. **Does `floor_ratio` belong in Rego or in config?** It is per-organisation
   policy, which argues Rego — but per-company policy does not exist yet
   (`policy.py` has no `org_id`). This ADR should land *after* per-company
   policy, or the floor is global and the feature is half-built.

3. **Currency.** `fallback_ratio × eligible` produces fractional minor units.
   Rounding direction is a commercial decision — rounding up favours the
   customer and is the safer default against rule 3, but it must be stated, not
   inherited from `Decimal`'s context.

4. **Does the built-in evaluator implement any of this?** Per Decisions §I the
   built-in evaluator may never be more permissive than Rego. A built-in
   evaluator that omits fallbacks is *stricter*, so it satisfies the invariant
   — but the 19-case matrix will need cases proving the fallback path cannot
   widen anything, or the invariant is being asserted over untested ground.

---

## Verification

Done when, and each covered by a test:

- a proposal materially below `effective_cap` returns `REVIEW`, never `DENY`,
  and never alters the cap;
- a richer claim cannot raise a floor into forcing a larger payment — the
  narrowing property holds with the floor present, asserted adversarially;
- an exhausted refund budget returns `DENY` carrying a fully-specified
  `store_credit` fallback, and the agent's re-proposal at the fallback cap is
  allowed;
- a fallback is refused when it would exceed `agent.max_action_amount` or
  `intent.max_amount`, proving degradation is not an escalation route;
- a fallback reserves against its own ledger, and exhausting the refund budget
  does not grant unlimited credit;
- `AGENT_REVOKED` and a fleet stop produce **no** fallback, asserted explicitly;
- both pots exhausted yields `NO_REMEDY_AVAILABLE` with typed context naming
  each rung and its blocker, plus a review entry;
- the permissiveness invariant still holds across both evaluators with
  fallbacks present.
