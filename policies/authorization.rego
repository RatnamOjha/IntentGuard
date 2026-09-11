package intentguard.authorization

import rego.v1

# Stateful facts (budget exposure, revocation, fleet state, and authenticated
# intent lookup) are assembled by Python. Rego owns the declarative decision.

blocking contains {"code": "FLEET_STOPPED", "message": "The fleet emergency stop is active.", "blocking": true} if input.fleet_stopped
blocking contains {"code": "AGENT_UNKNOWN", "message": "The requesting agent is not registered.", "blocking": true} if not input.agent.known

blocking contains {"code": "AGENT_INACTIVE", "message": "The requesting agent is inactive.", "blocking": true} if {
	input.agent.known
	not input.agent.active
}

blocking contains {"code": "AGENT_REVOKED", "message": "The requesting agent has been revoked.", "blocking": true} if input.agent.revoked

blocking contains {"code": "ACTION_NOT_PERMITTED", "message": "The agent is not permitted to perform this action.", "blocking": true} if {
	input.agent.known
	not input.request.action in input.agent.allowed_actions
}

blocking contains {"code": "AGENT_ACTION_LIMIT", "message": "The action exceeds the agent's per-action limit.", "blocking": true} if {
	input.agent.known
	input.request.amount > input.agent.max_action_amount
}

blocking contains {"code": "INTENT_UNKNOWN", "message": "No authenticated customer intent matches this request.", "blocking": true} if not input.intent.known

blocking contains {"code": "INTENT_AGENT_MISMATCH", "message": "The intent was issued to a different agent.", "blocking": true} if {
	input.intent.known
	input.intent.agent_id != input.request.agent_id
}

blocking contains {"code": "INTENT_ACTION_MISMATCH", "message": "The requested action is outside the customer's intent.", "blocking": true} if {
	input.intent.known
	input.intent.action != input.request.action
}

blocking contains {"code": "INTENT_EXPIRED", "message": "The customer's intent has expired.", "blocking": true} if {
	input.intent.known
	input.intent.expired
}

blocking contains {"code": "INTENT_CUSTOMER_MISMATCH", "message": "The intent belongs to a different customer than the one this action is proposed for.", "blocking": true} if {
	input.intent.known
	input.request.customer_id != null
	input.intent.customer_id != input.request.customer_id
}

blocking contains {"code": "INTENT_CURRENCY_MISMATCH", "message": "The request currency differs from the authorized currency.", "blocking": true} if {
	input.intent.known
	input.intent.currency != input.request.currency
}

blocking contains {"code": "INTENT_AMOUNT_EXCEEDED", "message": "The amount exceeds the customer's authorized maximum.", "blocking": true} if {
	input.intent.known
	input.request.amount > input.intent.max_amount
}

blocking contains {"code": "DAILY_BUDGET_EXCEEDED", "message": "The action exceeds the agent's remaining daily budget.", "blocking": true} if {
	input.agent.known
	input.request.amount > input.agent.remaining_daily_budget
}

blocking contains {"code": "INTENT_ATTRIBUTE_MISMATCH", "message": sprintf("The request violates the authorized '%s' constraint: expected %v, received %v.", [key, expected, object.get(input.request.attributes, key, null)]), "blocking": true} if {
	input.intent.known
	some key, expected in input.intent.required_attributes
	object.get(input.request.attributes, key, null) != expected
}

# A claim may only ever narrow what is permitted, never widen it. Every field
# of input.claim is asserted by the agent, so if "evidence" could buy a bigger
# payout an agent that wanted one would simply claim it. effective_cap below is
# min'd with the ceilings that already applied, which is what keeps an agent's
# own account of the complaint from becoming a permission escalation.

has_evidence(kind) if kind in input.claim.evidence

# What the proposed action would pay out with. An action that settles nothing
# defaults to "none", so a claim attached to one can never match a real remedy
# and is refused rather than escaping the claim rules entirely.
default proposed_remedy := "none"

proposed_remedy := "refund_to_source" if input.request.action == "refund_order"

proposed_remedy := "store_credit" if input.request.action == "issue_goodwill_credit"

proposed_remedy := "shipping_refund" if input.request.action == "refund_shipping"

proposed_remedy := "reschedule" if input.request.action == "reschedule_service"

# What policy will honour for the claim. One rule per reason, and the
# evidence-bearing variants come first so the unevidenced fallbacks cannot
# also match.
policy_remedy := {"kind": "refund_to_source", "cap": input.claim.order_value} if {
	input.claim.reason == "defect"
	has_evidence("photo")
}

policy_remedy := {"kind": "shipping_refund", "cap": input.config.shipping_refund_cap} if {
	input.claim.reason == "defect"
	not has_evidence("photo")
}

policy_remedy := {"kind": "refund_to_source", "cap": input.claim.order_value} if {
	input.claim.reason == "not_delivered"
	has_evidence("courier_scan")
}

policy_remedy := {"kind": "store_credit", "cap": input.claim.order_value} if {
	input.claim.reason == "not_delivered"
	not has_evidence("courier_scan")
}

policy_remedy := {"kind": "shipping_refund", "cap": input.config.shipping_refund_cap} if {
	input.claim.reason == "late"
}

policy_remedy := {"kind": "store_credit", "cap": input.claim.order_value} if {
	input.claim.reason == "changed_mind"
	input.claim.days_since_delivery <= input.config.change_of_mind_days
}

policy_remedy := {"kind": "none", "cap": 0} if {
	input.claim.reason == "changed_mind"
	input.claim.days_since_delivery > input.config.change_of_mind_days
}

# The narrowing rule, in one place: a claim never reaches past the agent's own
# per-action limit or the customer's authorised maximum.
effective_cap := min([policy_remedy.cap, input.agent.max_action_amount, input.intent.max_amount])

blocking contains {"code": "CLAIM_NOT_RECOGNISED", "message": "No remedy rule matches this claim, so nothing about it has been authorised.", "blocking": true} if {
	input.claim.known
	not policy_remedy
}

blocking contains {"code": "REMEDY_NOT_PERMITTED", "message": sprintf("A '%s' claim is not settled with %s under this policy; the permitted remedy is %s.", [input.claim.reason, proposed_remedy, policy_remedy.kind]), "blocking": true} if {
	input.claim.known
	proposed_remedy != policy_remedy.kind
}

blocking contains {"code": "REMEDY_CAP_EXCEEDED", "message": sprintf("The amount exceeds what a '%s' claim permits.", [input.claim.reason]), "blocking": true} if {
	input.claim.known
	proposed_remedy == policy_remedy.kind
	input.request.amount > effective_cap
}

notices contains {"code": "RISK_SCORE_UNDER_DECLARED", "message": sprintf("The agent declared a risk score of %v, but the gateway derived %v. The derived score applies.", [input.risk.declared, input.risk.derived]), "blocking": false} if input.risk.under_declared

notices contains {"code": "HUMAN_APPROVAL_REQUIRED", "message": "The action requires human approval under the active policy.", "blocking": false} if {
	count(blocking) == 0
	review_required
}

notices contains {"code": "POLICY_SATISFIED", "message": "The action satisfies all active runtime policies.", "blocking": false} if {
	count(blocking) == 0
	not review_required
}

review_required if input.risk.effective >= input.config.review_risk_threshold

# Was gated on action == "book_hotel", so it protected nothing once the product
# became refunds: no agent is permitted that action. Now it applies to any
# payout, which is what it was always meant to mean.
review_required if {
	input.config.large_payout_threshold != null
	input.request.amount >= input.config.large_payout_threshold
}

review_required if object.get(input.request.attributes, "merchant_category", "") in input.config.review_merchant_categories

outcome := "deny" if count(blocking) > 0

outcome := "review" if {
	count(blocking) == 0
	review_required
}

outcome := "allow" if {
	count(blocking) == 0
	not review_required
}

# Undefined would make `decision` itself undefined, so the no-claim case has to
# be a value rather than an absence.
default remedy := null

remedy := {"kind": policy_remedy.kind, "cap": effective_cap} if input.claim.known

decision := {
	"decision": outcome,
	"findings": array.concat(sort([x | some x in blocking]), sort([x | some x in notices])),
	"remedy": remedy,
}
