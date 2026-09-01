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

blocking contains {"code": "NON_REFUNDABLE_CONSENT_REQUIRED", "message": "A non-refundable booking requires explicit customer consent.", "blocking": true} if {
	startswith(input.request.action, "book_")
	object.get(input.request.attributes, "refundable", null) == false
	object.get(input.intent.required_attributes, "refundable", null) != false
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

review_required if {
	input.request.action == "book_hotel"
	input.request.amount >= input.config.large_booking_threshold
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

decision := {
	"decision": outcome,
	"findings": array.concat(sort([x | some x in blocking]), sort([x | some x in notices])),
}
