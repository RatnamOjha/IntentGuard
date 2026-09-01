package intentguard.authorization_test

import data.intentguard.authorization.decision
import rego.v1

base := {
	"fleet_stopped": false,
	"request": {"request_id": "matrix", "agent_id": "travel-01", "action": "book_hotel", "amount": 4500, "currency": "INR", "customer_id": "customer-01", "attributes": {"refundable": true}},
	"agent": {"known": true, "active": true, "revoked": false, "allowed_actions": ["book_hotel"], "max_action_amount": 20000, "remaining_daily_budget": 30000},
	"intent": {"known": true, "agent_id": "travel-01", "action": "book_hotel", "customer_id": "customer-01", "currency": "INR", "max_amount": 18000, "expired": false, "required_attributes": {"refundable": true}},
	"risk": {"declared": 10, "derived": 10, "effective": 10, "under_declared": false},
	"config": {"review_risk_threshold": 70, "large_booking_threshold": 10000, "review_merchant_categories": ["cash_equivalent", "restricted_travel"]},
}

test_refundable_hotel_under_limit_is_allowed if {
	decision.decision == "allow" with input as base
}

test_non_refundable_hotel_without_consent_is_denied if {
	request := object.union(base.request, {"attributes": {"refundable": false}})
	decision.decision == "deny" with input as object.union(base, {"request": request})
}

test_amount_over_intent_limit_is_denied if {
	request := object.union(base.request, {"amount": 19000})
	decision.decision == "deny" with input as object.union(base, {"request": request})
}

test_high_risk_action_requires_review if {
	risk := object.union(base.risk, {"declared": 90, "effective": 90})
	decision.decision == "review" with input as object.union(base, {"risk": risk})
}

test_revoked_agent_is_denied if {
	agent := object.union(base.agent, {"revoked": true})
	decision.decision == "deny" with input as object.union(base, {"agent": agent})
}

test_stopped_fleet_is_denied if {
	decision.decision == "deny" with input as object.union(base, {"fleet_stopped": true})
}
