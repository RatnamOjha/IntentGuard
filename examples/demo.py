"""Run representative IntentGuard governance scenarios."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

from intentguard import (
    ActionRequest,
    AgentProfile,
    IntentPassport,
    PolicyEngine,
)


def request(
    request_id: str,
    *,
    amount: str,
    risk_score: int,
    refundable: bool = True,
) -> ActionRequest:
    return ActionRequest(
        request_id=request_id,
        agent_id="travel-agent-01",
        action="book_flight",
        amount=Decimal(amount),
        currency="INR",
        intent_id="intent-001",
        risk_score=risk_score,
        attributes={"destination": "DEL", "refundable": refundable},
    )


engine = PolicyEngine(review_risk_threshold=70)
engine.register_agent(
    AgentProfile(
        agent_id="travel-agent-01",
        name="Travel Concierge",
        allowed_actions=frozenset({"search_flights", "book_flight"}),
        max_action_amount=Decimal("25000"),
        daily_budget=Decimal("40000"),
    )
)
engine.register_intent(
    IntentPassport(
        intent_id="intent-001",
        customer_id="card-member-001",
        agent_id="travel-agent-01",
        action="book_flight",
        max_amount=Decimal("18000"),
        currency="INR",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        required_attributes={"destination": "DEL", "refundable": True},
    )
)

scenarios = [
    request("request-allow", amount="16000", risk_score=20),
    request("request-over-limit", amount="31000", risk_score=20),
    request("request-review", amount="17000", risk_score=82),
]

for action in scenarios:
    decision = engine.evaluate(action)
    print(
        f"{action.request_id}: {decision.decision.value.upper()} — "
        f"{decision.explanation}"
    )
    if decision.decision.value == "allow":
        engine.record_execution(action, decision)

engine.stop_fleet(reason="Operator detected abnormal fleet activity.")
stopped_decision = engine.evaluate(
    request("request-after-stop", amount="10000", risk_score=10)
)
print(
    f"request-after-stop: {stopped_decision.decision.value.upper()} — "
    f"{stopped_decision.explanation}"
)
print(f"Audit chain valid: {engine.audit_ledger.verify()}")

