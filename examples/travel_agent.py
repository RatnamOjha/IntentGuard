"""Run one complete, offline IntentGuard travel-booking scenario.

Usage from the repository root: ``python examples/travel_agent.py``.
No API key, web server, or external booking account is required.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from intentguard import (  # noqa: E402
    AgentProfile,
    AgentTurn,
    AuthorizationResult,
    Decision,
    GovernedAgent,
    IntentPassport,
    PolicyEngine,
    ScriptedPlanner,
)
from mock_booking_connector import (  # noqa: E402
    BookingOutcome,
    HotelBooking,
    MockBookingConnector,
)
from intentguard.execution_lease import (  # noqa: E402
    ExecutionLeaseSigner,
    ExecutionLeaseVerifier,
    InMemoryLeaseKeyRegistry,
)

DEMO_CUSTOMER_ID = "customer-travel-demo"
DEMO_AGENT_ID = "agent-travel-demo"
DEMO_INTENT_ID = "intent-hotel-demo"


@dataclass(frozen=True)
class TravelResult:
    turn: AgentTurn
    authorization: AuthorizationResult | None
    booking: BookingOutcome | None


class TravelBookingWorkflow:
    """Compose the planner, policy engine, reviewer, and protected connector."""

    def __init__(self) -> None:
        lease_keys = InMemoryLeaseKeyRegistry()
        self.engine = PolicyEngine(
            review_risk_threshold=45,
            lease_signer=ExecutionLeaseSigner(
                Ed25519PrivateKey.generate(),
                issuer="intentguard-travel-demo",
                audience="intentguard-booking-connector",
                key_registry=lease_keys,
            ),
        )
        self.engine.register_agent(
            AgentProfile(
                agent_id=DEMO_AGENT_ID,
                name="Offline Travel Concierge",
                allowed_actions=frozenset({"book_hotel"}),
                max_action_amount=Decimal("18000"),
                daily_budget=Decimal("30000"),
            )
        )
        self.engine.register_intent(
            IntentPassport(
                intent_id=DEMO_INTENT_ID,
                customer_id=DEMO_CUSTOMER_ID,
                agent_id=DEMO_AGENT_ID,
                action="book_hotel",
                max_amount=Decimal("15000"),
                currency="INR",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
                required_attributes={"refundable": True},
            )
        )
        # Pin the deterministic planner so the example never reads an API key.
        self.agent = GovernedAgent(self.engine, planner=ScriptedPlanner())
        self.connector = MockBookingConnector(
            self.engine,
            ExecutionLeaseVerifier(
                audience="intentguard-booking-connector",
                key_registry=lease_keys,
            ),
        )

    def run(
        self,
        message: str,
        *,
        hotel: str = "Intent Inn",
        approve_review: bool = True,
        simulate_provider_failure: bool = False,
    ) -> TravelResult:
        turn = self.agent.send(
            message,
            customer_id=DEMO_CUSTOMER_ID,
            agent_id=DEMO_AGENT_ID,
        )
        authorization = turn.result
        if turn.decision is Decision.REVIEW and approve_review:
            authorization = self.engine.approve_action(
                turn.result.decision.request_id,
                reviewer="demo-reviewer",
                reason="Customer itinerary and refundable rate verified.",
            )

        if (
            authorization is None
            or authorization.decision.decision is not Decision.ALLOW
            or turn.proposal is None
        ):
            return TravelResult(turn, authorization, None)

        booking = HotelBooking(
            request_id=authorization.decision.request_id,
            agent_id=DEMO_AGENT_ID,
            customer_id=DEMO_CUSTOMER_ID,
            hotel=hotel,
            amount=turn.proposal.amount,
            currency=turn.proposal.currency,
            refundable=bool(turn.proposal.attributes.get("refundable")),
        )
        outcome = self.connector.execute(
            booking,
            authorization,
            simulate_provider_failure=simulate_provider_failure,
        )
        return TravelResult(turn, authorization, outcome)


def _print_result(label: str, result: TravelResult) -> None:
    authorization = result.authorization or result.turn.result
    name = authorization.decision.decision.value.upper() if authorization else "NONE"
    print(f"\n{label}: {name}")
    print(f"  Agent: {result.turn.reply}")
    if result.turn.decision is Decision.REVIEW and result.booking is not None:
        print("  Reviewer: APPROVED")
    if result.booking is not None:
        print(
            f"  Connector: {result.booking.status.upper()} - "
            f"{result.booking.message}"
        )
        if result.booking.provider_reference:
            print(f"  Provider reference: {result.booking.provider_reference}")


def main() -> None:
    workflow = TravelBookingWorkflow()
    scenarios = (
        ("valid booking", "Book a refundable hotel for INR 4500", {}),
        ("high-risk booking", "Book a refundable hotel for INR 13500", {}),
        ("invalid refund terms", "Book a non-refundable hotel for INR 5000", {}),
        ("over intent limit", "Book a refundable hotel for INR 17000", {}),
        (
            "provider failure",
            "Book a refundable hotel for INR 2500",
            {"simulate_provider_failure": True},
        ),
    )
    for label, message, options in scenarios:
        _print_result(label, workflow.run(message, **options))

    state = workflow.engine.list_agent_states()[0]
    print("\nSummary")
    print(f"  Committed spend: {state['spent_today']} INR")
    print(f"  Reserved spend: {state['reserved_today']} INR")
    print(f"  Audit events: {len(workflow.engine.audit_ledger.events)}")
    print(f"  Audit chain valid: {workflow.engine.audit_ledger.verify()}")


if __name__ == "__main__":
    main()
