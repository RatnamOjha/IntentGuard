from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "examples"))

from intentguard import Decision, ReservationStatus  # noqa: E402
from mock_booking_connector import BookingConnectorError, HotelBooking  # noqa: E402
from travel_agent import (  # noqa: E402
    DEMO_AGENT_ID,
    DEMO_CUSTOMER_ID,
    TravelBookingWorkflow,
)


class TravelBookingWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = TravelBookingWorkflow()

    def test_valid_booking_commits_budget_and_audits_connector(self) -> None:
        result = self.workflow.run("Book a refundable hotel for INR 4500")

        self.assertEqual(Decision.ALLOW, result.turn.decision)
        self.assertEqual("booked", result.booking.status)
        reservation = self.workflow.engine.get_reservation(
            result.authorization.reservation.reservation_id
        )
        self.assertEqual(ReservationStatus.COMMITTED, reservation.status)
        self.assertEqual(
            Decimal("4500"), self.workflow.engine.list_agent_states()[0]["spent_today"]
        )
        self.assertEqual(
            "connector.booking_succeeded",
            self.workflow.engine.audit_ledger.events[-1].event_type,
        )

    def test_high_risk_booking_is_reviewed_then_approved(self) -> None:
        result = self.workflow.run("Book a refundable hotel for INR 14500")

        self.assertEqual(Decision.REVIEW, result.turn.decision)
        self.assertEqual(Decision.ALLOW, result.authorization.decision.decision)
        self.assertEqual("booked", result.booking.status)
        event_types = {
            event.event_type for event in self.workflow.engine.audit_ledger.events
        }
        self.assertIn("approval.requested", event_types)
        self.assertIn("approval.approved", event_types)

    def test_invalid_booking_never_reaches_connector(self) -> None:
        result = self.workflow.run("Book a non-refundable hotel for INR 5000")

        self.assertEqual(Decision.DENY, result.turn.decision)
        self.assertIsNone(result.booking)
        self.assertIn(
            "INTENT_ATTRIBUTE_MISMATCH",
            {finding.code for finding in result.turn.result.decision.findings},
        )

    def test_booking_over_customer_limit_never_reaches_connector(self) -> None:
        result = self.workflow.run("Book a refundable hotel for INR 17000")

        self.assertEqual(Decision.DENY, result.turn.decision)
        self.assertIsNone(result.booking)
        self.assertIn(
            "INTENT_AMOUNT_EXCEEDED",
            {finding.code for finding in result.turn.result.decision.findings},
        )

    def test_provider_failure_releases_budget(self) -> None:
        result = self.workflow.run(
            "Book a refundable hotel for INR 2500",
            simulate_provider_failure=True,
        )

        self.assertEqual("failed", result.booking.status)
        reservation = self.workflow.engine.get_reservation(
            result.authorization.reservation.reservation_id
        )
        self.assertEqual(ReservationStatus.RELEASED, reservation.status)
        self.assertEqual(
            Decimal("0"), self.workflow.engine.list_agent_states()[0]["reserved_today"]
        )

    def test_connector_rejects_booking_tampering(self) -> None:
        turn = self.workflow.agent.send(
            "Book a refundable hotel for INR 4500",
            customer_id=DEMO_CUSTOMER_ID,
            agent_id=DEMO_AGENT_ID,
        )
        booking = HotelBooking(
            request_id=turn.result.decision.request_id,
            agent_id=DEMO_AGENT_ID,
            customer_id=DEMO_CUSTOMER_ID,
            hotel="Intent Inn",
            amount=Decimal("4500"),
            currency="INR",
            refundable=True,
        )

        with self.assertRaises(BookingConnectorError):
            self.workflow.connector.execute(
                replace(booking, amount=Decimal("4600")), turn.result
            )


if __name__ == "__main__":
    unittest.main()
