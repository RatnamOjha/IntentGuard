"""A protected, offline hotel-booking connector for the travel demo.

The connector requires the reservation and short-lived execution lease returned
by IntentGuard. It checks their request bindings and lets the policy engine
perform final lease validation when provider success is committed.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from intentguard import AuthorizationResult, Decision, PolicyEngine
from intentguard.booking_connector import (
    BookingCommand,
    EngineGovernanceGateway,
    InMemoryExecutionStore,
    ProtectedBookingConnector,
)
from intentguard.execution_lease import ExecutionLeaseVerifier


class BookingConnectorError(RuntimeError):
    """The connector refused an unprotected or inconsistent booking."""


@dataclass(frozen=True)
class HotelBooking:
    request_id: str
    agent_id: str
    customer_id: str
    hotel: str
    amount: Decimal
    currency: str
    refundable: bool


@dataclass(frozen=True)
class BookingOutcome:
    status: str
    provider_reference: str | None
    message: str


class MockBookingConnector:
    """Simulate a provider while enforcing IntentGuard's execution boundary."""

    def __init__(
        self, engine: PolicyEngine, verifier: ExecutionLeaseVerifier
    ) -> None:
        self.engine = engine
        self._execution_store = InMemoryExecutionStore()
        self._connector = ProtectedBookingConnector(
            verifier=verifier,
            governance=EngineGovernanceGateway(engine),
            execution_store=self._execution_store,
        )

    def execute(
        self,
        booking: HotelBooking,
        authorization: AuthorizationResult,
        *,
        simulate_provider_failure: bool = False,
    ) -> BookingOutcome:
        reservation, lease = authorization.reservation, authorization.lease
        if authorization.decision.decision is not Decision.ALLOW:
            raise BookingConnectorError("IntentGuard did not allow this booking.")
        if reservation is None or lease is None:
            raise BookingConnectorError(
                "A budget reservation and execution lease are required."
            )

        mismatches = []
        if authorization.decision.request_id != booking.request_id:
            mismatches.append("decision.request_id")
        if reservation.request_id != booking.request_id:
            mismatches.append("reservation.request_id")
        if lease.request_id != booking.request_id:
            mismatches.append("lease.request_id")
        if (
            reservation.agent_id != booking.agent_id
            or lease.agent_id != booking.agent_id
        ):
            mismatches.append("agent_id")
        if lease.reservation_id != reservation.reservation_id:
            mismatches.append("reservation_id")
        if reservation.amount != booking.amount:
            mismatches.append("amount")
        if reservation.currency != booking.currency:
            mismatches.append("currency")
        if mismatches:
            raise BookingConnectorError(
                "Authorization does not match the booking: " + ", ".join(mismatches)
            )

        if not lease.token:
            raise BookingConnectorError("A signed execution lease is required.")

        if simulate_provider_failure:
            self.engine.release_reservation(
                reservation.reservation_id,
                reason="mock_booking_provider_failed",
            )
            self.engine.audit_ledger.append(
                "connector.booking_failed",
                {
                    "request_id": booking.request_id,
                    "agent_id": booking.agent_id,
                    "hotel": booking.hotel,
                    "reason": "simulated_provider_failure",
                },
            )
            return BookingOutcome(
                status="failed",
                provider_reference=None,
                message="The mock provider failed; the budget hold was released.",
            )

        response = self._connector.execute(
            BookingCommand(
                request_id=booking.request_id,
                reservation_id=reservation.reservation_id,
                agent_id=booking.agent_id,
                customer_id=booking.customer_id,
                action="book_hotel",
                hotel=booking.hotel,
                amount=booking.amount,
                currency=booking.currency,
                refundable=booking.refundable,
                lease_token=lease.token,
            )
        )
        self.engine.audit_ledger.append(
            "connector.booking_succeeded",
            {
                "request_id": booking.request_id,
                "agent_id": booking.agent_id,
                "hotel": booking.hotel,
                "provider_reference": response.provider_reference,
                "reservation_status": "committed",
            },
        )
        return BookingOutcome(
            status="booked",
            provider_reference=response.provider_reference,
            message="The hotel was booked and the reserved budget was committed.",
        )
