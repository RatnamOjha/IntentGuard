from __future__ import annotations

import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from intentguard import (  # noqa: E402
    ActionRequest,
    AgentProfile,
    Decision,
    IntentPassport,
    PolicyEngine,
    ReservationStatus,
)


class AuthorizationFlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 27, 10, tzinfo=timezone.utc)
        self.engine = PolicyEngine()
        self.engine.register_agent(
            AgentProfile(
                agent_id="payments-01",
                name="Payments Agent",
                allowed_actions=frozenset({"transfer"}),
                max_action_amount=Decimal("20000"),
                daily_budget=Decimal("100000"),
            )
        )
        self.engine.register_intent(
            IntentPassport(
                intent_id="intent-payments",
                customer_id="customer-01",
                agent_id="payments-01",
                action="transfer",
                max_amount=Decimal("20000"),
                currency="INR",
                expires_at=self.now + timedelta(hours=1),
            )
        )

    def request(self, request_id: str, amount: str = "20000") -> ActionRequest:
        return ActionRequest(
            request_id=request_id,
            agent_id="payments-01",
            action="transfer",
            amount=Decimal(amount),
            currency="INR",
            intent_id="intent-payments",
            risk_score=10,
            occurred_at=self.now,
        )

    def test_authorize_reserves_and_commit_consumes_budget(self) -> None:
        result = self.engine.authorize_action(self.request("request-1"), now=self.now)

        self.assertEqual(Decision.ALLOW, result.decision.decision)
        self.assertIsNotNone(result.reservation)
        self.assertIsNotNone(result.lease)
        reservation = self.engine.commit_reservation(
            result.reservation.reservation_id,
            lease_id=result.lease.lease_id,
            now=self.now + timedelta(seconds=1),
        )
        self.assertEqual(ReservationStatus.COMMITTED, reservation.status)

    def test_release_returns_budget_to_the_pool(self) -> None:
        result = self.engine.authorize_action(self.request("request-1"), now=self.now)
        released = self.engine.release_reservation(
            result.reservation.reservation_id,
            reason="connector_failed",
            now=self.now,
        )

        self.assertEqual(ReservationStatus.RELEASED, released.status)
        replacement = self.engine.authorize_action(
            self.request("request-2"), now=self.now
        )
        self.assertEqual(Decision.ALLOW, replacement.decision.decision)

    def test_expired_hold_is_reclaimed(self) -> None:
        result = self.engine.authorize_action(
            self.request("request-expiring"),
            now=self.now,
            lease_ttl=timedelta(seconds=1),
        )

        replacement = self.engine.authorize_action(
            self.request("request-after-expiry"),
            now=self.now + timedelta(seconds=2),
        )

        expired = self.engine.get_reservation(result.reservation.reservation_id)
        self.assertEqual(ReservationStatus.EXPIRED, expired.status)
        self.assertEqual(Decision.ALLOW, replacement.decision.decision)

    def test_revocation_releases_agent_holds(self) -> None:
        result = self.engine.authorize_action(self.request("request-1"), now=self.now)

        self.engine.revoke_agent("payments-01")

        reservation = self.engine.get_reservation(result.reservation.reservation_id)
        self.assertEqual(ReservationStatus.RELEASED, reservation.status)
        denied = self.engine.authorize_action(
            self.request("request-after-revocation"), now=self.now
        )
        self.assertEqual(Decision.DENY, denied.decision.decision)

    def test_request_id_is_idempotent(self) -> None:
        request = self.request("request-idempotent")
        first = self.engine.authorize_action(request, now=self.now)
        retry = ActionRequest(
            request_id=request.request_id,
            agent_id=request.agent_id,
            action=request.action,
            amount=request.amount,
            currency=request.currency,
            intent_id=request.intent_id,
            risk_score=request.risk_score,
            attributes=request.attributes,
            occurred_at=self.now + timedelta(seconds=1),
        )
        second = self.engine.authorize_action(retry, now=self.now)

        self.assertEqual(first.lease.lease_id, second.lease.lease_id)
        self.assertEqual(
            first.reservation.reservation_id,
            second.reservation.reservation_id,
        )

    def test_request_id_reuse_with_different_data_is_rejected(self) -> None:
        self.engine.authorize_action(self.request("request-reused"), now=self.now)
        with self.assertRaises(ValueError):
            self.engine.authorize_action(
                self.request("request-reused", amount="10000"), now=self.now
            )

    def test_concurrent_requests_never_exceed_budget(self) -> None:
        requests = [self.request(f"request-{index}") for index in range(10)]
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(
                executor.map(
                    lambda item: self.engine.authorize_action(item, now=self.now),
                    requests,
                )
            )

        allowed = [item for item in results if item.decision.decision is Decision.ALLOW]
        denied = [item for item in results if item.decision.decision is Decision.DENY]
        self.assertEqual(5, len(allowed))
        self.assertEqual(5, len(denied))
        self.assertTrue(
            all(
                "DAILY_BUDGET_EXCEEDED"
                in {finding.code for finding in item.decision.findings}
                for item in denied
            )
        )

    def test_fleet_stop_releases_holds_and_invalidates_lease(self) -> None:
        result = self.engine.authorize_action(self.request("request-1"), now=self.now)
        original_epoch = result.lease.fleet_epoch

        self.engine.stop_fleet(reason="suspected compromise")

        self.assertEqual(original_epoch + 1, self.engine.fleet_epoch)
        reservation = self.engine.get_reservation(result.reservation.reservation_id)
        self.assertEqual(ReservationStatus.RELEASED, reservation.status)
        with self.assertRaises(ValueError):
            self.engine.commit_reservation(
                result.reservation.reservation_id,
                lease_id=result.lease.lease_id,
                now=self.now + timedelta(seconds=1),
            )


if __name__ == "__main__":
    unittest.main()
