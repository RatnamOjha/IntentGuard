"""Adversarial tests against the real policy engine.

Every test here drives the production ``PolicyEngine`` (and, where the attack
targets the protected connector boundary, the real FastAPI app). Nothing under
test is mocked. Assertions are on observable behaviour -- decisions, raised
errors, HTTP status codes, committed spend, and audit events -- rather than on
private engine state, except where a total has to be read back to prove an
invariant held.
"""

from __future__ import annotations

import copy
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

try:
    from fastapi.testclient import TestClient
except ImportError:  # Allows domain-only test runs before API extras are installed.
    TestClient = None

from intentguard import (  # noqa: E402
    ActionRequest,
    AgentProfile,
    AuditLedger,
    Decision,
    DecisionRecord,
    IntentPassport,
    PolicyEngine,
    ReservationStatus,
)

AGENT_ID = "travel-agent-01"
INTENT_ID = "intent-refundable-18000"


def build_engine(
    *,
    daily_budget: str = "40000",
    max_action_amount: str = "25000",
    intent_max_amount: str = "18000",
    intent_attributes: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> tuple[PolicyEngine, datetime]:
    """An agent authorized for refundable bookings up to INR 18,000.

    Tests that drive the engine directly pass an explicit ``now`` everywhere and
    use the fixed default. Tests that go through FastAPI must anchor to the wall
    clock, because the gateway stamps its own ``now`` on each request.
    """

    now = now or datetime(2026, 8, 21, 10, tzinfo=timezone.utc)
    engine = PolicyEngine()
    engine.register_agent(
        AgentProfile(
            agent_id=AGENT_ID,
            name="Travel Concierge",
            allowed_actions=frozenset({"book_flight"}),
            max_action_amount=Decimal(max_action_amount),
            daily_budget=Decimal(daily_budget),
        )
    )
    engine.register_intent(
        IntentPassport(
            intent_id=INTENT_ID,
            customer_id="card-member-001",
            agent_id=AGENT_ID,
            action="book_flight",
            max_amount=Decimal(intent_max_amount),
            currency="INR",
            expires_at=now + timedelta(hours=2),
            required_attributes=(
                {"refundable": True}
                if intent_attributes is None
                else intent_attributes
            ),
        )
    )
    return engine, now


def booking(
    request_id: str,
    *,
    amount: str = "16000",
    refundable: bool = True,
    risk_score: int = 20,
) -> ActionRequest:
    return ActionRequest(
        request_id=request_id,
        agent_id=AGENT_ID,
        action="book_flight",
        amount=Decimal(amount),
        currency="INR",
        intent_id=INTENT_ID,
        risk_score=risk_score,
        attributes={"refundable": refundable},
    )


def audit_payloads(engine: PolicyEngine, event_type: str) -> list[dict[str, Any]]:
    return [
        event.payload
        for event in engine.audit_ledger.events
        if event.event_type == event_type
    ]


def spent_today(engine: PolicyEngine, now: datetime) -> Decimal:
    (state,) = [
        item
        for item in engine.list_agent_states(now=now)
        if item["agent_id"] == AGENT_ID
    ]
    return state["spent_today"]


class IntentTamperingTest(unittest.TestCase):
    """1. Intent tampering after authorization."""

    def setUp(self) -> None:
        self.engine, self.now = build_engine()

    def test_authorized_artifacts_bind_the_authorized_intent(self) -> None:
        """The reservation holds what was authorized, not what is asked later."""

        authorized = self.engine.authorize_action(booking("req-1"), now=self.now)

        self.assertIs(Decision.ALLOW, authorized.decision.decision)
        assert authorized.reservation is not None
        self.assertEqual(Decimal("16000"), authorized.reservation.amount)
        self.assertEqual("INR", authorized.reservation.currency)

    def test_tampered_amount_under_the_same_request_id_is_rejected(self) -> None:
        authorized = self.engine.authorize_action(booking("req-1"), now=self.now)
        assert authorized.reservation is not None

        with self.assertRaises(ValueError) as raised:
            self.engine.authorize_action(
                booking("req-1", amount="31000"), now=self.now
            )
        self.assertIn("different action data", str(raised.exception))

        # The original hold is untouched: replaying the untampered request
        # returns the same artifacts, still bound to the authorized amount.
        replayed = self.engine.authorize_action(booking("req-1"), now=self.now)
        assert replayed.reservation is not None
        self.assertEqual(
            authorized.reservation.reservation_id,
            replayed.reservation.reservation_id,
        )
        self.assertEqual(Decimal("16000"), replayed.reservation.amount)
        self.assertIs(ReservationStatus.HELD, replayed.reservation.status)

    def test_tampered_refundability_under_the_same_request_id_is_rejected(
        self,
    ) -> None:
        self.engine.authorize_action(booking("req-1"), now=self.now)

        with self.assertRaises(ValueError) as raised:
            self.engine.authorize_action(
                booking("req-1", refundable=False), now=self.now
            )
        self.assertIn("different action data", str(raised.exception))

    def test_tampered_request_id_replay_is_recorded_as_an_audit_event(self) -> None:
        """A rejected tampering attempt must leave a trace."""

        self.engine.authorize_action(booking("req-1"), now=self.now)
        before = len(self.engine.audit_ledger.events)

        with self.assertRaises(ValueError):
            self.engine.authorize_action(
                booking("req-1", amount="31000"), now=self.now
            )

        appended = self.engine.audit_ledger.events[before:]
        self.assertTrue(
            appended,
            "The engine rejected a tampered replay without auditing it.",
        )
        (recorded,) = appended
        self.assertEqual("authorization.rejected", recorded.event_type)
        self.assertEqual("req-1", recorded.payload["request_id"])
        self.assertEqual(AGENT_ID, recorded.payload["agent_id"])
        self.assertIn("amount", recorded.payload["conflicting_fields"])
        # The submitted values are attacker controlled and are not copied in.
        self.assertNotIn("31000", str(recorded.payload))
        self.assertTrue(self.engine.audit_ledger.verify())

    def test_tampered_action_submitted_fresh_is_denied_and_audited(self) -> None:
        """Re-submitting the tampered action under a new ID is denied on merit."""

        self.engine.authorize_action(booking("req-1"), now=self.now)

        over_amount = self.engine.authorize_action(
            booking("req-tampered-amount", amount="31000"), now=self.now
        )
        self.assertIs(Decision.DENY, over_amount.decision.decision)
        self.assertIsNone(over_amount.reservation)
        self.assertIsNone(over_amount.lease)
        self.assertIn(
            "INTENT_AMOUNT_EXCEEDED",
            [finding.code for finding in over_amount.decision.findings],
        )

        non_refundable = self.engine.authorize_action(
            booking("req-tampered-refundable", refundable=False), now=self.now
        )
        self.assertIs(Decision.DENY, non_refundable.decision.decision)
        self.assertIn(
            "INTENT_ATTRIBUTE_MISMATCH",
            [finding.code for finding in non_refundable.decision.findings],
        )

        denials = [
            payload
            for payload in audit_payloads(self.engine, "policy.evaluated")
            if payload["decision"] == "deny"
        ]
        denied_ids = {payload["request_id"] for payload in denials}
        self.assertIn("req-tampered-amount", denied_ids)
        self.assertIn("req-tampered-refundable", denied_ids)
        self.assertTrue(self.engine.audit_ledger.verify())

    def test_a_lease_cannot_be_pointed_at_another_reservation(self) -> None:
        """Swapping artifacts between two authorizations is rejected."""

        first = self.engine.authorize_action(booking("req-1"), now=self.now)
        second = self.engine.authorize_action(
            booking("req-2", amount="1000"), now=self.now
        )
        assert first.lease is not None and second.reservation is not None

        with self.assertRaises(ValueError) as raised:
            self.engine.commit_reservation(
                second.reservation.reservation_id,
                lease_id=first.lease.lease_id,
                now=self.now,
            )
        self.assertIn("invalid for this reservation", str(raised.exception))
        self.assertEqual(Decimal("0"), spent_today(self.engine, self.now))


class ReplayAfterRevocationTest(unittest.TestCase):
    """2. Replay of a still-valid lease after the agent is revoked."""

    def setUp(self) -> None:
        self.engine, self.now = build_engine()
        self.authorized = self.engine.authorize_action(
            booking("req-lease"),
            now=self.now,
            lease_ttl=timedelta(minutes=30),
        )
        assert self.authorized.lease is not None
        assert self.authorized.reservation is not None

    def test_the_lease_is_valid_and_unexpired_before_revocation(self) -> None:
        lease = self.authorized.lease
        assert lease is not None
        self.assertFalse(lease.is_expired(self.now + timedelta(seconds=1)))

    def test_a_lease_issued_before_revocation_does_not_survive_it(self) -> None:
        lease = self.authorized.lease
        reservation = self.authorized.reservation
        assert lease is not None and reservation is not None

        self.engine.revoke_agent(AGENT_ID)

        with self.assertRaises(ValueError) as raised:
            self.engine.commit_reservation(
                reservation.reservation_id,
                lease_id=lease.lease_id,
                now=self.now + timedelta(seconds=1),
            )
        self.assertIn("revoked agent", str(raised.exception))
        self.assertEqual(Decimal("0"), spent_today(self.engine, self.now))
        self.assertTrue(self.engine.audit_ledger.verify())

    def test_replay_stays_rejected_after_the_agent_is_restored(self) -> None:
        """Restoring the agent must not resurrect the pre-revocation lease."""

        lease = self.authorized.lease
        reservation = self.authorized.reservation
        assert lease is not None and reservation is not None

        self.engine.revoke_agent(AGENT_ID)
        self.engine.restore_agent(AGENT_ID)

        with self.assertRaises(ValueError) as raised:
            self.engine.commit_reservation(
                reservation.reservation_id,
                lease_id=lease.lease_id,
                now=self.now + timedelta(seconds=2),
            )
        # Revocation released the hold, so the reservation is no longer held.
        self.assertIn("not held", str(raised.exception))
        self.assertEqual(Decimal("0"), spent_today(self.engine, self.now))


@unittest.skipIf(TestClient is None, "Install the api and dev extras to test FastAPI")
class ReplayAfterRevocationThroughTheConnectorTest(unittest.TestCase):
    """2 (continued). The same replay driven through the real gateway."""

    def setUp(self) -> None:
        from intentguard.api import create_app

        self.engine, _ = build_engine(now=datetime.now(timezone.utc))
        self.client = TestClient(create_app(self.engine))

    def test_the_connector_rejects_a_pre_revocation_lease(self) -> None:
        authorized = self.client.post(
            "/v1/actions/authorize",
            json={
                "request_id": "req-connector",
                "agent_id": AGENT_ID,
                "action": "book_flight",
                "amount": "16000",
                "currency": "INR",
                "intent_id": INTENT_ID,
                "risk_score": 20,
                "attributes": {"refundable": True},
            },
        ).json()
        self.assertEqual("allow", authorized["decision"]["decision"])

        self.assertEqual(
            204, self.client.post(f"/v1/agents/{AGENT_ID}/revoke").status_code
        )

        replayed = self.client.post(
            f"/v1/reservations/{authorized['reservation']['reservation_id']}/commit",
            json={"lease_id": authorized["lease"]["lease_id"]},
        )
        self.assertEqual(409, replayed.status_code)

        rejections = audit_payloads(self.engine, "connector.execution.rejected")
        self.assertEqual(1, len(rejections))
        self.assertEqual("req-connector", rejections[0]["request_id"])

        status = self.client.get("/v1/audit/status").json()
        self.assertTrue(status["verified"])


class BudgetTimeOfCheckTimeOfUseTest(unittest.TestCase):
    """3. Time-of-check to time-of-use against the daily cap."""

    def setUp(self) -> None:
        # Cap 20,000 with 18,000 already committed leaves 2,000 of headroom.
        self.engine, self.now = build_engine(daily_budget="20000")
        seeded = self.engine.authorize_action(booking("seed", amount="18000"), now=self.now)
        assert seeded.reservation is not None and seeded.lease is not None
        self.engine.commit_reservation(
            seeded.reservation.reservation_id,
            lease_id=seeded.lease.lease_id,
            now=self.now,
        )
        self.assertEqual(Decimal("18000"), spent_today(self.engine, self.now))

    def test_a_stale_check_cannot_be_turned_into_a_commit(self) -> None:
        """Passing the check, then losing the headroom, must fail the commit."""

        checked = self.engine.evaluate(booking("attacker", amount="2000"), now=self.now)
        self.assertIs(Decision.ALLOW, checked.decision)

        time.sleep(0.05)

        # A competing flow consumes the headroom in the gap.
        competitor = self.engine.authorize_action(
            booking("competitor", amount="2000"), now=self.now
        )
        assert competitor.reservation is not None and competitor.lease is not None
        self.engine.commit_reservation(
            competitor.reservation.reservation_id,
            lease_id=competitor.lease.lease_id,
            now=self.now,
        )

        # The stale check is worthless: execution needs a fresh authorization.
        late = self.engine.authorize_action(
            booking("attacker", amount="2000"), now=self.now
        )
        self.assertIs(Decision.DENY, late.decision.decision)
        self.assertIsNone(late.lease)
        self.assertIn(
            "DAILY_BUDGET_EXCEEDED",
            [finding.code for finding in late.decision.findings],
        )
        self.assertEqual(Decimal("20000"), spent_today(self.engine, self.now))

    def test_a_reservation_binds_the_funds_rather_than_observing_them(self) -> None:
        """Holding the headroom blocks the competitor, not the other way round."""

        holder = self.engine.authorize_action(
            booking("holder", amount="2000"), now=self.now
        )
        self.assertIs(Decision.ALLOW, holder.decision.decision)
        assert holder.reservation is not None and holder.lease is not None

        time.sleep(0.05)

        competitor = self.engine.authorize_action(
            booking("competitor", amount="2000"), now=self.now
        )
        self.assertIs(Decision.DENY, competitor.decision.decision)
        self.assertIn(
            "DAILY_BUDGET_EXCEEDED",
            [finding.code for finding in competitor.decision.findings],
        )

        committed = self.engine.commit_reservation(
            holder.reservation.reservation_id,
            lease_id=holder.lease.lease_id,
            now=self.now,
        )
        self.assertIs(ReservationStatus.COMMITTED, committed.status)
        self.assertEqual(Decimal("20000"), spent_today(self.engine, self.now))

    def test_a_stale_allow_decision_cannot_be_replayed_into_spend(self) -> None:
        """Two stale checks must not both become spend above the cap."""

        first = booking("stale-a", amount="2000")
        second = booking("stale-b", amount="2000")
        first_decision = self.engine.evaluate(first, now=self.now)
        second_decision = self.engine.evaluate(second, now=self.now)
        self.assertIs(Decision.ALLOW, first_decision.decision)
        self.assertIs(Decision.ALLOW, second_decision.decision)

        time.sleep(0.05)

        # The first stale decision still fits the headroom it was checked
        # against, so it is recorded.
        self.engine.record_execution(first, first_decision, executed_at=self.now)

        # The second was checked against the same headroom, which is now gone.
        with self.assertRaises(ValueError) as raised:
            self.engine.record_execution(second, second_decision, executed_at=self.now)
        self.assertIn("remaining daily budget", str(raised.exception))

        self.assertLessEqual(
            spent_today(self.engine, self.now),
            Decimal("20000"),
            "Stale allow decisions were replayed into spend above the daily cap.",
        )
        refusals = audit_payloads(self.engine, "action.execution_rejected")
        self.assertEqual(1, len(refusals))
        self.assertEqual("stale-b", refusals[0]["request_id"])
        self.assertEqual("daily_budget_exceeded", refusals[0]["reason"])
        self.assertTrue(self.engine.audit_ledger.verify())


class ConcurrentSpendRaceTest(unittest.TestCase):
    """4. N concurrent requests, each under the cap, summing to more than it."""

    ITERATIONS = 50
    WORKERS = 20
    CAP = Decimal("10000")
    AMOUNT = "1500"

    def _run_one_race(self, iteration: int) -> Decimal:
        engine, now = build_engine(daily_budget=str(self.CAP))
        barrier = threading.Barrier(self.WORKERS)

        def attempt(index: int) -> None:
            request = booking(f"race-{iteration}-{index}", amount=self.AMOUNT)
            barrier.wait()
            result = engine.authorize_action(request, now=now)
            if result.decision.decision is not Decision.ALLOW:
                return
            assert result.reservation is not None and result.lease is not None
            engine.commit_reservation(
                result.reservation.reservation_id,
                lease_id=result.lease.lease_id,
                now=now,
            )

        with ThreadPoolExecutor(max_workers=self.WORKERS) as executor:
            for future in [
                executor.submit(attempt, index) for index in range(self.WORKERS)
            ]:
                future.result()

        self.assertTrue(engine.audit_ledger.verify())
        return spent_today(engine, now)

    def test_concurrent_commits_never_exceed_the_daily_cap(self) -> None:
        # Each request is individually well under the cap, but 20 x 1,500 =
        # 30,000 is three times it. Races are intermittent, so repeat.
        self.assertLess(Decimal(self.AMOUNT), self.CAP)
        self.assertGreater(Decimal(self.AMOUNT) * self.WORKERS, self.CAP)

        totals: list[Decimal] = []
        for iteration in range(self.ITERATIONS):
            total = self._run_one_race(iteration)
            totals.append(total)
            self.assertLessEqual(
                total,
                self.CAP,
                f"Iteration {iteration} committed {total} against a cap of {self.CAP}.",
            )

        self.assertEqual(self.ITERATIONS, len(totals))
        self.assertLessEqual(max(totals), self.CAP)
        # 10,000 / 1,500 allows six commits; anything else means lost or
        # duplicated capacity rather than a clean serialization.
        self.assertEqual({Decimal("9000")}, set(totals))


class FleetEpochBypassTest(unittest.TestCase):
    """5. Work already in flight when the emergency stop is pulled."""

    OUTSTANDING = 5

    def setUp(self) -> None:
        self.engine, self.now = build_engine(daily_budget="100000")
        self.authorizations = [
            self.engine.authorize_action(
                booking(f"inflight-{index}", amount="1000"),
                now=self.now,
                lease_ttl=timedelta(minutes=30),
            )
            for index in range(self.OUTSTANDING)
        ]
        for authorization in self.authorizations:
            self.assertIs(Decision.ALLOW, authorization.decision.decision)
            self.assertIsNotNone(authorization.lease)

    def _commit_all(self, at: datetime) -> list[str]:
        """Try to execute every outstanding authorization; collect refusals."""

        refusals: list[str] = []
        for authorization in self.authorizations:
            assert authorization.reservation is not None
            assert authorization.lease is not None
            try:
                self.engine.commit_reservation(
                    authorization.reservation.reservation_id,
                    lease_id=authorization.lease.lease_id,
                    now=at,
                )
            except ValueError as exc:
                refusals.append(str(exc))
        return refusals

    def test_the_stop_invalidates_authorizations_already_in_flight(self) -> None:
        self.engine.stop_fleet(reason="Operator detected abnormal fleet activity.")

        refusals = self._commit_all(self.now + timedelta(seconds=1))

        self.assertEqual(self.OUTSTANDING, len(refusals))
        self.assertEqual(Decimal("0"), spent_today(self.engine, self.now))
        self.assertTrue(self.engine.audit_ledger.verify())

    def test_resuming_the_fleet_does_not_revive_pre_stop_authorizations(self) -> None:
        """The epoch must not roll back when the operator resumes the fleet."""

        stopped_epoch = self.engine.fleet_epoch
        self.engine.stop_fleet(reason="Emergency stop")
        self.assertGreater(self.engine.fleet_epoch, stopped_epoch)

        self.engine.resume_fleet()
        self.assertFalse(self.engine.fleet_stopped)

        refusals = self._commit_all(self.now + timedelta(seconds=2))
        self.assertEqual(self.OUTSTANDING, len(refusals))
        self.assertEqual(Decimal("0"), spent_today(self.engine, self.now))

        # A freshly issued authorization carries the new epoch and works.
        fresh = self.engine.authorize_action(
            booking("post-resume", amount="1000"), now=self.now
        )
        self.assertIs(Decision.ALLOW, fresh.decision.decision)
        assert fresh.reservation is not None and fresh.lease is not None
        self.assertEqual(self.engine.fleet_epoch, fresh.lease.fleet_epoch)
        self.engine.commit_reservation(
            fresh.reservation.reservation_id,
            lease_id=fresh.lease.lease_id,
            now=self.now,
        )
        self.assertEqual(Decimal("1000"), spent_today(self.engine, self.now))


class CrossCustomerIntentTest(unittest.TestCase):
    """8. Spending against another customer's authorization."""

    def setUp(self) -> None:
        # One concierge agent serving two customers, as a real deployment would.
        self.now = datetime(2026, 8, 22, 10, tzinfo=timezone.utc)
        self.engine = PolicyEngine()
        self.engine.register_agent(
            AgentProfile(
                agent_id=AGENT_ID,
                name="Shared Concierge",
                allowed_actions=frozenset({"book_flight"}),
                max_action_amount=Decimal("50000"),
                daily_budget=Decimal("100000"),
            )
        )
        for customer, ceiling in (("alice", "5000"), ("bob", "45000")):
            self.engine.register_intent(
                IntentPassport(
                    intent_id=f"intent-{customer}",
                    customer_id=customer,
                    agent_id=AGENT_ID,
                    action="book_flight",
                    max_amount=Decimal(ceiling),
                    currency="INR",
                    expires_at=self.now + timedelta(hours=2),
                )
            )

    def _attempt(
        self, request_id: str, *, intent_id: str, customer_id: str | None, amount: str
    ) -> DecisionRecord:
        return self.engine.evaluate(
            ActionRequest(
                request_id=request_id,
                agent_id=AGENT_ID,
                action="book_flight",
                amount=Decimal(amount),
                currency="INR",
                intent_id=intent_id,
                risk_score=0,
                attributes={},
                customer_id=customer_id,
            ),
            now=self.now,
        )

    def test_citing_another_customers_intent_is_denied(self) -> None:
        """Alice's ceiling is 5,000; Bob's intent must not raise it to 45,000."""

        decision = self._attempt(
            "cross-customer",
            intent_id="intent-bob",
            customer_id="alice",
            amount="45000",
        )

        self.assertIs(Decision.DENY, decision.decision)
        self.assertIn(
            "INTENT_CUSTOMER_MISMATCH",
            [finding.code for finding in decision.findings],
        )

    def test_each_customer_can_still_use_their_own_intent(self) -> None:
        """The control must not break the ordinary case."""

        for customer, amount in (("alice", "5000"), ("bob", "45000")):
            with self.subTest(customer=customer):
                decision = self._attempt(
                    f"own-{customer}",
                    intent_id=f"intent-{customer}",
                    customer_id=customer,
                    amount=amount,
                )
                self.assertIs(Decision.ALLOW, decision.decision)

    def test_the_binding_also_holds_through_authorization(self) -> None:
        """No lease or reservation is issued for a mismatched customer."""

        result = self.engine.authorize_action(
            ActionRequest(
                request_id="cross-customer-authorize",
                agent_id=AGENT_ID,
                action="book_flight",
                amount=Decimal("45000"),
                currency="INR",
                intent_id="intent-bob",
                risk_score=0,
                attributes={},
                customer_id="alice",
            ),
            now=self.now,
        )

        self.assertIs(Decision.DENY, result.decision.decision)
        self.assertIsNone(result.reservation)
        self.assertIsNone(result.lease)

    def test_the_same_request_id_cannot_be_reused_across_customers(self) -> None:
        """Swapping only the customer is a different action, not a replay."""

        first = self.engine.authorize_action(
            ActionRequest(
                request_id="shared-id",
                agent_id=AGENT_ID,
                action="book_flight",
                amount=Decimal("5000"),
                currency="INR",
                intent_id="intent-alice",
                risk_score=0,
                attributes={},
                customer_id="alice",
            ),
            now=self.now,
        )
        self.assertIs(Decision.ALLOW, first.decision.decision)

        with self.assertRaises(ValueError) as raised:
            self.engine.authorize_action(
                ActionRequest(
                    request_id="shared-id",
                    agent_id=AGENT_ID,
                    action="book_flight",
                    amount=Decimal("5000"),
                    currency="INR",
                    intent_id="intent-alice",
                    risk_score=0,
                    attributes={},
                    customer_id="bob",
                ),
                now=self.now,
            )
        self.assertIn("different action data", str(raised.exception))

    def test_unauthenticated_callers_keep_working(self) -> None:
        """customer_id is optional, so existing integrations are unaffected."""

        decision = self._attempt(
            "legacy", intent_id="intent-bob", customer_id=None, amount="45000"
        )
        self.assertIs(Decision.ALLOW, decision.decision)


class SelfReportedRiskTest(unittest.TestCase):
    """7. The agent grading its own risk to duck human approval."""

    def setUp(self) -> None:
        # Ceiling 18,000 against a 20,000 daily cap: a maxed booking sits at the
        # top of both envelopes. The intent deliberately does not pin
        # refundability, so choosing a non-refundable commitment is the agent's
        # discretion rather than a blocking envelope violation -- which is
        # exactly the case where a risk score has to do real work.
        self.engine, self.now = build_engine(
            daily_budget="20000", intent_attributes={}
        )

    def test_declared_risk_can_never_lower_the_effective_score(self) -> None:
        """Monotonicity: the agent's number may raise risk, never reduce it."""

        for declared in (0, 1, 25, 50, 69, 70, 99, 100):
            with self.subTest(declared=declared):
                decision = self.engine.evaluate(
                    booking(f"mono-{declared}", amount="5000", risk_score=declared),
                    now=self.now,
                )
                assert decision.risk is not None
                self.assertGreaterEqual(decision.risk.effective, declared)
                self.assertGreaterEqual(decision.risk.effective, decision.risk.derived)
                self.assertEqual(
                    max(declared, decision.risk.derived),
                    decision.risk.effective,
                )

    def test_declaring_zero_does_not_buy_a_lower_score(self) -> None:
        """Under-declaring gains the agent nothing at all."""

        honest = self.engine.evaluate(
            booking("honest", amount="9000", risk_score=40), now=self.now
        )
        lying = self.engine.evaluate(
            booking("lying", amount="9000", risk_score=0), now=self.now
        )
        assert honest.risk is not None and lying.risk is not None

        # Same action, so the gateway derives the same number for both.
        self.assertEqual(honest.risk.derived, lying.risk.derived)
        # Declaring zero cannot go below it.
        self.assertEqual(lying.risk.derived, lying.risk.effective)

    def test_a_dangerous_action_declared_safe_is_still_reviewed(self) -> None:
        """The headline attack: risk_score=0 on an action that must be seen."""

        decision = self.engine.evaluate(
            ActionRequest(
                request_id="ducking-review",
                agent_id=AGENT_ID,
                action="book_flight",
                amount=Decimal("18000"),
                currency="INR",
                intent_id=INTENT_ID,
                risk_score=0,
                attributes={"refundable": False},
            ),
            now=self.now,
        )

        assert decision.risk is not None
        self.assertEqual(0, decision.risk.declared)
        self.assertGreaterEqual(decision.risk.derived, 70)
        self.assertIs(Decision.REVIEW, decision.decision)

        codes = [finding.code for finding in decision.findings]
        self.assertIn("RISK_SCORE_UNDER_DECLARED", codes)
        self.assertIn("HUMAN_APPROVAL_REQUIRED", codes)

    def test_repeated_envelope_maxing_escalates_even_at_declared_zero(self) -> None:
        """Velocity is derived from engine history, not from the agent."""

        engine, now = build_engine(daily_budget="200000")
        outcomes = []
        for index in range(6):
            result = engine.authorize_action(
                booking(f"velocity-{index}", amount="18000", risk_score=0),
                now=now,
            )
            assert result.decision.risk is not None
            outcomes.append(
                (result.decision.decision, result.decision.risk.derived)
            )

        # Derived risk is non-decreasing as the agent keeps hammering.
        derived = [score for _, score in outcomes]
        self.assertEqual(sorted(derived), derived)
        # And it eventually forces a human to look, despite declared zero.
        self.assertIn(Decision.REVIEW, [decision for decision, _ in outcomes])

    def test_the_under_declaration_is_recorded_in_the_audit_trail(self) -> None:
        self.engine.evaluate(
            ActionRequest(
                request_id="audited-underdeclaration",
                agent_id=AGENT_ID,
                action="book_flight",
                amount=Decimal("18000"),
                currency="INR",
                intent_id=INTENT_ID,
                risk_score=0,
                attributes={"refundable": False},
            ),
            now=self.now,
        )

        (evaluated,) = [
            payload
            for payload in audit_payloads(self.engine, "policy.evaluated")
            if payload["request_id"] == "audited-underdeclaration"
        ]
        self.assertEqual(0, evaluated["declared_risk"])
        self.assertGreaterEqual(evaluated["derived_risk"], 70)
        self.assertEqual(evaluated["derived_risk"], evaluated["effective_risk"])
        self.assertTrue(evaluated["risk_signals"])
        self.assertIn("RISK_SCORE_UNDER_DECLARED", evaluated["finding_codes"])
        self.assertTrue(self.engine.audit_ledger.verify())

    def test_an_in_policy_action_is_not_over_flagged(self) -> None:
        """The control must not make every ordinary action need a human."""

        decision = self.engine.evaluate(
            booking("ordinary", amount="3000", risk_score=10), now=self.now
        )
        assert decision.risk is not None
        self.assertLess(decision.risk.effective, 70)
        self.assertIs(Decision.ALLOW, decision.decision)


class AuditChainTamperingTest(unittest.TestCase):
    """6. Mutation, deletion, and reordering of chained audit events."""

    EVENTS = 6

    def setUp(self) -> None:
        self.ledger = AuditLedger()
        for index in range(self.EVENTS):
            self.ledger.append(
                "action.executed",
                {"request_id": f"req-{index}", "amount": Decimal("1000")},
            )

    def test_an_untampered_chain_verifies(self) -> None:
        self.assertTrue(self.ledger.verify())
        self.assertIsNone(self.ledger.first_invalid_link())

    def test_mutating_one_event_in_place_breaks_the_chain(self) -> None:
        tampered = copy.deepcopy(self.ledger)
        tampered.events[2].payload["amount"] = Decimal("999999")

        self.assertFalse(tampered.verify())
        self.assertEqual(3, tampered.first_invalid_link())
        # Only the mutated link and its successors are implicated.
        self.assertEqual(self.EVENTS, len(tampered.events))

    def test_mutating_an_event_field_breaks_the_chain(self) -> None:
        tampered = copy.deepcopy(self.ledger)
        object.__setattr__(tampered.events[4], "event_type", "action.approved")

        self.assertFalse(tampered.verify())
        self.assertEqual(5, tampered.first_invalid_link())

    def test_deleting_a_middle_event_breaks_the_chain(self) -> None:
        tampered = copy.deepcopy(self.ledger)
        removed = tampered.events[2]
        tampered._events.pop(2)

        self.assertFalse(tampered.verify())
        self.assertEqual(self.EVENTS - 1, len(tampered.events))
        # The hole is at position 3: the event now sitting there still points at
        # the hash of the event that was removed.
        self.assertEqual(3, tampered.first_invalid_link())
        self.assertEqual(removed.event_hash, tampered.events[2].previous_hash)

    def test_reordering_two_events_breaks_the_chain(self) -> None:
        tampered = copy.deepcopy(self.ledger)
        events = tampered._events
        events[2], events[3] = events[3], events[2]

        self.assertFalse(tampered.verify())
        self.assertEqual(3, tampered.first_invalid_link())

    def test_truncating_the_newest_events_breaks_the_chain(self) -> None:
        """An attacker's own events are always the newest ones."""

        for removed in (1, 2, self.EVENTS):
            with self.subTest(removed=removed):
                tampered = copy.deepcopy(self.ledger)
                del tampered._events[self.EVENTS - removed :]

                self.assertEqual(self.EVENTS - removed, len(tampered.events))
                self.assertFalse(
                    tampered.verify(),
                    "Truncating the tail left a chain that still verified.",
                )
                # The break is reported at the first position that is missing.
                self.assertEqual(
                    self.EVENTS - removed + 1, tampered.first_invalid_link()
                )

    def test_the_checkpoint_survives_a_wholesale_replacement(self) -> None:
        """Rebuilding a shorter chain from genesis does not restore the head."""

        forged = AuditLedger()
        for index in (0, 1, 4):
            forged.append(
                "action.executed",
                {"request_id": f"req-{index}", "amount": Decimal("1000")},
            )
        # A forged chain is internally consistent; only comparison against a
        # separately held expectation reveals it.
        self.assertTrue(forged.verify())
        self.assertNotEqual(
            self.ledger.checkpoint.head_hash, forged.checkpoint.head_hash
        )
        self.assertNotEqual(
            self.ledger.checkpoint.event_count, forged.checkpoint.event_count
        )

    def test_appending_a_forged_event_breaks_the_chain(self) -> None:
        tampered = copy.deepcopy(self.ledger)
        tampered._events.append(tampered._events[-1])

        self.assertFalse(tampered.verify())
        self.assertEqual(self.EVENTS + 1, tampered.first_invalid_link())

    def test_a_tampered_engine_ledger_is_detected_through_the_engine(self) -> None:
        engine, now = build_engine()
        engine.authorize_action(booking("req-audited"), now=now)
        self.assertTrue(engine.audit_ledger.verify())

        engine.audit_ledger.events[1].payload["agent_id"] = "attacker-agent"

        self.assertFalse(engine.audit_ledger.verify())
        self.assertEqual(2, engine.audit_ledger.first_invalid_link())


if __name__ == "__main__":
    unittest.main()
