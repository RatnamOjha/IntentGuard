from __future__ import annotations

import os
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from intentguard.budget import InMemoryBudgetLedger  # noqa: E402
from intentguard.models import (  # noqa: E402
    ActionRequest,
    AgentProfile,
    ApprovalStatus,
    Decision,
    IntentPassport,
    ReservationStatus,
)
from intentguard.persistence import (  # noqa: E402
    InMemoryStateRepository,
    PostgresStateRepository,
    _decode,
    _encode,
)
from intentguard.policy_engine import PolicyEngine  # noqa: E402


NOW = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)


class SharedStateContract:
    repository: object
    budget: object

    def make_engine(self) -> PolicyEngine:
        return PolicyEngine(
            state_repository=self.repository,
            budget_ledger=self.budget,
        )

    def bootstrap(self, engine: PolicyEngine, suffix: str = "") -> tuple[str, str]:
        agent_id = f"durable-agent{suffix}"
        intent_id = f"durable-intent{suffix}"
        engine.register_agent(
            AgentProfile(
                agent_id=agent_id,
                name="Durable Agent",
                allowed_actions=frozenset({"pay"}),
                max_action_amount=Decimal("1000"),
                daily_budget=Decimal("5000"),
            )
        )
        engine.register_intent(
            IntentPassport(
                intent_id=intent_id,
                customer_id="customer-1",
                agent_id=agent_id,
                action="pay",
                max_amount=Decimal("1000"),
                currency="INR",
                expires_at=NOW + timedelta(hours=1),
            )
        )
        return agent_id, intent_id

    @staticmethod
    def request(agent_id: str, intent_id: str, request_id: str, *, risk: int = 1) -> ActionRequest:
        return ActionRequest(
            request_id=request_id,
            agent_id=agent_id,
            action="pay",
            amount=Decimal("100"),
            currency="INR",
            intent_id=intent_id,
            risk_score=risk,
            customer_id="customer-1",
            submitted_by="agent-user",
            occurred_at=NOW,
        )

    def test_lease_issued_by_one_instance_can_be_committed_by_another(self) -> None:
        first, second = self.make_engine(), self.make_engine()
        agent_id, intent_id = self.bootstrap(first, self.unique_suffix())
        result = first.authorize_action(
            self.request(agent_id, intent_id, self.unique_id("request")), now=NOW
        )

        committed = second.commit_reservation(
            result.reservation.reservation_id,
            lease_id=result.lease.lease_id,
            now=NOW + timedelta(seconds=1),
        )

        self.assertEqual(ReservationStatus.COMMITTED, committed.status)

    def test_fleet_stop_and_revocation_are_seen_after_restart(self) -> None:
        first = self.make_engine()
        agent_id, intent_id = self.bootstrap(first, self.unique_suffix())
        first.stop_fleet(reason="incident")
        restarted = self.make_engine()
        self.assertTrue(restarted.fleet_stopped)
        denied = restarted.evaluate(
            self.request(agent_id, intent_id, self.unique_id("fleet")), now=NOW
        )
        self.assertEqual(Decision.DENY, denied.decision)

        first.resume_fleet()
        first.revoke_agent(agent_id)
        restarted_again = self.make_engine()
        revoked = restarted_again.evaluate(
            self.request(agent_id, intent_id, self.unique_id("revoked")), now=NOW
        )
        self.assertIn("AGENT_REVOKED", {item.code for item in revoked.findings})

    def test_approval_and_idempotency_survive_restart(self) -> None:
        first = self.make_engine()
        agent_id, intent_id = self.bootstrap(first, self.unique_suffix())
        review_request = self.request(
            agent_id, intent_id, self.unique_id("review"), risk=100
        )
        first.authorize_action(review_request, now=NOW)

        restarted = self.make_engine()
        approvals = {item.request_id: item for item in restarted.list_approvals()}
        self.assertEqual(ApprovalStatus.PENDING, approvals[review_request.request_id].status)

        allowed_request = self.request(
            agent_id, intent_id, self.unique_id("idempotent")
        )
        original = first.authorize_action(allowed_request, now=NOW)
        retried = self.make_engine().authorize_action(allowed_request, now=NOW)
        self.assertEqual(original.lease.lease_id, retried.lease.lease_id)

    def unique_suffix(self) -> str:
        return ""

    def unique_id(self, prefix: str) -> str:
        return prefix


class InMemoryStateRepositoryTest(SharedStateContract, unittest.TestCase):
    def setUp(self) -> None:
        self.repository = InMemoryStateRepository()
        self.budget = InMemoryBudgetLedger()

    def test_postgres_json_round_trip_preserves_domain_types(self) -> None:
        agent_id, intent_id = "round-trip-agent", "round-trip-intent"
        request = self.request(agent_id, intent_id, "round-trip-request")
        self.assertEqual(request, _decode(_encode(request)))


DATABASE_URL = os.getenv("INTENTGUARD_DATABASE_URL", "postgresql:///intentguard")


def postgres_available() -> bool:
    try:
        import psycopg
    except ImportError:
        return False
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=3) as connection:
            connection.execute("SELECT 1 FROM governance_metadata LIMIT 1")
        return True
    except Exception:
        return False


@unittest.skipUnless(postgres_available(), "PostgreSQL governance migration is unavailable")
class PostgresStateRepositoryTest(SharedStateContract, unittest.TestCase):
    def setUp(self) -> None:
        from intentguard.budget import PostgresBudgetLedger

        self.repository = PostgresStateRepository(DATABASE_URL)
        self.budget = PostgresBudgetLedger(DATABASE_URL)
        self._suffix = f"-{uuid.uuid4().hex}"

    def tearDown(self) -> None:
        self.repository.close()
        self.budget.close()

    def unique_suffix(self) -> str:
        return self._suffix

    def unique_id(self, prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex}"
