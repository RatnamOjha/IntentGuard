from __future__ import annotations

import multiprocessing as mp
import os
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from unittest.mock import MagicMock

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


class PostgresBatchApiTest(unittest.TestCase):
    def test_batch_writes_use_a_psycopg_cursor(self) -> None:
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        params = [("first", 1), ("second", 2)]

        PostgresStateRepository._executemany(
            connection, "INSERT INTO example VALUES (%s, %s)", params
        )

        connection.cursor.assert_called_once_with()
        cursor.executemany.assert_called_once_with(
            "INSERT INTO example VALUES (%s, %s)", params
        )


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


# ---------------------------------------------------------------------------
# Idempotency across replicas
#
# authorize_action reads the stored authorization for a request_id and, on a
# miss, issues a fresh reservation and lease. The engine's RLock makes that
# check-then-act atomic within one process and does nothing across two, which
# is the deployment the project documents. Threads cannot show this; only
# separate OS processes sharing one database can.
# ---------------------------------------------------------------------------

IDEMPOTENCY_WORKERS = 8


def _same_request_worker(  # noqa: ANN001
    barrier, results, database_url: str, agent_id: str, intent_id: str, request_id: str
) -> None:
    """One replica authorizing the request_id every other replica is authorizing."""

    from intentguard.audit import PostgresAuditLedger
    from intentguard.budget import PostgresBudgetLedger
    from intentguard.models import ActionRequest
    from intentguard.persistence import PostgresStateRepository
    from intentguard.policy_engine import PolicyEngine

    engine = PolicyEngine(
        budget_ledger=PostgresBudgetLedger(database_url),
        state_repository=PostgresStateRepository(database_url),
        audit_ledger=PostgresAuditLedger(database_url),
    )
    try:
        request = ActionRequest(
            request_id=request_id,
            agent_id=agent_id,
            action="pay",
            amount=Decimal("100"),
            currency="INR",
            intent_id=intent_id,
            risk_score=1,
            customer_id="customer-1",
            occurred_at=NOW,
        )
        barrier.wait()
        result = engine.authorize_action(request, now=NOW)
        results.append(
            (
                result.decision.decision.value,
                result.lease.lease_id if result.lease is not None else None,
                (
                    result.reservation.reservation_id
                    if result.reservation is not None
                    else None
                ),
            )
        )
    except Exception as exc:  # a crash is a result worth seeing, not a hang
        results.append(("error", type(exc).__name__, str(exc)[:120]))
    finally:
        engine.close()


@unittest.skipUnless(
    postgres_available(), "PostgreSQL governance migration is unavailable"
)
class ConcurrentIdempotencyTest(unittest.TestCase):
    """One request_id must buy exactly one reservation, however many replicas ask."""

    def setUp(self) -> None:
        from intentguard.budget import PostgresBudgetLedger

        suffix = uuid.uuid4().hex
        self.agent_id = f"idem-agent-{suffix}"
        self.intent_id = f"idem-intent-{suffix}"
        self.request_id = f"idem-request-{suffix}"

        self.repository = PostgresStateRepository(DATABASE_URL)
        self.budget = PostgresBudgetLedger(DATABASE_URL)
        self.addCleanup(self.repository.close)
        self.addCleanup(self.budget.close)

        engine = PolicyEngine(
            state_repository=self.repository, budget_ledger=self.budget
        )
        engine.register_agent(
            AgentProfile(
                agent_id=self.agent_id,
                name="Idempotency Agent",
                allowed_actions=frozenset({"pay"}),
                max_action_amount=Decimal("1000"),
                # Deliberately far above 8 x 100, so a duplicate is not masked
                # by the cap refusing it. The cap is not what is under test.
                daily_budget=Decimal("1000000"),
            )
        )
        engine.register_intent(
            IntentPassport(
                intent_id=self.intent_id,
                customer_id="customer-1",
                agent_id=self.agent_id,
                action="pay",
                max_amount=Decimal("1000"),
                currency="INR",
                expires_at=NOW + timedelta(hours=1),
            )
        )

    def _race(self) -> list[tuple]:
        context = mp.get_context("spawn")
        with context.Manager() as manager:
            results = manager.list()
            barrier = manager.Barrier(IDEMPOTENCY_WORKERS)
            processes = [
                context.Process(
                    target=_same_request_worker,
                    args=(
                        barrier,
                        results,
                        DATABASE_URL,
                        self.agent_id,
                        self.intent_id,
                        self.request_id,
                    ),
                )
                for _ in range(IDEMPOTENCY_WORKERS)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=120)
            for process in processes:
                self.assertEqual(0, process.exitcode, "A replica crashed.")
            return list(results)

    def _reservations(self) -> list[tuple]:
        import psycopg

        with psycopg.connect(DATABASE_URL) as connection:
            return connection.execute(
                "SELECT reservation_id, status, amount FROM reservations "
                "WHERE request_id = %s ORDER BY reservation_id",
                (self.request_id,),
            ).fetchall()

    def test_one_request_id_buys_one_reservation_across_replicas(self) -> None:
        outcomes = self._race()

        self.assertEqual(IDEMPOTENCY_WORKERS, len(outcomes))
        self.assertTrue(
            all(outcome[0] == "allow" for outcome in outcomes),
            f"Every replica should have been allowed: {outcomes}",
        )

        held = [row for row in self._reservations() if row[1] == "held"]
        self.assertEqual(
            1,
            len(held),
            f"One request_id held {len(held)} reservations: {held}",
        )

        leases = {outcome[1] for outcome in outcomes}
        self.assertEqual(
            1,
            len(leases),
            f"One request_id handed out {len(leases)} distinct leases: {leases}",
        )

    def test_duplicate_authorizations_do_not_hold_extra_budget(self) -> None:
        """Eight replicas asking for 100 must hold 100, not 800."""

        self._race()
        exposure = self.budget.exposure(self.agent_id, NOW.date())
        self.assertEqual(Decimal("100"), exposure.reserved)


# ---------------------------------------------------------------------------
# Approval transitions across replicas
#
# approve_action reads the approval, sees PENDING, and issues a lease. That is
# the same check-then-act shape authorize_action had: atomic within one process
# because of the engine lock, and unguarded across two.
# ---------------------------------------------------------------------------


def _approve_worker(  # noqa: ANN001
    barrier, results, database_url: str, request_id: str, reviewer: str
) -> None:
    """One replica approving the review every other replica is approving."""

    from intentguard.audit import PostgresAuditLedger
    from intentguard.budget import PostgresBudgetLedger
    from intentguard.persistence import PostgresStateRepository
    from intentguard.policy_engine import PolicyEngine

    engine = PolicyEngine(
        budget_ledger=PostgresBudgetLedger(database_url),
        state_repository=PostgresStateRepository(database_url),
        audit_ledger=PostgresAuditLedger(database_url),
    )
    try:
        barrier.wait()
        result = engine.approve_action(
            request_id,
            reviewer=reviewer,
            reason="concurrent approval",
            now=NOW + timedelta(minutes=1),
        )
        results.append(
            (
                reviewer,
                result.decision.decision.value,
                result.lease.lease_id if result.lease is not None else None,
                (
                    result.reservation.reservation_id
                    if result.reservation is not None
                    else None
                ),
            )
        )
    except Exception as exc:
        results.append((reviewer, "error", type(exc).__name__, str(exc)[:120]))
    finally:
        engine.close()


@unittest.skipUnless(
    postgres_available(), "PostgreSQL governance migration is unavailable"
)
class ConcurrentApprovalTest(unittest.TestCase):
    """One pending approval must resolve once, however many reviewers act."""

    WORKERS = 8

    def setUp(self) -> None:
        from intentguard.budget import PostgresBudgetLedger

        suffix = uuid.uuid4().hex
        self.agent_id = f"appr-agent-{suffix}"
        self.intent_id = f"appr-intent-{suffix}"
        self.request_id = f"appr-request-{suffix}"

        self.repository = PostgresStateRepository(DATABASE_URL)
        self.budget = PostgresBudgetLedger(DATABASE_URL)
        self.addCleanup(self.repository.close)
        self.addCleanup(self.budget.close)

        engine = PolicyEngine(
            state_repository=self.repository, budget_ledger=self.budget
        )
        engine.register_agent(
            AgentProfile(
                agent_id=self.agent_id,
                name="Approval Agent",
                allowed_actions=frozenset({"pay"}),
                max_action_amount=Decimal("1000"),
                # Far above WORKERS x 100, so a duplicate lease is never masked
                # by the cap refusing it. The cap is not what is under test.
                daily_budget=Decimal("1000000"),
            )
        )
        engine.register_intent(
            IntentPassport(
                intent_id=self.intent_id,
                customer_id="customer-1",
                agent_id=self.agent_id,
                action="pay",
                max_amount=Decimal("1000"),
                currency="INR",
                expires_at=NOW + timedelta(hours=1),
            )
        )
        # risk_score 100 routes the action to human review, leaving exactly one
        # PENDING approval for the replicas to race over.
        review = ActionRequest(
            request_id=self.request_id,
            agent_id=self.agent_id,
            action="pay",
            amount=Decimal("100"),
            currency="INR",
            intent_id=self.intent_id,
            risk_score=100,
            customer_id="customer-1",
            submitted_by="agent-user",
            occurred_at=NOW,
        )
        outcome = engine.authorize_action(review, now=NOW)
        self.assertEqual(Decision.REVIEW, outcome.decision.decision)
        self.assertIsNone(outcome.lease)

    def _race(self) -> list[tuple]:
        context = mp.get_context("spawn")
        with context.Manager() as manager:
            results = manager.list()
            barrier = manager.Barrier(self.WORKERS)
            processes = [
                context.Process(
                    target=_approve_worker,
                    args=(
                        barrier,
                        results,
                        DATABASE_URL,
                        self.request_id,
                        f"reviewer-{index}",
                    ),
                )
                for index in range(self.WORKERS)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=120)
            for process in processes:
                self.assertEqual(0, process.exitcode, "A replica crashed.")
            return list(results)

    def _reservations(self) -> list[tuple]:
        import psycopg

        with psycopg.connect(DATABASE_URL) as connection:
            return connection.execute(
                "SELECT reservation_id, status, amount FROM reservations "
                "WHERE request_id = %s ORDER BY reservation_id",
                (self.request_id,),
            ).fetchall()

    def _approval_event_reviewers(self) -> list[str]:
        """Who the audit trail says approved this request."""

        import psycopg

        with psycopg.connect(DATABASE_URL) as connection:
            rows = connection.execute(
                "SELECT payload ->> 'reviewer' FROM audit_events "
                "WHERE event_type = 'approval.approved' "
                "AND payload ->> 'request_id' = %s ORDER BY sequence",
                (self.request_id,),
            ).fetchall()
        return [row[0] for row in rows]

    def test_one_approval_issues_one_lease_across_replicas(self) -> None:
        outcomes = self._race()

        self.assertEqual(self.WORKERS, len(outcomes))
        errors = [item for item in outcomes if item[1] == "error"]
        self.assertEqual([], errors, f"No replica should have failed: {errors}")

        leases = {item[2] for item in outcomes}
        self.assertEqual(
            1,
            len(leases),
            f"One approval handed out {len(leases)} distinct leases: {leases}",
        )

        held = [row for row in self._reservations() if row[1] == "held"]
        self.assertEqual(
            1,
            len(held),
            f"One approval held {len(held)} reservations: {held}",
        )

    def test_concurrent_approvals_do_not_hold_extra_budget(self) -> None:
        """Eight reviewers approving one 100 action must hold 100, not 800."""

        self._race()
        exposure = self.budget.exposure(self.agent_id, NOW.date())
        self.assertEqual(Decimal("100"), exposure.reserved)

    def test_exactly_one_reviewer_wins_the_transition(self) -> None:
        """One approval means one audit event, not one per replica.

        Asserting on the approval row alone would not detect the race: every
        replica writes APPROVED and the last writer wins, so the row looks
        settled either way. The audit trail is what distinguishes one approval
        from eight, and a replica that lost the transition approved nothing.
        """

        self._race()
        engine = PolicyEngine(
            state_repository=PostgresStateRepository(DATABASE_URL),
            budget_ledger=self.budget,
        )
        self.addCleanup(engine.close)

        approvals = {item.request_id: item for item in engine.list_approvals()}
        resolved = approvals[self.request_id]
        self.assertEqual(ApprovalStatus.APPROVED, resolved.status)
        self.assertIsNotNone(resolved.reviewer)
        self.assertEqual("concurrent approval", resolved.reason)

        reviewers = self._approval_event_reviewers()
        self.assertEqual(
            1,
            len(reviewers),
            f"One approval produced {len(reviewers)} approval.approved "
            f"events, by {reviewers}",
        )
        self.assertEqual(resolved.reviewer, reviewers[0])
