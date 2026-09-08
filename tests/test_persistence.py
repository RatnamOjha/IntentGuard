from __future__ import annotations

import multiprocessing as mp
import os
import sys
import typing
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
    FindingContext,
    IntentPassport,
    PolicyFinding,
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


# ---------------------------------------------------------------------------
# Counters and epochs across replicas
#
# Every numeric field in GovernanceState is incremented as a read-modify-write
# in Python and merged on save. Two replicas that each read N and write N+1
# leave N+1 where N+2 happened. Threads cannot show this; separate OS processes
# sharing one database can.
# ---------------------------------------------------------------------------

COUNTER_WORKERS = 8


def _counter_worker(barrier, results, database_url, kind, agent_id, intent_id):  # noqa: ANN001
    """One replica performing a single increment of the named counter."""

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
        barrier.wait()
        if kind == "authorization_count":
            outcome = engine.authorize_action(
                ActionRequest(
                    request_id=f"count-{uuid.uuid4().hex}",
                    agent_id=agent_id,
                    action="pay",
                    amount=Decimal("1"),
                    currency="INR",
                    intent_id=intent_id,
                    risk_score=0,
                    customer_id="customer-1",
                    occurred_at=NOW,
                ),
                now=NOW,
            )
            results.append(("ok", outcome.decision.decision.value))
        elif kind == "fleet_epoch":
            engine.stop_fleet(reason="counter race")
            results.append(("ok", engine.fleet_epoch))
        elif kind == "policy_revision":
            engine.update_agent_policy(
                agent_id,
                allowed_actions=frozenset({"pay"}),
                max_action_amount=Decimal("1000"),
                daily_budget=Decimal("1000000"),
                active=True,
                operator=f"operator-{os.getpid()}",
                reason="counter race",
                now=NOW,
            )
            results.append(("ok", engine.policy_version))
        elif kind == "revocation_epoch":
            engine.revoke_agent(agent_id)
            results.append(("ok", agent_id))
    except Exception as exc:
        results.append(("error", f"{type(exc).__name__}: {str(exc)[:100]}"))
    finally:
        engine.close()


@unittest.skipUnless(
    postgres_available(), "PostgreSQL governance migration is unavailable"
)
class ConcurrentCounterTest(unittest.TestCase):
    """N concurrent increments must leave N, not 1."""

    def setUp(self) -> None:
        from intentguard.budget import PostgresBudgetLedger

        suffix = uuid.uuid4().hex
        self.agent_id = f"count-agent-{suffix}"
        self.intent_id = f"count-intent-{suffix}"

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
                name="Counter Agent",
                allowed_actions=frozenset({"pay"}),
                max_action_amount=Decimal("1000"),
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

    def _race(self, kind: str) -> list[tuple]:
        context = mp.get_context("spawn")
        with context.Manager() as manager:
            results = manager.list()
            barrier = manager.Barrier(COUNTER_WORKERS)
            processes = [
                context.Process(
                    target=_counter_worker,
                    args=(
                        barrier,
                        results,
                        DATABASE_URL,
                        kind,
                        self.agent_id,
                        self.intent_id,
                    ),
                )
                for _ in range(COUNTER_WORKERS)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=120)
            for process in processes:
                self.assertEqual(0, process.exitcode, "A replica crashed.")
            outcomes = list(results)
        errors = [item for item in outcomes if item[0] == "error"]
        self.assertEqual([], errors, f"No replica should have failed: {errors}")
        return outcomes

    @staticmethod
    def _scalar(query: str, parameters: tuple) -> object:
        import psycopg

        with psycopg.connect(DATABASE_URL) as connection:
            row = connection.execute(query, parameters).fetchone()
        return None if row is None else row[0]

    def test_authorization_count_sums_concurrent_increments(self) -> None:
        """The velocity counter feeds risk scoring, so undercounting hides risk."""

        self._race("authorization_count")

        stored = self._scalar(
            "SELECT authorization_count FROM authorization_counters "
            "WHERE agent_id = %s AND budget_date = %s",
            (self.agent_id, NOW.date()),
        )
        self.assertEqual(
            COUNTER_WORKERS,
            stored,
            f"{COUNTER_WORKERS} authorizations counted as {stored}.",
        )

    def test_fleet_epoch_sums_concurrent_stops(self) -> None:
        """A collapsed epoch lets a lease survive the stop that should void it."""

        before = self._scalar(
            "SELECT fleet_epoch FROM governance_metadata WHERE singleton = TRUE", ()
        )
        # Leave the shared database usable for every test that follows.
        self.addCleanup(
            PolicyEngine(
                state_repository=PostgresStateRepository(DATABASE_URL),
                budget_ledger=self.budget,
            ).resume_fleet
        )

        self._race("fleet_epoch")

        after = self._scalar(
            "SELECT fleet_epoch FROM governance_metadata WHERE singleton = TRUE", ()
        )
        self.assertEqual(
            (before or 0) + COUNTER_WORKERS,
            after,
            f"{COUNTER_WORKERS} fleet stops moved the epoch from {before} to {after}.",
        )

    def test_policy_revision_sums_concurrent_updates(self) -> None:
        """Two policies sharing one version string cannot be told apart later."""

        before = self._scalar(
            "SELECT policy_revision FROM governance_metadata WHERE singleton = TRUE",
            (),
        )

        self._race("policy_revision")

        after = self._scalar(
            "SELECT policy_revision FROM governance_metadata WHERE singleton = TRUE",
            (),
        )
        self.assertEqual(
            (before or 0) + COUNTER_WORKERS,
            after,
            f"{COUNTER_WORKERS} policy updates moved the revision from "
            f"{before} to {after}.",
        )

    def test_revocation_epoch_sums_concurrent_revocations(self) -> None:
        self._race("revocation_epoch")

        stored = self._scalar(
            "SELECT revocation_epoch FROM agent_revocations WHERE agent_id = %s",
            (self.agent_id,),
        )
        self.assertEqual(
            COUNTER_WORKERS,
            stored,
            f"{COUNTER_WORKERS} revocations counted as {stored}.",
        )


# ---------------------------------------------------------------------------
# Fleet stop durability and stop-wins resume
#
# These are fault-injection tests, not concurrency tests: the failure is
# injected directly, so they are deterministic and run without a database.
# ---------------------------------------------------------------------------


class _FailingEpochRepository(InMemoryStateRepository):
    """A repository whose durable fleet stop always fails."""

    def next_fleet_epoch(self, *, policy_version: str) -> int:
        raise RuntimeError("the database is unreachable")


class _StopBetweenReadAndWriteRepository(InMemoryStateRepository):
    """Lets exactly one extra fleet stop land after a caller reads state.

    Simulates another replica stopping the fleet in the window between this
    replica's refresh and its write, without needing two processes.
    """

    def __init__(self) -> None:
        super().__init__()
        self.arm_after_next_load = False

    def load(self, *, default_policy_version: str):  # noqa: ANN201
        state = super().load(default_policy_version=default_policy_version)
        if self.arm_after_next_load:
            self.arm_after_next_load = False
            super().next_fleet_epoch(policy_version=default_policy_version)
        return state


class _ReleaseFailingLedger(InMemoryBudgetLedger):
    """A ledger whose release always fails for an unrecoverable reason."""

    def release(self, reservation_id, *, now, reason="released"):  # noqa: ANN001,ANN201
        raise RuntimeError("the ledger is unreachable")


class FleetStopDurabilityTest(unittest.TestCase):
    """A stop must be durable before it is recorded, and never undone by a save."""

    @staticmethod
    def _fleet_events(engine: PolicyEngine, event_type: str) -> list:
        return [
            event
            for event in engine.audit_ledger.events
            if event.event_type == event_type
        ]

    def test_failed_durable_stop_records_nothing(self) -> None:
        """The ledger entry must not outlive a stop that never landed."""

        engine = PolicyEngine(
            state_repository=_FailingEpochRepository(),
            budget_ledger=InMemoryBudgetLedger(),
        )

        with self.assertRaises(RuntimeError):
            engine.stop_fleet(reason="incident")

        self.assertEqual([], self._fleet_events(engine, "fleet.stopped"))
        self.assertFalse(
            engine.fleet_stopped,
            "A stop that failed to persist must not appear to have happened.",
        )

    def test_stop_survives_a_failing_release_sweep(self) -> None:
        """Cleanup after the durable stop is best effort; the stop still stands."""

        repository = InMemoryStateRepository()
        engine = PolicyEngine(
            state_repository=repository, budget_ledger=InMemoryBudgetLedger()
        )
        engine.register_agent(
            AgentProfile(
                agent_id="sweep-agent",
                name="Sweep",
                allowed_actions=frozenset({"pay"}),
                max_action_amount=Decimal("100"),
                daily_budget=Decimal("1000"),
            )
        )
        engine.budget_ledger.reserve(
            "res-sweep",
            request_id="req-sweep",
            agent_id="sweep-agent",
            amount=Decimal("10"),
            currency="INR",
            budget_date=NOW.date(),
            expires_at=NOW + timedelta(minutes=5),
        )
        # Swap in a ledger that cannot release, keeping the outstanding hold.
        failing = _ReleaseFailingLedger()
        failing._agents = engine.budget_ledger._agents
        failing._days = engine.budget_ledger._days
        failing._reservations = engine.budget_ledger._reservations
        engine.budget_ledger = failing

        with self.assertRaises(RuntimeError):
            engine.stop_fleet(reason="incident")

        # The durable stop happened before the sweep, so it stands.
        self.assertTrue(engine.fleet_stopped)
        self.assertEqual(1, len(self._fleet_events(engine, "fleet.stopped")))

    def test_a_stale_save_cannot_undo_a_stop(self) -> None:
        """A replica writing a snapshot taken before a stop must not clear it.

        Every mutating method refreshes before it writes, so the window is
        between that refresh and the save. The repository injects a stop into
        exactly that window, which is what a second replica would do.
        """

        repository = _StopBetweenReadAndWriteRepository()
        engine = PolicyEngine(
            state_repository=repository, budget_ledger=InMemoryBudgetLedger()
        )
        self.assertFalse(engine.fleet_stopped)

        # register_agent reloads, then another replica stops the fleet, then
        # register_agent saves a snapshot that still says the fleet is running.
        repository.arm_after_next_load = True
        engine.register_agent(
            AgentProfile(
                agent_id="stale-agent",
                name="Stale",
                allowed_actions=frozenset({"pay"}),
                max_action_amount=Decimal("100"),
                daily_budget=Decimal("1000"),
            )
        )

        fresh = PolicyEngine(
            state_repository=repository, budget_ledger=InMemoryBudgetLedger()
        )
        self.assertTrue(
            fresh.fleet_stopped,
            "A snapshot save cleared a fleet stop it never knew about.",
        )
        self.assertEqual(1, fresh.fleet_epoch)


class FleetResumeCompareAndSetTest(unittest.TestCase):
    """Resume is a compare-and-set on the epoch, so a newer stop wins."""

    def test_resume_is_refused_when_a_newer_stop_landed(self) -> None:
        repository = _StopBetweenReadAndWriteRepository()
        engine = PolicyEngine(
            state_repository=repository, budget_ledger=InMemoryBudgetLedger()
        )
        engine.stop_fleet(reason="first incident")

        # The next refresh inside resume_fleet sees the epoch it is about to
        # act on, and another stop lands immediately afterwards.
        repository.arm_after_next_load = True

        with self.assertRaises(ValueError) as caught:
            engine.resume_fleet()
        self.assertIn("stopped again", str(caught.exception))

        fresh = PolicyEngine(
            state_repository=repository, budget_ledger=InMemoryBudgetLedger()
        )
        self.assertTrue(
            fresh.fleet_stopped, "The newer stop should have survived the resume."
        )

    def test_resume_succeeds_when_nothing_moved(self) -> None:
        repository = InMemoryStateRepository()
        engine = PolicyEngine(
            state_repository=repository, budget_ledger=InMemoryBudgetLedger()
        )
        engine.stop_fleet(reason="incident")
        self.assertTrue(engine.fleet_stopped)

        engine.resume_fleet()

        self.assertFalse(engine.fleet_stopped)
        fresh = PolicyEngine(
            state_repository=repository, budget_ledger=InMemoryBudgetLedger()
        )
        self.assertFalse(fresh.fleet_stopped)

    def test_resume_does_not_lower_the_epoch(self) -> None:
        repository = InMemoryStateRepository()
        engine = PolicyEngine(
            state_repository=repository, budget_ledger=InMemoryBudgetLedger()
        )
        engine.stop_fleet(reason="one")
        engine.resume_fleet()
        engine.stop_fleet(reason="two")

        self.assertEqual(2, engine.fleet_epoch)


@unittest.skipUnless(
    postgres_available(), "PostgreSQL governance migration is unavailable"
)
class PostgresFleetCompareAndSetTest(unittest.TestCase):
    """The same compare-and-set, asserted against the real SQL."""

    def setUp(self) -> None:
        self.repository = PostgresStateRepository(DATABASE_URL)
        self.addCleanup(self.repository.close)

    def test_resume_matches_only_the_expected_epoch(self) -> None:
        epoch = self.repository.next_fleet_epoch(policy_version="2026.07")
        self.addCleanup(self.repository.resume_fleet, expected_epoch=epoch + 1)

        self.assertFalse(
            self.repository.resume_fleet(expected_epoch=epoch - 1),
            "A resume citing a superseded epoch must not match.",
        )
        # A newer stop moves the epoch, so the original resume no longer applies.
        newer = self.repository.next_fleet_epoch(policy_version="2026.07")
        self.assertEqual(epoch + 1, newer)
        self.assertFalse(self.repository.resume_fleet(expected_epoch=epoch))
        self.assertTrue(self.repository.resume_fleet(expected_epoch=newer))


class EncodingRegistryTest(unittest.TestCase):
    """The codec must be able to read back everything it is able to write."""

    def test_every_encodable_dataclass_can_be_decoded(self) -> None:
        """A dataclass reachable from stored state but missing from the type
        registry encodes happily and raises KeyError on the way back, so the
        failure surfaces on a later read rather than on the write that caused
        it. This asserts the registry covers the whole reachable graph."""

        from dataclasses import fields, is_dataclass

        from intentguard import models
        from intentguard.persistence import _DATACLASSES

        def unwrap(annotation: object) -> list[type]:
            args = typing.get_args(annotation)
            if not args:
                return [annotation] if isinstance(annotation, type) else []
            found: list[type] = []
            for arg in args:
                if arg is type(None) or arg is Ellipsis:
                    continue
                found.extend(unwrap(arg))
            return found

        def reachable(cls: type, seen: frozenset[type]) -> frozenset[type]:
            if cls in seen or not is_dataclass(cls):
                return seen
            seen = seen | {cls}
            hints = typing.get_type_hints(cls)
            for field in fields(cls):
                for candidate in unwrap(hints[field.name]):
                    seen = reachable(candidate, seen)
            return seen

        roots = (
            models.AuthorizationResult,
            models.HumanApproval,
            models.ActionRequest,
            models.AgentProfile,
            models.IntentPassport,
        )
        required: frozenset[type] = frozenset()
        for root in roots:
            required |= reachable(root, frozenset())

        missing = sorted(
            cls.__name__ for cls in required if cls.__name__ not in _DATACLASSES
        )
        self.assertEqual(
            [],
            missing,
            "Reachable from stored state but absent from persistence "
            f"_DATACLASSES, so decoding raises KeyError: {missing}",
        )

    def test_a_finding_context_survives_the_round_trip(self) -> None:
        from intentguard.persistence import _decode, _encode

        finding = PolicyFinding(
            code="AGENT_ACTION_LIMIT",
            message="The action exceeds the agent's per-action limit.",
            blocking=True,
            context=FindingContext(limit=Decimal("500"), actual=Decimal("4200")),
        )
        restored = _decode(_encode(finding))
        self.assertEqual(finding, restored)
        assert restored.context is not None
        self.assertEqual(Decimal("500"), restored.context.limit)

    def test_a_permitted_set_survives_the_round_trip(self) -> None:
        from intentguard.persistence import _decode, _encode

        finding = PolicyFinding(
            code="ACTION_NOT_PERMITTED",
            message="The agent is not permitted to perform this action.",
            blocking=True,
            context=FindingContext(
                permitted=frozenset({"refund_order", "apply_discount"})
            ),
        )
        self.assertEqual(finding, _decode(_encode(finding)))


class _TearInjectingConnection:
    """Proxies a psycopg connection and fires a hook mid-``load()``.

    The hook runs immediately after the ``authorization_records`` SELECT and
    before the ``approval_requests`` SELECT -- exactly the window in which a
    concurrent ``claim_approval_transition`` commits both rows. It makes the
    torn read deterministic instead of something to race for.
    """

    NEEDLE = "FROM authorization_records"

    def __init__(self, inner, hook) -> None:
        self._inner = inner
        self._hook = hook
        self._fired = False

    def execute(self, query, *args, **kwargs):
        cursor = self._inner.execute(query, *args, **kwargs)
        if not self._fired and self.NEEDLE in str(query):
            self._fired = True
            # Materialise before the writer commits: under the old code the
            # rows are already this statement's own snapshot.
            rows = cursor.fetchall()
            self._hook()
            return iter(rows)
        return cursor

    def __getattr__(self, name):
        return getattr(self._inner, name)


class _HookedPool:
    """Hands ``load()`` a proxied connection, once."""

    def __init__(self, inner, hook) -> None:
        self._inner = inner
        self._hook = hook

    def connection(self):
        from contextlib import contextmanager

        @contextmanager
        def wrapped():
            with self._inner.connection() as connection:
                yield _TearInjectingConnection(connection, self._hook)

        return wrapped()

    def __getattr__(self, name):
        return getattr(self._inner, name)


@unittest.skipUnless(
    postgres_available(), "PostgreSQL governance migration is unavailable"
)
class LoadSnapshotConsistencyTest(unittest.TestCase):
    """``load()`` must return one instant, not eight."""

    def setUp(self) -> None:
        from intentguard.budget import PostgresBudgetLedger

        suffix = uuid.uuid4().hex
        self.agent_id = f"tear-agent-{suffix}"
        self.intent_id = f"tear-intent-{suffix}"
        self.request_id = f"tear-request-{suffix}"

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
                name="Tear Agent",
                allowed_actions=frozenset({"pay"}),
                max_action_amount=Decimal("1000"),
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

    def _resolve_from_another_replica(self) -> None:
        """A second replica approves, committing both rows in one transaction."""

        from intentguard.budget import PostgresBudgetLedger

        other_repo = PostgresStateRepository(DATABASE_URL)
        other_budget = PostgresBudgetLedger(DATABASE_URL)
        try:
            other = PolicyEngine(
                state_repository=other_repo, budget_ledger=other_budget
            )
            other.approve_action(
                self.request_id,
                reviewer="other-replica",
                reason="approved mid-load",
                now=NOW + timedelta(minutes=1),
            )
        finally:
            other_repo.close()
            other_budget.close()

    def test_load_cannot_mix_a_resolved_approval_with_its_stale_record(self) -> None:
        """The snapshot must not show APPROVED beside its pre-approval record.

        Fires a real approval from another replica in the window between
        ``load()`` reading authorization_records and reading approval_requests.
        Under READ COMMITTED (or plain autocommit) the two disagree, and
        ``approve_action``'s early return would then hand a caller the
        superseded REVIEW result.
        """

        original_pool = self.repository._pool
        self.repository._pool = _HookedPool(
            original_pool, self._resolve_from_another_replica
        )
        try:
            state = self.repository.load(default_policy_version="2026.07")
        finally:
            self.repository._pool = original_pool

        approval = state.approvals.get(self.request_id)
        record = state.authorizations.get(self.request_id)
        self.assertIsNotNone(approval, "The seeded approval must be in the snapshot.")
        self.assertIsNotNone(record, "The seeded record must be in the snapshot.")
        assert approval is not None and record is not None

        if approval.status is ApprovalStatus.APPROVED:
            self.assertEqual(
                Decision.ALLOW,
                record[1].decision.decision,
                "Torn snapshot: the approval is APPROVED but its authorization "
                "record is still the pre-resolution REVIEW. approve_action's "
                "early return would hand this stale result to a caller.",
            )
        else:
            self.assertEqual(
                Decision.REVIEW,
                record[1].decision.decision,
                "Torn snapshot: the approval is still PENDING but its "
                "authorization record has already advanced.",
            )


def _approve_round_worker(  # noqa: ANN001
    barrier, results, database_url: str, request_id: str, reviewer: str
) -> None:
    """One replica in a single round of the torn-read reproducer."""

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
            reason="torn read reproducer",
            now=NOW + timedelta(minutes=1),
        )
        results.append(
            (
                result.decision.decision.value,
                result.lease.lease_id if result.lease is not None else None,
            )
        )
    except Exception as exc:  # noqa: BLE001
        results.append(("error", f"{type(exc).__name__}: {exc}"[:120]))
    finally:
        engine.close()


@unittest.skipUnless(
    postgres_available(), "PostgreSQL governance migration is unavailable"
)
@unittest.skipUnless(
    os.getenv("INTENTGUARD_RUN_SLOW_REPRODUCERS") == "1",
    "Set INTENTGUARD_RUN_SLOW_REPRODUCERS=1 to run the 50-round reproducer",
)
class TornReadReproducerTest(unittest.TestCase):
    """The many-round reproducer that exposed the torn read.

    Roughly one round in twenty-five failed before the isolation fix, so a
    single round proves nothing. Kept out of the default suite for runtime and
    run deliberately; ``LoadSnapshotConsistencyTest`` is the deterministic
    guard that runs every time.
    """

    WORKERS = 8
    ROUNDS = int(os.getenv("INTENTGUARD_REPRODUCER_ROUNDS", "50"))

    def _seed_review(self) -> str:
        from intentguard.budget import PostgresBudgetLedger

        suffix = uuid.uuid4().hex
        repository = PostgresStateRepository(DATABASE_URL)
        budget = PostgresBudgetLedger(DATABASE_URL)
        self.addCleanup(repository.close)
        self.addCleanup(budget.close)
        engine = PolicyEngine(state_repository=repository, budget_ledger=budget)
        agent_id = f"repro-agent-{suffix}"
        intent_id = f"repro-intent-{suffix}"
        request_id = f"repro-request-{suffix}"
        engine.register_agent(
            AgentProfile(
                agent_id=agent_id,
                name="Reproducer Agent",
                allowed_actions=frozenset({"pay"}),
                max_action_amount=Decimal("1000"),
                daily_budget=Decimal("1000000"),
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
        outcome = engine.authorize_action(
            ActionRequest(
                request_id=request_id,
                agent_id=agent_id,
                action="pay",
                amount=Decimal("100"),
                currency="INR",
                intent_id=intent_id,
                risk_score=100,
                customer_id="customer-1",
                submitted_by="agent-user",
                occurred_at=NOW,
            ),
            now=NOW,
        )
        self.assertEqual(Decision.REVIEW, outcome.decision.decision)
        return request_id

    def test_no_round_hands_back_a_lease_less_result(self) -> None:
        context = mp.get_context("spawn")
        failures: list[str] = []
        for round_number in range(1, self.ROUNDS + 1):
            request_id = self._seed_review()
            with context.Manager() as manager:
                results = manager.list()
                barrier = manager.Barrier(self.WORKERS)
                processes = [
                    context.Process(
                        target=_approve_round_worker,
                        args=(
                            barrier,
                            results,
                            DATABASE_URL,
                            request_id,
                            f"reviewer-{index}",
                        ),
                    )
                    for index in range(self.WORKERS)
                ]
                for process in processes:
                    process.start()
                for process in processes:
                    process.join(timeout=120)
                outcomes = list(results)
            # A worker that raised reports ("error", message); its second
            # element is a string, not None, so checking only for a missing
            # lease would let a crashed replica pass as a clean round.
            if len(outcomes) != self.WORKERS or any(
                outcome[0] == "error" or outcome[1] is None for outcome in outcomes
            ):
                failures.append(f"round {round_number}: {sorted(set(outcomes))}")
        self.assertEqual(
            [],
            failures,
            f"{len(failures)}/{self.ROUNDS} rounds were not clean "
            f"(a lease-less result, a crashed replica, or a missing one):\n"
            + "\n".join(failures[:5]),
        )
