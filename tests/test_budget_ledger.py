"""Budget ledger tests, including the one the old design could not pass.

The engine's daily cap used to be guarded by an in-process ``RLock``. Within a
single process that is correct, and the existing suite proved it with 20
threads over 50 iterations. Across two processes it is not correct at all, and
no thread-based test can show that.

So there are two tests here that matter more than the rest:

* :meth:`OverspendDemonstrationTest.test_independent_ledgers_overspend` runs the
  race across real OS processes with a per-process in-memory ledger -- the
  shape of two replicas -- and asserts that the cap *is* breached. It exists to
  document the bug rather than to defend against it.
* :meth:`PostgresConcurrencyTest.test_concurrent_processes_never_exceed_cap`
  runs the identical race against Postgres and asserts that it is not.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import sys
import unittest
import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from intentguard.budget import (  # noqa: E402
    BudgetExceeded,
    InMemoryBudgetLedger,
    UnknownAgent,
)

DATABASE_URL = os.getenv("INTENTGUARD_DATABASE_URL", "postgresql:///intentguard")
AGENT = "ledger-agent"
DAY = date(2026, 8, 25)
NOW = datetime(2026, 8, 25, 10, tzinfo=timezone.utc)


def postgres_available() -> bool:
    try:
        import psycopg
    except ImportError:
        return False
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=3) as connection:
            connection.execute("SELECT 1 FROM budget_days LIMIT 1")
        return True
    except Exception:
        return False


HAS_POSTGRES = postgres_available()


def make_memory_ledger(budget: str = "10000") -> InMemoryBudgetLedger:
    ledger = InMemoryBudgetLedger()
    ledger.register_agent(
        AGENT,
        name="Ledger Agent",
        daily_budget=Decimal(budget),
        max_action_amount=Decimal("50000"),
    )
    return ledger


# --------------------------------------------------------------------------
# Behaviour both implementations must share
# --------------------------------------------------------------------------


class LedgerContractMixin:
    """Applied to every implementation, so they cannot drift apart."""

    def make_ledger(self, budget: str = "10000"):  # noqa: ANN201
        raise NotImplementedError

    def _reserve(self, ledger, amount: str, *, expires_in: int = 300):  # noqa: ANN001
        reservation_id = f"res_{uuid.uuid4().hex}"
        ledger.reserve(
            reservation_id,
            request_id=f"req_{reservation_id}",
            agent_id=AGENT,
            amount=Decimal(amount),
            currency="INR",
            budget_date=DAY,
            expires_at=NOW + timedelta(seconds=expires_in),
        )
        return reservation_id

    def test_a_hold_reduces_the_headroom(self) -> None:
        ledger = self.make_ledger()
        self._reserve(ledger, "6000")

        exposure = ledger.exposure(AGENT, DAY)
        self.assertEqual(Decimal("6000"), exposure.reserved)
        self.assertEqual(Decimal("0"), exposure.committed)
        self.assertEqual(Decimal("4000"), exposure.remaining)

    def test_a_hold_binds_against_a_later_request(self) -> None:
        """A reservation is as binding as spend -- that's the whole point."""

        ledger = self.make_ledger()
        self._reserve(ledger, "6000")

        with self.assertRaises(BudgetExceeded):
            self._reserve(ledger, "5000")

    def test_the_exact_remaining_amount_is_allowed(self) -> None:
        ledger = self.make_ledger()
        self._reserve(ledger, "6000")
        self._reserve(ledger, "4000")

        self.assertEqual(Decimal("0"), ledger.exposure(AGENT, DAY).remaining)

    def test_commit_moves_a_hold_into_spend(self) -> None:
        ledger = self.make_ledger()
        reservation_id = self._reserve(ledger, "6000")

        exposure = ledger.commit(reservation_id, now=NOW)

        self.assertEqual(Decimal("6000"), exposure.committed)
        self.assertEqual(Decimal("0"), exposure.reserved)
        self.assertEqual(Decimal("4000"), exposure.remaining)

    def test_release_returns_the_headroom(self) -> None:
        ledger = self.make_ledger()
        reservation_id = self._reserve(ledger, "6000")

        exposure = ledger.release(reservation_id, now=NOW, reason="cancelled")

        self.assertEqual(Decimal("0"), exposure.committed)
        self.assertEqual(Decimal("10000"), exposure.remaining)

    def test_a_reservation_resolves_only_once(self) -> None:
        """Guards against double-commit inflating spend."""

        ledger = self.make_ledger()
        reservation_id = self._reserve(ledger, "6000")
        ledger.commit(reservation_id, now=NOW)

        with self.assertRaises(ValueError):
            ledger.commit(reservation_id, now=NOW)
        with self.assertRaises(ValueError):
            ledger.release(reservation_id, now=NOW, reason="late")

        self.assertEqual(Decimal("6000"), ledger.exposure(AGENT, DAY).committed)

    def test_expiry_reclaims_abandoned_holds(self) -> None:
        ledger = self.make_ledger()
        self._reserve(ledger, "6000", expires_in=-1)

        self.assertEqual(1, ledger.expire_due(now=NOW))
        self.assertEqual(Decimal("10000"), ledger.exposure(AGENT, DAY).remaining)
        # Idempotent: a second sweep finds nothing left to reclaim.
        self.assertEqual(0, ledger.expire_due(now=NOW))

    def test_an_unknown_agent_is_rejected(self) -> None:
        ledger = self.make_ledger()

        with self.assertRaises(UnknownAgent):
            ledger.reserve(
                "res_x",
                request_id="req_x",
                agent_id="nobody",
                amount=Decimal("1"),
                currency="INR",
                budget_date=DAY,
                expires_at=NOW + timedelta(seconds=60),
            )

    def test_the_invariant_holds_after_a_mixed_workload(self) -> None:
        ledger = self.make_ledger()
        held = [self._reserve(ledger, "1000") for _ in range(8)]
        for reservation_id in held[:3]:
            ledger.commit(reservation_id, now=NOW)
        for reservation_id in held[3:5]:
            ledger.release(reservation_id, now=NOW, reason="failed")

        exposure = ledger.exposure(AGENT, DAY)
        self.assertEqual(Decimal("3000"), exposure.committed)
        self.assertEqual(Decimal("3000"), exposure.reserved)
        self.assertFalse(exposure.breached)


class InMemoryLedgerTest(LedgerContractMixin, unittest.TestCase):
    def make_ledger(self, budget: str = "10000") -> InMemoryBudgetLedger:
        return make_memory_ledger(budget)


# --------------------------------------------------------------------------
# Cross-process workers. Module level so `spawn` can pickle them.
# --------------------------------------------------------------------------

CAP = "10000"
AMOUNT = "1500"          # 6 fit; 7 would breach
WORKERS = 8


def _memory_worker(barrier, results) -> None:  # noqa: ANN001
    """One replica with its own in-memory ledger. The old architecture."""

    ledger = make_memory_ledger(CAP)
    barrier.wait()
    try:
        ledger.reserve(
            f"res_{uuid.uuid4().hex}",
            request_id=f"req_{os.getpid()}",
            agent_id=AGENT,
            amount=Decimal(AMOUNT),
            currency="INR",
            budget_date=DAY,
            expires_at=NOW + timedelta(seconds=300),
        )
        results.append(Decimal(AMOUNT))
    except BudgetExceeded:
        pass


def _postgres_worker(barrier, results, database_url: str) -> None:  # noqa: ANN001
    """One replica sharing the ledger through Postgres. The new architecture."""

    from intentguard.budget import PostgresBudgetLedger

    ledger = PostgresBudgetLedger(database_url)
    try:
        barrier.wait()
        try:
            ledger.reserve(
                f"res_{uuid.uuid4().hex}",
                request_id=f"req_{os.getpid()}",
                agent_id=AGENT,
                amount=Decimal(AMOUNT),
                currency="INR",
                budget_date=DAY,
                expires_at=NOW + timedelta(seconds=300),
            )
            results.append(Decimal(AMOUNT))
        except BudgetExceeded:
            pass
    finally:
        ledger.close()


class OverspendDemonstrationTest(unittest.TestCase):
    """Documents the bug the Postgres ledger exists to fix."""

    def test_independent_ledgers_overspend(self) -> None:
        context = mp.get_context("spawn")
        with context.Manager() as manager:
            results = manager.list()
            barrier = manager.Barrier(WORKERS)
            processes = [
                context.Process(target=_memory_worker, args=(barrier, results))
                for _ in range(WORKERS)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=30)
            total = sum(results, Decimal("0"))

        # Every replica believes it owns the whole cap, so all of them succeed.
        self.assertEqual(
            Decimal(AMOUNT) * WORKERS,
            total,
            "Expected each in-memory replica to grant the full amount.",
        )
        self.assertGreater(
            total,
            Decimal(CAP),
            "This test exists to show the cap being breached across replicas.",
        )


@unittest.skipUnless(
    HAS_POSTGRES, f"Postgres not reachable at {DATABASE_URL}; run migrations first"
)
class PostgresLedgerTest(LedgerContractMixin, unittest.TestCase):
    def make_ledger(self, budget: str = "10000"):  # noqa: ANN201
        from intentguard.budget import PostgresBudgetLedger

        _truncate()
        ledger = PostgresBudgetLedger(DATABASE_URL)
        ledger.register_agent(
            AGENT,
            name="Ledger Agent",
            daily_budget=Decimal(budget),
            max_action_amount=Decimal("50000"),
        )
        self.addCleanup(ledger.close)
        return ledger


def _truncate() -> None:
    import psycopg

    with psycopg.connect(DATABASE_URL) as connection:
        connection.execute(
            "TRUNCATE reservations, budget_days, agents RESTART IDENTITY CASCADE"
        )
        connection.commit()


@unittest.skipUnless(
    HAS_POSTGRES, f"Postgres not reachable at {DATABASE_URL}; run migrations first"
)
class PostgresConcurrencyTest(unittest.TestCase):
    """The test the in-process lock could never have passed."""

    ITERATIONS = 12

    def setUp(self) -> None:
        from intentguard.budget import PostgresBudgetLedger

        _truncate()
        self.ledger = PostgresBudgetLedger(DATABASE_URL)
        self.ledger.register_agent(
            AGENT,
            name="Ledger Agent",
            daily_budget=Decimal(CAP),
            max_action_amount=Decimal("50000"),
        )
        self.addCleanup(self.ledger.close)

    def _race(self) -> Decimal:
        context = mp.get_context("spawn")
        with context.Manager() as manager:
            results = manager.list()
            barrier = manager.Barrier(WORKERS)
            processes = [
                context.Process(
                    target=_postgres_worker, args=(barrier, results, DATABASE_URL)
                )
                for _ in range(WORKERS)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=60)
            for process in processes:
                self.assertEqual(0, process.exitcode, "A replica crashed.")
            return sum(results, Decimal("0"))

    def test_concurrent_processes_never_exceed_cap(self) -> None:
        granted = self._race()
        exposure = self.ledger.exposure(AGENT, DAY)

        self.assertLessEqual(
            exposure.reserved,
            Decimal(CAP),
            f"Replicas reserved {exposure.reserved} against a cap of {CAP}.",
        )
        self.assertFalse(exposure.breached)
        # Nothing is lost either: what the ledger holds is what was granted.
        self.assertEqual(granted, exposure.reserved)
        # 10000 / 1500 leaves room for exactly six.
        self.assertEqual(Decimal("9000"), exposure.reserved)

    def test_the_race_is_stable_across_repeats(self) -> None:
        """Races are intermittent, so one clean run proves little."""

        for iteration in range(self.ITERATIONS):
            with self.subTest(iteration=iteration):
                _truncate()
                self.ledger.register_agent(
                    AGENT,
                    name="Ledger Agent",
                    daily_budget=Decimal(CAP),
                    max_action_amount=Decimal("50000"),
                )
                self._race()
                exposure = self.ledger.exposure(AGENT, DAY)
                self.assertLessEqual(exposure.reserved, Decimal(CAP))
                self.assertEqual(Decimal("9000"), exposure.reserved)


if __name__ == "__main__":
    unittest.main()
