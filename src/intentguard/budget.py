"""Budget ledgers: where a daily cap is actually enforced.

The engine originally held spend counters in dictionaries guarded by an
in-process ``RLock``. That is correct in one process and wrong in two: each
replica keeps its own counters, so N replicas permit N times the cap. This
module moves the invariant somewhere every replica shares.

The invariant, stated once:

    committed + reserved + amount <= daily_budget

A *reservation* holds funds while an action is in flight, so a hold is exactly
as binding as a payment. Reserve, then commit on success or release on failure.
Nothing is ever spent that was not first held.

Two implementations satisfy the same protocol. :class:`InMemoryBudgetLedger`
preserves the original single-process behaviour for tests and local runs.
:class:`PostgresBudgetLedger` enforces the invariant in a single atomic
statement, so concurrent replicas serialise on the row rather than on a lock
they do not share.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from threading import RLock
from typing import Any, Protocol


class BudgetExceeded(Exception):
    """A reservation would have breached the agent's daily cap."""

    def __init__(self, agent_id: str, requested: Decimal, remaining: Decimal) -> None:
        super().__init__(
            f"Agent {agent_id} requested {requested} with {remaining} remaining "
            "against its daily budget."
        )
        self.agent_id = agent_id
        self.requested = requested
        self.remaining = remaining


class UnknownAgent(KeyError):
    """No such agent in the ledger."""


@dataclass(frozen=True)
class Exposure:
    """What an agent has spent and is holding on a given day."""

    agent_id: str
    budget_date: date
    daily_budget: Decimal
    committed: Decimal
    reserved: Decimal

    @property
    def remaining(self) -> Decimal:
        return max(self.daily_budget - self.committed - self.reserved, Decimal("0"))

    @property
    def breached(self) -> bool:
        """True if the ledger is in a state the invariant forbids."""

        return self.committed + self.reserved > self.daily_budget


class BudgetLedger(Protocol):
    """The operations a budget ledger must support atomically."""

    def register_agent(
        self,
        agent_id: str,
        *,
        name: str,
        daily_budget: Decimal,
        max_action_amount: Decimal,
        active: bool = True,
    ) -> None: ...

    def reserve(
        self,
        reservation_id: str,
        *,
        request_id: str,
        agent_id: str,
        amount: Decimal,
        currency: str,
        budget_date: date,
        expires_at: datetime,
    ) -> Exposure:
        """Hold ``amount`` against the cap, or raise :class:`BudgetExceeded`."""
        ...

    def commit(self, reservation_id: str, *, now: datetime) -> Exposure: ...

    def release(self, reservation_id: str, *, now: datetime, reason: str) -> Exposure: ...

    def expire_due(self, *, now: datetime) -> int:
        """Release every hold past its expiry. Returns how many were reclaimed."""
        ...

    def exposure(self, agent_id: str, budget_date: date) -> Exposure: ...


# --------------------------------------------------------------------------
# In-memory
# --------------------------------------------------------------------------


class InMemoryBudgetLedger:
    """Single-process ledger. Correct within one process, and only one.

    Kept so tests and local runs need no database, and so the Postgres
    implementation can be differentially tested against a known-good reference.
    Do not deploy more than one replica against this.
    """

    def __init__(self) -> None:
        self._agents: dict[str, dict[str, Any]] = {}
        self._days: dict[tuple[str, date], list[Decimal]] = {}
        self._reservations: dict[str, dict[str, Any]] = {}
        self._lock = RLock()

    def register_agent(
        self,
        agent_id: str,
        *,
        name: str,
        daily_budget: Decimal,
        max_action_amount: Decimal,
        active: bool = True,
    ) -> None:
        with self._lock:
            self._agents[agent_id] = {
                "name": name,
                "daily_budget": daily_budget,
                "max_action_amount": max_action_amount,
                "active": active,
            }

    def _day(self, agent_id: str, budget_date: date) -> list[Decimal]:
        return self._days.setdefault(
            (agent_id, budget_date), [Decimal("0"), Decimal("0")]
        )

    def reserve(
        self,
        reservation_id: str,
        *,
        request_id: str,
        agent_id: str,
        amount: Decimal,
        currency: str,
        budget_date: date,
        expires_at: datetime,
    ) -> Exposure:
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                raise UnknownAgent(agent_id)
            committed, reserved = self._day(agent_id, budget_date)
            budget = agent["daily_budget"]
            if committed + reserved + amount > budget:
                raise BudgetExceeded(
                    agent_id, amount, max(budget - committed - reserved, Decimal("0"))
                )
            self._days[(agent_id, budget_date)] = [committed, reserved + amount]
            self._reservations[reservation_id] = {
                "request_id": request_id,
                "agent_id": agent_id,
                "amount": amount,
                "currency": currency,
                "budget_date": budget_date,
                "status": "held",
                "expires_at": expires_at,
            }
            return self.exposure(agent_id, budget_date)

    def _resolve(
        self, reservation_id: str, *, status: str, now: datetime
    ) -> Exposure:
        with self._lock:
            record = self._reservations.get(reservation_id)
            if record is None:
                raise KeyError(f"Unknown reservation: {reservation_id}")
            if record["status"] != "held":
                raise ValueError(
                    f"Reservation is {record['status']}, not held."
                )
            agent_id: str = record["agent_id"]
            budget_date: date = record["budget_date"]
            amount: Decimal = record["amount"]
            committed, reserved = self._day(agent_id, budget_date)
            reserved -= amount
            if status == "committed":
                committed += amount
            self._days[(agent_id, budget_date)] = [committed, reserved]
            record["status"] = status
            record["resolved_at"] = now
            return self.exposure(agent_id, budget_date)

    def commit(self, reservation_id: str, *, now: datetime) -> Exposure:
        return self._resolve(reservation_id, status="committed", now=now)

    def release(
        self, reservation_id: str, *, now: datetime, reason: str = "released"
    ) -> Exposure:
        return self._resolve(reservation_id, status="released", now=now)

    def expire_due(self, *, now: datetime) -> int:
        with self._lock:
            due = [
                reservation_id
                for reservation_id, record in self._reservations.items()
                if record["status"] == "held" and now >= record["expires_at"]
            ]
            for reservation_id in due:
                self._resolve(reservation_id, status="expired", now=now)
            return len(due)

    def exposure(self, agent_id: str, budget_date: date) -> Exposure:
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                raise UnknownAgent(agent_id)
            committed, reserved = self._day(agent_id, budget_date)
            return Exposure(
                agent_id=agent_id,
                budget_date=budget_date,
                daily_budget=agent["daily_budget"],
                committed=committed,
                reserved=reserved,
            )


# --------------------------------------------------------------------------
# Postgres
# --------------------------------------------------------------------------

# The whole point of this module. The WHERE clause carries the invariant, so
# the check and the write are one statement and cannot be interleaved: a
# concurrent reserver either sees our reserved value or we see theirs, and the
# loser matches zero rows. No advisory locks, no SELECT ... FOR UPDATE, no
# read-modify-write window for two replicas to race through.
# The day row must exist before the UPDATE can lock it. This cannot be folded
# into the UPDATE as a data-modifying CTE: CTEs and the main statement share
# one snapshot, so the UPDATE would not see the row the CTE just inserted.
_ENSURE_DAY_SQL = """
INSERT INTO budget_days (agent_id, budget_date)
VALUES (%(agent_id)s, %(budget_date)s)
ON CONFLICT (agent_id, budget_date) DO NOTHING
"""

# Under READ COMMITTED, a writer that blocks on a concurrently-updated row
# re-evaluates this WHERE clause against the committed row version once the
# lock is released. So the loser of a race re-reads the winner's `reserved`,
# fails the comparison, and matches zero rows -- which is exactly the refusal
# we want, with no read-modify-write window in between.
_RESERVE_SQL = """
UPDATE budget_days AS b
   SET reserved = b.reserved + %(amount)s
  FROM agents AS a
 WHERE b.agent_id = a.agent_id
   AND b.agent_id = %(agent_id)s
   AND b.budget_date = %(budget_date)s
   AND b.committed + b.reserved + %(amount)s <= a.daily_budget
RETURNING b.committed, b.reserved, a.daily_budget
"""

_RESOLVE_SQL = """
WITH claimed AS (
    UPDATE reservations
       SET status = %(status)s, resolved_at = %(now)s
     WHERE reservation_id = %(reservation_id)s AND status = 'held'
    RETURNING agent_id, budget_date, amount
)
UPDATE budget_days AS b
   SET reserved  = b.reserved - claimed.amount,
       committed = b.committed + CASE WHEN %(status)s = 'committed'
                                      THEN claimed.amount ELSE 0 END
  FROM claimed
 WHERE b.agent_id = claimed.agent_id AND b.budget_date = claimed.budget_date
RETURNING b.committed, b.reserved
"""


class PostgresBudgetLedger:
    """Budget ledger whose invariant is enforced by the database.

    Safe across processes and replicas: every mutation is a single statement
    whose WHERE clause encodes the cap, so Postgres row locking does the
    serialising. Requires the ``postgres`` extra.
    """

    def __init__(self, conninfo: str, *, autocommit: bool = True) -> None:
        import psycopg
        from psycopg_pool import ConnectionPool

        self._psycopg = psycopg
        self._pool = ConnectionPool(
            conninfo,
            min_size=1,
            max_size=8,
            open=True,
            kwargs={"autocommit": autocommit},
        )
        self._pool.wait(timeout=10)

    def close(self) -> None:
        self._pool.close()

    def register_agent(
        self,
        agent_id: str,
        *,
        name: str,
        daily_budget: Decimal,
        max_action_amount: Decimal,
        active: bool = True,
    ) -> None:
        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO agents
                    (agent_id, name, daily_budget, max_action_amount, active)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (agent_id) DO UPDATE
                    SET name = EXCLUDED.name,
                        daily_budget = EXCLUDED.daily_budget,
                        max_action_amount = EXCLUDED.max_action_amount,
                        active = EXCLUDED.active
                """,
                (agent_id, name, daily_budget, max_action_amount, active),
            )

    def reserve(
        self,
        reservation_id: str,
        *,
        request_id: str,
        agent_id: str,
        amount: Decimal,
        currency: str,
        budget_date: date,
        expires_at: datetime,
    ) -> Exposure:
        if amount <= 0:
            raise ValueError("A reservation amount must be positive.")

        with self._pool.connection() as connection:
            with connection.transaction():
                row = connection.execute(
                    "SELECT daily_budget FROM agents WHERE agent_id = %s",
                    (agent_id,),
                ).fetchone()
                if row is None:
                    raise UnknownAgent(agent_id)

                connection.execute(
                    _ENSURE_DAY_SQL,
                    {"agent_id": agent_id, "budget_date": budget_date},
                )
                updated = connection.execute(
                    _RESERVE_SQL,
                    {
                        "agent_id": agent_id,
                        "budget_date": budget_date,
                        "amount": amount,
                    },
                ).fetchone()

                if updated is None:
                    # The cap would have been breached. Report the headroom as
                    # it stands now rather than as it was when we looked.
                    current = self.exposure(agent_id, budget_date)
                    raise BudgetExceeded(agent_id, amount, current.remaining)

                committed, reserved, daily_budget = updated
                connection.execute(
                    """
                    INSERT INTO reservations
                        (reservation_id, request_id, agent_id, amount, currency,
                         budget_date, status, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, 'held', %s)
                    """,
                    (
                        reservation_id,
                        request_id,
                        agent_id,
                        amount,
                        currency,
                        budget_date,
                        expires_at,
                    ),
                )

        return Exposure(
            agent_id=agent_id,
            budget_date=budget_date,
            daily_budget=daily_budget,
            committed=committed,
            reserved=reserved,
        )

    def _resolve(self, reservation_id: str, *, status: str, now: datetime) -> Exposure:
        with self._pool.connection() as connection:
            with connection.transaction():
                reservation = connection.execute(
                    "SELECT agent_id, budget_date, status FROM reservations "
                    "WHERE reservation_id = %s",
                    (reservation_id,),
                ).fetchone()
                if reservation is None:
                    raise KeyError(f"Unknown reservation: {reservation_id}")
                agent_id, budget_date, current_status = reservation
                if current_status != "held":
                    raise ValueError(f"Reservation is {current_status}, not held.")

                connection.execute(
                    _RESOLVE_SQL,
                    {
                        "reservation_id": reservation_id,
                        "status": status,
                        "now": now,
                    },
                ).fetchone()

        return self.exposure(agent_id, budget_date)

    def commit(self, reservation_id: str, *, now: datetime) -> Exposure:
        return self._resolve(reservation_id, status="committed", now=now)

    def release(
        self, reservation_id: str, *, now: datetime, reason: str = "released"
    ) -> Exposure:
        return self._resolve(reservation_id, status="released", now=now)

    def expire_due(self, *, now: datetime) -> int:
        """Reclaim holds past their expiry.

        Safe to run concurrently on every replica: the UPDATE claims rows by
        flipping their status, so a reservation can only be reclaimed once.
        """

        with self._pool.connection() as connection:
            with connection.transaction():
                claimed = connection.execute(
                    """
                    UPDATE reservations
                       SET status = 'expired', resolved_at = %(now)s
                     WHERE reservation_id IN (
                         SELECT reservation_id FROM reservations
                          WHERE status = 'held' AND expires_at <= %(now)s
                          FOR UPDATE SKIP LOCKED
                     )
                    RETURNING agent_id, budget_date, amount
                    """,
                    {"now": now},
                ).fetchall()

                for agent_id, budget_date, amount in claimed:
                    connection.execute(
                        "UPDATE budget_days SET reserved = reserved - %s "
                        "WHERE agent_id = %s AND budget_date = %s",
                        (amount, agent_id, budget_date),
                    )
        return len(claimed)

    def exposure(self, agent_id: str, budget_date: date) -> Exposure:
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                SELECT a.daily_budget,
                       COALESCE(b.committed, 0),
                       COALESCE(b.reserved, 0)
                  FROM agents a
                  LEFT JOIN budget_days b
                    ON b.agent_id = a.agent_id AND b.budget_date = %s
                 WHERE a.agent_id = %s
                """,
                (budget_date, agent_id),
            ).fetchone()
        if row is None:
            raise UnknownAgent(agent_id)
        daily_budget, committed, reserved = row
        return Exposure(
            agent_id=agent_id,
            budget_date=budget_date,
            daily_budget=daily_budget,
            committed=committed,
            reserved=reserved,
        )
