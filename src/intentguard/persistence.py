"""Durable governance state repositories.

The policy engine stays independent of a particular database.  Production can
use :class:`PostgresStateRepository`; tests and local demos use the same
contract through :class:`InMemoryStateRepository`.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, fields, is_dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from threading import RLock
from typing import Any, Protocol

from .models import (
    ActionRequest,
    AgentProfile,
    ApprovalStatus,
    AuthorizationLease,
    AuthorizationResult,
    ClaimReason,
    EvidenceArtifact,
    EvidenceKind,
    Decision,
    DecisionRecord,
    FindingContext,
    HumanApproval,
    IntentPassport,
    PolicyFinding,
    RefundClaim,
    Remedy,
    RemedyKind,
    ReservationStatus,
    RiskAssessment,
    BudgetReservation,
)


@dataclass
class GovernanceState:
    """A repository-neutral snapshot of all non-budget runtime state."""

    policy_version: str
    policy_revision: int
    agents: dict[str, AgentProfile]
    intents: dict[str, IntentPassport]
    revoked_agents: set[str]
    revocation_epochs: dict[str, int]
    authorization_counts: dict[tuple[str, date], int]
    leases: dict[str, AuthorizationLease]
    authorizations: dict[str, tuple[ActionRequest, AuthorizationResult]]
    approvals: dict[str, HumanApproval]
    fleet_stopped: bool
    fleet_epoch: int


class StateRepository(Protocol):
    """Persistence boundary consumed by :class:`PolicyEngine`."""

    def load(self, *, default_policy_version: str) -> GovernanceState: ...

    def save(self, state: GovernanceState) -> None: ...

    def claim_authorization(
        self,
        request_id: str,
        request: ActionRequest,
        result: AuthorizationResult,
    ) -> bool:
        """Take exclusive ownership of ``request_id``, atomically.

        Returns ``True`` if this caller stored the record and ``False`` if some
        other replica got there first. This is the whole guard behind
        idempotency across replicas: ``load()`` and ``save()`` are a
        read-modify-write, so two replicas can both miss the same request and
        both issue a reservation for it. One indivisible insert is what makes
        one request_id mean one reservation.
        """
        ...

    def get_authorization(
        self, request_id: str
    ) -> tuple[ActionRequest, AuthorizationResult] | None:
        """Read one stored authorization without loading the whole table."""
        ...

    def claim_approval_transition(
        self,
        request_id: str,
        approval: HumanApproval,
        request: ActionRequest,
        result: AuthorizationResult,
    ) -> bool:
        """Move a pending approval to its resolved state, atomically.

        Returns ``True`` if this caller performed the transition and ``False``
        if the approval was no longer pending. The resolved approval and its
        authorization result are written together, so a caller that loses can
        immediately read back a state the winner has already committed --
        resolving the approval first and storing the result afterwards would
        leave a window where the row says ``approved`` while the stored
        authorization is still the superseded review.
        """
        ...

    def get_approval(self, request_id: str) -> HumanApproval | None:
        """Read one approval without loading the whole table."""
        ...

    # -- Counters and epochs ------------------------------------------------
    #
    # Every one of these is a read-modify-write when done in Python, and
    # save() merges the result, so two replicas that each read N and write
    # N+1 leave N+1 where N+2 happened. Each is therefore advanced by a single
    # statement that reads and writes inside the database, and returns the
    # authoritative value for the caller to adopt.

    def increment_authorization_count(self, agent_id: str, day: date) -> int:
        """Add one to an agent's authorization count for a day."""
        ...

    def next_fleet_epoch(self, *, policy_version: str) -> int:
        """Stop the fleet and advance its epoch by exactly one."""
        ...

    def resume_fleet(self, *, expected_epoch: int) -> bool:
        """Clear the fleet stop, but only if no newer stop has landed.

        Returns ``False`` when the epoch has moved since the caller read it,
        which means the fleet was stopped again and this resume is acting on a
        stale view. Stopping is the safe direction, so the newer stop wins.
        """
        ...

    def next_revocation_epoch(self, agent_id: str) -> int:
        """Advance one agent's revocation epoch by exactly one."""
        ...

    def next_policy_revision(self, *, version_prefix: str) -> tuple[int, str]:
        """Advance the policy revision and its derived version string together."""
        ...

    def close(self) -> None: ...


def empty_state(policy_version: str) -> GovernanceState:
    return GovernanceState(
        policy_version=policy_version,
        policy_revision=0,
        agents={},
        intents={},
        revoked_agents=set(),
        revocation_epochs={},
        authorization_counts={},
        leases={},
        authorizations={},
        approvals={},
        fleet_stopped=False,
        fleet_epoch=0,
    )


class InMemoryStateRepository:
    """Thread-safe repository used by unit tests and single-process demos."""

    def __init__(self, state: GovernanceState | None = None) -> None:
        self._state = deepcopy(state)
        self._lock = RLock()

    def load(self, *, default_policy_version: str) -> GovernanceState:
        with self._lock:
            if self._state is None:
                return empty_state(default_policy_version)
            return deepcopy(self._state)

    def save(self, state: GovernanceState) -> None:
        """Store the snapshot without regressing anything advanced atomically.

        Mirrors the merge rules PostgresStateRepository applies. The two
        implementations are differentially tested against one shared contract,
        so a snapshot that can undo an increment here but not there would make
        the in-memory reference wrong rather than merely simpler.
        """

        with self._lock:
            merged = deepcopy(state)
            current = self._state
            if current is not None:
                # Both stop and resume are atomic operations of their own, so
                # a snapshot never carries authority over the flag.
                merged.fleet_stopped = current.fleet_stopped
                merged.fleet_epoch = max(current.fleet_epoch, state.fleet_epoch)
                if current.policy_revision > state.policy_revision:
                    merged.policy_revision = current.policy_revision
                    merged.policy_version = current.policy_version
                for agent_id, epoch in current.revocation_epochs.items():
                    merged.revocation_epochs[agent_id] = max(
                        epoch, merged.revocation_epochs.get(agent_id, 0)
                    )
                for key, count in current.authorization_counts.items():
                    merged.authorization_counts[key] = max(
                        count, merged.authorization_counts.get(key, 0)
                    )
            self._state = merged

    def claim_authorization(
        self,
        request_id: str,
        request: ActionRequest,
        result: AuthorizationResult,
    ) -> bool:
        with self._lock:
            if self._state is None:
                # No save() has happened yet, so nothing can have claimed it.
                # The version is a placeholder; the next save() overwrites it.
                self._state = empty_state("")
            if request_id in self._state.authorizations:
                return False
            self._state.authorizations[request_id] = deepcopy((request, result))
            return True

    def get_authorization(
        self, request_id: str
    ) -> tuple[ActionRequest, AuthorizationResult] | None:
        with self._lock:
            if self._state is None:
                return None
            stored = self._state.authorizations.get(request_id)
            return None if stored is None else deepcopy(stored)

    def claim_approval_transition(
        self,
        request_id: str,
        approval: HumanApproval,
        request: ActionRequest,
        result: AuthorizationResult,
    ) -> bool:
        with self._lock:
            if self._state is None:
                return False
            current = self._state.approvals.get(request_id)
            if current is None or current.status is not ApprovalStatus.PENDING:
                return False
            self._state.approvals[request_id] = deepcopy(approval)
            self._state.authorizations[request_id] = deepcopy((request, result))
            return True

    def get_approval(self, request_id: str) -> HumanApproval | None:
        with self._lock:
            if self._state is None:
                return None
            stored = self._state.approvals.get(request_id)
            return None if stored is None else deepcopy(stored)

    def _mutable_state(self) -> GovernanceState:
        if self._state is None:
            self._state = empty_state("")
        return self._state

    def increment_authorization_count(self, agent_id: str, day: date) -> int:
        with self._lock:
            state = self._mutable_state()
            updated = state.authorization_counts.get((agent_id, day), 0) + 1
            state.authorization_counts[(agent_id, day)] = updated
            return updated

    def next_fleet_epoch(self, *, policy_version: str) -> int:
        with self._lock:
            state = self._mutable_state()
            state.fleet_stopped = True
            state.fleet_epoch += 1
            return state.fleet_epoch

    def resume_fleet(self, *, expected_epoch: int) -> bool:
        with self._lock:
            state = self._mutable_state()
            if state.fleet_epoch != expected_epoch:
                return False
            state.fleet_stopped = False
            return True

    def next_revocation_epoch(self, agent_id: str) -> int:
        with self._lock:
            state = self._mutable_state()
            updated = state.revocation_epochs.get(agent_id, 0) + 1
            state.revocation_epochs[agent_id] = updated
            state.revoked_agents.add(agent_id)
            return updated

    def next_policy_revision(self, *, version_prefix: str) -> tuple[int, str]:
        with self._lock:
            state = self._mutable_state()
            state.policy_revision += 1
            state.policy_version = f"{version_prefix}{state.policy_revision}"
            return state.policy_revision, state.policy_version

    def close(self) -> None:
        return None


_DATACLASSES = {
    item.__name__: item
    for item in (
        AgentProfile,
        IntentPassport,
        ActionRequest,
        RefundClaim,
        EvidenceArtifact,
        Remedy,
        FindingContext,
        PolicyFinding,
        RiskAssessment,
        DecisionRecord,
        BudgetReservation,
        AuthorizationLease,
        AuthorizationResult,
        HumanApproval,
    )
}
_ENUMS = {
    item.__name__: item
    for item in (
        Decision,
        ReservationStatus,
        ApprovalStatus,
        ClaimReason,
        EvidenceKind,
        RemedyKind,
    )
}


def _encode(value: Any) -> Any:
    if is_dataclass(value):
        return {
            "$type": type(value).__name__,
            **{field.name: _encode(getattr(value, field.name)) for field in fields(value)},
        }
    if isinstance(value, Enum):
        return {"$enum": type(value).__name__, "value": value.value}
    if isinstance(value, Decimal):
        return {"$decimal": str(value)}
    if isinstance(value, datetime):
        return {"$datetime": value.isoformat()}
    if isinstance(value, date):
        return {"$date": value.isoformat()}
    if isinstance(value, frozenset):
        return {"$frozenset": [_encode(item) for item in sorted(value)]}
    if isinstance(value, tuple):
        return {"$tuple": [_encode(item) for item in value]}
    if isinstance(value, dict):
        return {key: _encode(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_encode(item) for item in value]
    return value


def _decode(value: Any) -> Any:
    if isinstance(value, list):
        return [_decode(item) for item in value]
    if not isinstance(value, dict):
        return value
    if "$decimal" in value:
        return Decimal(value["$decimal"])
    if "$datetime" in value:
        return datetime.fromisoformat(value["$datetime"])
    if "$date" in value:
        return date.fromisoformat(value["$date"])
    if "$frozenset" in value:
        return frozenset(_decode(item) for item in value["$frozenset"])
    if "$tuple" in value:
        return tuple(_decode(item) for item in value["$tuple"])
    if "$enum" in value:
        return _ENUMS[value["$enum"]](value["value"])
    if "$type" in value:
        cls = _DATACLASSES[value["$type"]]
        return cls(**{key: _decode(item) for key, item in value.items() if key != "$type"})
    return {key: _decode(item) for key, item in value.items()}


class PostgresStateRepository:
    """PostgreSQL source of truth for governance records shared by replicas."""

    def __init__(self, conninfo: str, *, autocommit: bool = True) -> None:
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(
            conninfo,
            min_size=1,
            max_size=8,
            open=True,
            kwargs={"autocommit": autocommit},
        )
        self._pool.wait(timeout=10)
        self._baseline: GovernanceState | None = None

    def close(self) -> None:
        self._pool.close()

    def load(self, *, default_policy_version: str) -> GovernanceState:
        state = empty_state(default_policy_version)
        with self._pool.connection() as connection, connection.transaction():
            # The eight reads below must describe one instant. The pool runs in
            # autocommit, so without this every statement takes its own
            # snapshot and a writer committing mid-load is seen by the later
            # statements but not the earlier ones -- a torn snapshot.
            #
            # The damaging pair is authorization_records (read seventh) and
            # approval_requests (read eighth): claim_approval_transition writes
            # both in one transaction, so a tear between them yields a resolved
            # approval beside its own pre-resolution authorization record, and
            # approve_action's early return hands the caller the stale REVIEW.
            #
            # A transaction alone is not enough. Under READ COMMITTED each
            # statement still re-snapshots, so the tear survives; REPEATABLE
            # READ is what pins all eight statements to one snapshot. It has to
            # be the first statement in the transaction, and it is scoped to
            # this transaction rather than the session, so a pooled connection
            # is handed back unmodified. The transaction is read-only, so it
            # cannot raise a serialization failure and needs no retry.
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            metadata = connection.execute(
                "SELECT policy_version, policy_revision, fleet_stopped, fleet_epoch "
                "FROM governance_metadata WHERE singleton = TRUE"
            ).fetchone()
            if metadata is not None:
                state.policy_version = metadata[0]
                state.policy_revision = metadata[1]
                state.fleet_stopped = metadata[2]
                state.fleet_epoch = metadata[3]
            for agent_id, payload in connection.execute(
                "SELECT agent_id, payload FROM agent_policies"
            ):
                state.agents[agent_id] = _decode(payload)
            for intent_id, payload in connection.execute(
                "SELECT intent_id, payload FROM customer_intents"
            ):
                state.intents[intent_id] = _decode(payload)
            for agent_id, epoch in connection.execute(
                "SELECT agent_id, revocation_epoch FROM agent_revocations"
            ):
                state.revoked_agents.add(agent_id)
                state.revocation_epochs[agent_id] = epoch
            for agent_id, budget_date, count in connection.execute(
                "SELECT agent_id, budget_date, authorization_count "
                "FROM authorization_counters"
            ):
                state.authorization_counts[(agent_id, budget_date)] = count
            for lease_id, payload in connection.execute(
                "SELECT lease_id, payload FROM authorization_leases"
            ):
                state.leases[lease_id] = _decode(payload)
            for request_id, request_payload, result_payload in connection.execute(
                "SELECT request_id, request_payload, result_payload "
                "FROM authorization_records"
            ):
                state.authorizations[request_id] = (
                    _decode(request_payload),
                    _decode(result_payload),
                )
            for request_id, payload in connection.execute(
                "SELECT request_id, payload FROM approval_requests"
            ):
                state.approvals[request_id] = _decode(payload)
        self._baseline = deepcopy(state)
        return state

    def claim_authorization(
        self,
        request_id: str,
        request: ActionRequest,
        result: AuthorizationResult,
    ) -> bool:
        """Insert the record only if nobody else has, in one statement.

        ``ON CONFLICT DO NOTHING ... RETURNING`` yields a row to exactly one
        caller under concurrency; every other caller gets nothing back and
        knows it lost. ``save()`` writes the same row again later with
        identical content, which is a harmless no-op.
        """

        from psycopg.types.json import Jsonb

        with self._pool.connection() as connection:
            row = connection.execute(
                """
                INSERT INTO authorization_records
                    (request_id, request_payload, result_payload)
                VALUES (%s, %s, %s)
                ON CONFLICT (request_id) DO NOTHING
                RETURNING request_id
                """,
                (request_id, Jsonb(_encode(request)), Jsonb(_encode(result))),
            ).fetchone()
        return row is not None

    def get_authorization(
        self, request_id: str
    ) -> tuple[ActionRequest, AuthorizationResult] | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT request_payload, result_payload FROM authorization_records "
                "WHERE request_id = %s",
                (request_id,),
            ).fetchone()
        return None if row is None else (_decode(row[0]), _decode(row[1]))

    def claim_approval_transition(
        self,
        request_id: str,
        approval: HumanApproval,
        request: ActionRequest,
        result: AuthorizationResult,
    ) -> bool:
        """Resolve a pending approval and store its authorization in one go.

        The conditional UPDATE is the whole guard: under READ COMMITTED a
        second caller blocks on the row until the first commits, then
        re-evaluates the predicate against the committed row, finds the status
        is no longer pending, and matches zero rows. Because the authorization
        record is written inside the same transaction, by the time a loser is
        told it lost, the winner's result is already readable.
        """

        from psycopg.types.json import Jsonb

        with self._pool.connection() as connection:
            with connection.transaction():
                row = connection.execute(
                    """
                    UPDATE approval_requests
                       SET payload = %s, updated_at = now()
                     WHERE request_id = %s
                       AND payload -> 'status' ->> 'value' = %s
                    RETURNING request_id
                    """,
                    (
                        Jsonb(_encode(approval)),
                        request_id,
                        ApprovalStatus.PENDING.value,
                    ),
                ).fetchone()
                if row is None:
                    return False
                connection.execute(
                    """
                    INSERT INTO authorization_records
                        (request_id, request_payload, result_payload)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (request_id) DO UPDATE SET
                        request_payload = EXCLUDED.request_payload,
                        result_payload = EXCLUDED.result_payload,
                        updated_at = now()
                    """,
                    (request_id, Jsonb(_encode(request)), Jsonb(_encode(result))),
                )
        return True

    def get_approval(self, request_id: str) -> HumanApproval | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT payload FROM approval_requests WHERE request_id = %s",
                (request_id,),
            ).fetchone()
        return None if row is None else _decode(row[0])

    def increment_authorization_count(self, agent_id: str, day: date) -> int:
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                INSERT INTO authorization_counters
                    (agent_id, budget_date, authorization_count)
                VALUES (%s, %s, 1)
                ON CONFLICT (agent_id, budget_date) DO UPDATE SET
                    authorization_count =
                        authorization_counters.authorization_count + 1
                RETURNING authorization_count
                """,
                (agent_id, day),
            ).fetchone()
        return int(row[0])

    def next_fleet_epoch(self, *, policy_version: str) -> int:
        """Stop the fleet, advancing the epoch by one inside the database.

        The epoch must never repeat. ``commit_reservation`` refuses a lease
        whose stamped epoch differs from the current one, so two stops that
        collapsed onto the same number would let a lease issued between them
        survive the second stop.
        """

        with self._pool.connection() as connection:
            row = connection.execute(
                """
                INSERT INTO governance_metadata
                    (singleton, policy_version, policy_revision,
                     fleet_stopped, fleet_epoch)
                VALUES (TRUE, %s, 0, TRUE, 1)
                ON CONFLICT (singleton) DO UPDATE SET
                    fleet_stopped = TRUE,
                    fleet_epoch = governance_metadata.fleet_epoch + 1,
                    updated_at = now()
                RETURNING fleet_epoch
                """,
                (policy_version,),
            ).fetchone()
        return int(row[0])

    def resume_fleet(self, *, expected_epoch: int) -> bool:
        """Clear the stop only while the epoch still matches what was read.

        The epoch is the version number of the fleet's stopped state. Matching
        it means no stop has landed since the caller looked, so clearing the
        flag cannot silently undo one.
        """

        with self._pool.connection() as connection:
            row = connection.execute(
                """
                UPDATE governance_metadata
                   SET fleet_stopped = FALSE, updated_at = now()
                 WHERE singleton = TRUE AND fleet_epoch = %s
                RETURNING fleet_epoch
                """,
                (expected_epoch,),
            ).fetchone()
        return row is not None

    def next_revocation_epoch(self, agent_id: str) -> int:
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                INSERT INTO agent_revocations (agent_id, revocation_epoch)
                VALUES (%s, 1)
                ON CONFLICT (agent_id) DO UPDATE SET
                    revocation_epoch = agent_revocations.revocation_epoch + 1,
                    revoked_at = now()
                RETURNING revocation_epoch
                """,
                (agent_id,),
            ).fetchone()
        return int(row[0])

    def next_policy_revision(self, *, version_prefix: str) -> tuple[int, str]:
        """Advance the revision and rebuild its version string in one statement.

        The two are written together because they are one fact. Bumping the
        number in the database while composing the string in Python lets a
        slower replica store a version that disagrees with the revision beside
        it, and a decision's recorded policy_version is how an auditor
        identifies which policy applied.
        """

        with self._pool.connection() as connection:
            row = connection.execute(
                """
                INSERT INTO governance_metadata
                    (singleton, policy_version, policy_revision,
                     fleet_stopped, fleet_epoch)
                VALUES (TRUE, %(prefix)s || '1', 1, FALSE, 0)
                ON CONFLICT (singleton) DO UPDATE SET
                    policy_revision = governance_metadata.policy_revision + 1,
                    policy_version = %(prefix)s ||
                        (governance_metadata.policy_revision + 1)::text,
                    updated_at = now()
                RETURNING policy_revision, policy_version
                """,
                {"prefix": version_prefix},
            ).fetchone()
        return int(row[0]), str(row[1])

    def save(self, state: GovernanceState) -> None:
        from psycopg.types.json import Jsonb

        baseline = self._baseline or empty_state(state.policy_version)
        with self._pool.connection() as connection:
            with connection.transaction():
                self._sync_metadata(connection, baseline, state)
                self._sync_payloads(
                    connection, "agent_policies", "agent_id",
                    baseline.agents, state.agents, Jsonb
                )
                self._sync_payloads(
                    connection, "customer_intents", "intent_id",
                    baseline.intents, state.intents, Jsonb
                )
                self._sync_payloads(
                    connection, "authorization_leases", "lease_id",
                    baseline.leases, state.leases, Jsonb
                )
                self._sync_payloads(
                    connection, "approval_requests", "request_id",
                    baseline.approvals, state.approvals, Jsonb
                )
                self._sync_authorizations(
                    connection, baseline.authorizations, state.authorizations, Jsonb
                )
                for agent_id in baseline.revoked_agents - state.revoked_agents:
                    connection.execute(
                        "DELETE FROM agent_revocations WHERE agent_id = %s",
                        (agent_id,),
                    )
                changed_revocations = [
                    (agent_id, state.revocation_epochs.get(agent_id, 1))
                    for agent_id in state.revoked_agents
                    if baseline.revocation_epochs.get(agent_id)
                    != state.revocation_epochs.get(agent_id)
                ]
                if changed_revocations:
                    self._executemany(
                        connection,
                        """
                        INSERT INTO agent_revocations (agent_id, revocation_epoch)
                        VALUES (%s, %s)
                        ON CONFLICT (agent_id) DO UPDATE SET
                            revocation_epoch = GREATEST(
                                agent_revocations.revocation_epoch,
                                EXCLUDED.revocation_epoch
                            ),
                            revoked_at = now()
                        """,
                        changed_revocations,
                    )
                changed_counts = [
                    (*key, count)
                    for key, count in state.authorization_counts.items()
                    if baseline.authorization_counts.get(key) != count
                ]
                if changed_counts:
                    self._executemany(
                        connection,
                        """
                        INSERT INTO authorization_counters
                            (agent_id, budget_date, authorization_count)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (agent_id, budget_date) DO UPDATE SET
                            authorization_count = GREATEST(
                                authorization_counters.authorization_count,
                                EXCLUDED.authorization_count
                            )
                        """,
                        changed_counts,
                    )
        self._baseline = deepcopy(state)

    @staticmethod
    def _sync_metadata(
        connection: Any,
        baseline: GovernanceState,
        state: GovernanceState,
    ) -> None:
        previous = (
            baseline.policy_version,
            baseline.policy_revision,
            baseline.fleet_stopped,
            baseline.fleet_epoch,
        )
        desired = (
            state.policy_version,
            state.policy_revision,
            state.fleet_stopped,
            state.fleet_epoch,
        )
        if previous == desired:
            return
        row = connection.execute(
            """
            SELECT policy_version, policy_revision, fleet_stopped, fleet_epoch
            FROM governance_metadata WHERE singleton = TRUE FOR UPDATE
            """
        ).fetchone()
        merged = list(row or previous)
        # Monotonic values are advanced by their own single-statement updates
        # and must never move backwards here. A replica whose snapshot is one
        # behind would otherwise undo a peer's increment simply by saving last.
        # fleet_stopped is deliberately NOT merged here. Both directions are
        # atomic operations of their own -- next_fleet_epoch sets it, and
        # resume_fleet clears it only while the epoch is unchanged. Letting a
        # snapshot write it would let a stale save undo a stop.
        merged[3] = max(merged[3], state.fleet_epoch)
        # policy_version is derived from policy_revision, so the pair moves
        # together or not at all; writing one without the other would leave a
        # version string that disagrees with the revision beside it.
        if state.policy_revision > merged[1]:
            merged[1] = state.policy_revision
            merged[0] = state.policy_version
        connection.execute(
            """
            INSERT INTO governance_metadata
                (singleton, policy_version, policy_revision, fleet_stopped, fleet_epoch)
            VALUES (TRUE, %s, %s, %s, %s)
            ON CONFLICT (singleton) DO UPDATE SET
                policy_version = EXCLUDED.policy_version,
                policy_revision = EXCLUDED.policy_revision,
                fleet_stopped = EXCLUDED.fleet_stopped,
                fleet_epoch = EXCLUDED.fleet_epoch,
                updated_at = now()
            """,
            tuple(merged),
        )

    @staticmethod
    def _sync_payloads(
        connection: Any,
        table: str,
        key: str,
        baseline: dict[str, Any],
        values: dict[str, Any],
        jsonb: Any,
    ) -> None:
        for item_id in baseline.keys() - values.keys():
            connection.execute(f"DELETE FROM {table} WHERE {key} = %s", (item_id,))
        changed = [
            (item_id, jsonb(_encode(item)))
            for item_id, item in values.items()
            if baseline.get(item_id) != item
        ]
        if changed:
            PostgresStateRepository._executemany(
                connection,
                f"""
                INSERT INTO {table} ({key}, payload) VALUES (%s, %s)
                ON CONFLICT ({key}) DO UPDATE SET
                    payload = EXCLUDED.payload, updated_at = now()
                """,
                changed,
            )

    @staticmethod
    def _sync_authorizations(
        connection: Any,
        baseline: dict[str, tuple[ActionRequest, AuthorizationResult]],
        values: dict[str, tuple[ActionRequest, AuthorizationResult]],
        jsonb: Any,
    ) -> None:
        for request_id in baseline.keys() - values.keys():
            connection.execute(
                "DELETE FROM authorization_records WHERE request_id = %s",
                (request_id,),
            )
        changed = [
            (request_id, jsonb(_encode(request)), jsonb(_encode(result)))
            for request_id, (request, result) in values.items()
            if baseline.get(request_id) != (request, result)
        ]
        if changed:
            PostgresStateRepository._executemany(
                connection,
                """
                INSERT INTO authorization_records
                    (request_id, request_payload, result_payload)
                VALUES (%s, %s, %s)
                ON CONFLICT (request_id) DO UPDATE SET
                    request_payload = EXCLUDED.request_payload,
                    result_payload = EXCLUDED.result_payload,
                    updated_at = now()
                """,
                changed,
            )

    @staticmethod
    def _executemany(
        connection: Any, query: str, params: list[tuple[Any, ...]]
    ) -> None:
        """Execute a parameter batch through psycopg's cursor API."""

        with connection.cursor() as cursor:
            cursor.executemany(query, params)
