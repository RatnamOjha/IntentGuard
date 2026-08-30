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
    Decision,
    DecisionRecord,
    HumanApproval,
    IntentPassport,
    PolicyFinding,
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
        with self._lock:
            self._state = deepcopy(state)

    def close(self) -> None:
        return None


_DATACLASSES = {
    item.__name__: item
    for item in (
        AgentProfile,
        IntentPassport,
        ActionRequest,
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
    for item in (Decision, ReservationStatus, ApprovalStatus)
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
        with self._pool.connection() as connection:
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
                            revocation_epoch = EXCLUDED.revocation_epoch,
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
        for index, (old, new) in enumerate(zip(previous, desired)):
            if old != new:
                merged[index] = new
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
