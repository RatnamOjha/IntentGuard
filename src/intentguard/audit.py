"""Tamper-evident, hash-chained audit events."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Protocol


def _json_default(value: Any) -> str:
    if isinstance(value, (datetime, Decimal, Enum)):
        return str(value)
    raise TypeError(f"Unsupported audit value: {type(value)!r}")


@dataclass(frozen=True)
class LedgerCheckpoint:
    """The expected length and head of a chain, held outside the chain itself.

    A bare hash chain cannot detect truncation: lopping events off the end
    leaves a shorter chain that still verifies, and an attacker's own events are
    always the newest ones. Holding the count and head hash separately closes
    that, but only to the extent the checkpoint really is separate. Kept in the
    same process, it stops an attacker who edits the event list; it does not
    stop one who updates the checkpoint too. A signed, externally stored
    checkpoint is the fuller answer.
    """

    event_count: int
    head_hash: str


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    occurred_at: datetime
    event_type: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str


@dataclass(frozen=True)
class AuditRetentionPolicy:
    """Archive eligibility without destructive mutation of the hash chain."""

    archive_after_days: int = 365

    @classmethod
    def from_env(cls) -> "AuditRetentionPolicy":
        days = int(os.getenv("INTENTGUARD_AUDIT_ARCHIVE_AFTER_DAYS", "365"))
        if days < 1:
            raise ValueError("Audit archive retention must be at least one day.")
        return cls(archive_after_days=days)

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": "append_only_archive",
            "archive_after_days": self.archive_after_days,
            "automatic_deletion": False,
            "reason": "Deletion would invalidate the tamper-evident hash chain.",
        }


class AuditLedger:
    """In-memory ledger suitable for demonstrations and deterministic tests."""

    GENESIS_HASH = "0" * 64

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._checkpoint = LedgerCheckpoint(
            event_count=0, head_hash=self.GENESIS_HASH
        )

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    @property
    def checkpoint(self) -> LedgerCheckpoint:
        """The expected length and head, tracked outside the event list."""

        return self._checkpoint

    def append(self, event_type: str, payload: dict[str, Any]) -> AuditEvent:
        sequence = len(self._events) + 1
        occurred_at = datetime.now(timezone.utc)
        previous_hash = (
            self._events[-1].event_hash if self._events else self.GENESIS_HASH
        )
        hash_input = self._canonical(
            {
                "sequence": sequence,
                "occurred_at": occurred_at,
                "event_type": event_type,
                "payload": payload,
                "previous_hash": previous_hash,
            }
        )
        event_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
        event = AuditEvent(
            sequence=sequence,
            occurred_at=occurred_at,
            event_type=event_type,
            payload=payload,
            previous_hash=previous_hash,
            event_hash=event_hash,
        )
        self._events.append(event)
        self._checkpoint = LedgerCheckpoint(
            event_count=len(self._events), head_hash=event_hash
        )
        return event

    def first_invalid_link(self) -> int | None:
        """Return the 1-based position of the first event that breaks the chain.

        Returns ``None`` when the whole chain verifies against itself and
        against the checkpoint. The position is the offset in the stored list
        rather than the ``sequence`` field, because ``sequence`` is itself part
        of the tampered data: after a deletion the surviving events keep their
        original sequence numbers, and the position is what identifies where the
        chain actually breaks.

        Truncation is reported at the first position that is missing, which is
        one past the end of what remains.
        """

        previous_hash = self.GENESIS_HASH
        for position, event in enumerate(self._events, start=1):
            expected_hash = hashlib.sha256(
                self._canonical(
                    {
                        "sequence": event.sequence,
                        "occurred_at": event.occurred_at,
                        "event_type": event.event_type,
                        "payload": event.payload,
                        "previous_hash": previous_hash,
                    }
                ).encode("utf-8")
            ).hexdigest()
            if event.previous_hash != previous_hash:
                return position
            if event.event_hash != expected_hash:
                return position
            previous_hash = event.event_hash

        # Links so far are internally consistent. The chain cannot tell on its
        # own that events were removed from the end, so compare against the
        # separately held checkpoint.
        if len(self._events) != self._checkpoint.event_count:
            return min(len(self._events), self._checkpoint.event_count) + 1
        if previous_hash != self._checkpoint.head_hash:
            return len(self._events) or 1
        return None

    def verify(self) -> bool:
        return self.first_invalid_link() is None

    @staticmethod
    def _canonical(value: dict[str, Any]) -> str:
        return json.dumps(
            value,
            default=_json_default,
            separators=(",", ":"),
            sort_keys=True,
        )

    def as_dicts(
        self, *, after_sequence: int = 0, limit: int | None = None
    ) -> list[dict[str, Any]]:
        events = [event for event in self._events if event.sequence > after_sequence]
        if limit is not None:
            events = events[:limit]
        return [asdict(event) for event in events]


def _jsonable(value: Any) -> Any:
    """Convert audit values to the exact JSON scalars used by `_canonical`."""

    if isinstance(value, (datetime, Decimal, Enum)):
        return str(value)
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


class PostgresAuditLedger:
    """A database-backed hash chain with an atomically updated checkpoint."""

    GENESIS_HASH = AuditLedger.GENESIS_HASH

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

    def close(self) -> None:
        self._pool.close()

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                """
                SELECT sequence, occurred_at, event_type, payload,
                       previous_hash, event_hash
                FROM audit_events ORDER BY sequence
                """
            ).fetchall()
        return tuple(AuditEvent(*row) for row in rows)

    @property
    def checkpoint(self) -> LedgerCheckpoint:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT event_count, head_hash FROM audit_metadata "
                "WHERE singleton = TRUE"
            ).fetchone()
        if row is None:
            return LedgerCheckpoint(0, self.GENESIS_HASH)
        return LedgerCheckpoint(event_count=row[0], head_hash=row[1])

    def append(self, event_type: str, payload: dict[str, Any]) -> AuditEvent:
        from psycopg.types.json import Jsonb

        occurred_at = datetime.now(timezone.utc)
        stored_payload = _jsonable(payload)
        with self._pool.connection() as connection:
            with connection.transaction():
                row = connection.execute(
                    """
                    SELECT event_count, head_hash FROM audit_metadata
                    WHERE singleton = TRUE FOR UPDATE
                    """
                ).fetchone()
                if row is None:
                    connection.execute(
                        """
                        INSERT INTO audit_metadata (singleton, event_count, head_hash)
                        VALUES (TRUE, 0, %s)
                        """,
                        (self.GENESIS_HASH,),
                    )
                    sequence, previous_hash = 1, self.GENESIS_HASH
                else:
                    sequence, previous_hash = row[0] + 1, row[1]
                hash_input = AuditLedger._canonical(
                    {
                        "sequence": sequence,
                        "occurred_at": occurred_at,
                        "event_type": event_type,
                        "payload": stored_payload,
                        "previous_hash": previous_hash,
                    }
                )
                event_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
                connection.execute(
                    """
                    INSERT INTO audit_events
                        (sequence, occurred_at, event_type, payload,
                         previous_hash, event_hash)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        sequence,
                        occurred_at,
                        event_type,
                        Jsonb(stored_payload),
                        previous_hash,
                        event_hash,
                    ),
                )
                connection.execute(
                    """
                    UPDATE audit_metadata SET event_count = %s, head_hash = %s
                    WHERE singleton = TRUE
                    """,
                    (sequence, event_hash),
                )
        return AuditEvent(
            sequence=sequence,
            occurred_at=occurred_at,
            event_type=event_type,
            payload=stored_payload,
            previous_hash=previous_hash,
            event_hash=event_hash,
        )

    def first_invalid_link(self) -> int | None:
        previous_hash = self.GENESIS_HASH
        events = self.events
        for position, event in enumerate(events, start=1):
            expected_hash = hashlib.sha256(
                AuditLedger._canonical(
                    {
                        "sequence": event.sequence,
                        "occurred_at": event.occurred_at,
                        "event_type": event.event_type,
                        "payload": event.payload,
                        "previous_hash": previous_hash,
                    }
                ).encode("utf-8")
            ).hexdigest()
            if event.previous_hash != previous_hash or event.event_hash != expected_hash:
                return position
            previous_hash = event.event_hash
        checkpoint = self.checkpoint
        if len(events) != checkpoint.event_count:
            return min(len(events), checkpoint.event_count) + 1
        if previous_hash != checkpoint.head_hash:
            return len(events) or 1
        return None

    def verify(self) -> bool:
        return self.first_invalid_link() is None

    def as_dicts(
        self, *, after_sequence: int = 0, limit: int | None = None
    ) -> list[dict[str, Any]]:
        query = (
            "SELECT sequence, occurred_at, event_type, payload, "
            "previous_hash, event_hash FROM audit_events "
            "WHERE sequence > %s ORDER BY sequence"
        )
        parameters: tuple[Any, ...] = (after_sequence,)
        if limit is not None:
            query += " LIMIT %s"
            parameters += (limit,)
        with self._pool.connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [asdict(AuditEvent(*row)) for row in rows]

