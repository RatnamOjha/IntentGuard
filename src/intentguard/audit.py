"""Tamper-evident, hash-chained audit events."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any


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

    def as_dicts(self) -> list[dict[str, Any]]:
        return [asdict(event) for event in self._events]

