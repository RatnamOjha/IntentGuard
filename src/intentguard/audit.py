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

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

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
        return event

    def first_invalid_link(self) -> int | None:
        """Return the 1-based position of the first event that breaks the chain.

        Returns ``None`` when the whole chain verifies. The position is the
        offset in the stored list rather than the ``sequence`` field, because
        ``sequence`` is itself part of the tampered data: after a deletion the
        surviving events keep their original sequence numbers, and the position
        is what identifies where the chain actually breaks.

        This applies exactly the checks :meth:`verify` has always applied. It
        reports where they first fail; it does not add any.
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

