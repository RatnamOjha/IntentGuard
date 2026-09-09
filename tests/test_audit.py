"""The audit chain's canonical form.

A hash chain is only useful if the digest describes the event. Section H of
Decisions.md recorded the case where it described the *reader* instead: a
ledger written by one host reported itself broken when read from another.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from intentguard.audit import AuditLedger  # noqa: E402

KOLKATA = timezone(timedelta(hours=5, minutes=30))
INSTANT = datetime(2026, 9, 9, 10, 42, 33, 166800, tzinfo=timezone.utc)


class CanonicalInstantTest(unittest.TestCase):
    """The digest must be a property of the instant, not of who reads it."""

    def test_one_instant_canonicalises_identically_in_any_zone(self) -> None:
        same_instant_elsewhere = INSTANT.astimezone(KOLKATA)

        self.assertNotEqual(
            str(INSTANT),
            str(same_instant_elsewhere),
            "Premise of this test: str() alone renders one instant two ways. "
            "If these ever match, the trap is gone and so is the test.",
        )
        self.assertEqual(
            AuditLedger._canonical({"occurred_at": INSTANT}),
            AuditLedger._canonical({"occurred_at": same_instant_elsewhere}),
            "The same instant hashed to two digests depending on the reading "
            "session's timezone, so a chain verified only on a UTC host.",
        )

    def test_the_fix_moves_no_digest_that_was_already_correct(self) -> None:
        """No re-chaining. Chains written on a UTC host keep their hashes.

        The pre-fix canonicaliser emitted ``str(value)``. For a value that is
        already UTC the conversion is a no-op, so this reproduces the old
        output exactly -- which is why the fix needs no migration.
        """

        self.assertEqual(
            json.dumps(
                {"occurred_at": str(INSTANT)},
                separators=(",", ":"),
                sort_keys=True,
            ),
            AuditLedger._canonical({"occurred_at": INSTANT}),
        )

    def test_a_naive_datetime_is_not_given_an_offset_from_the_host_clock(
        self,
    ) -> None:
        """astimezone() on a naive value would read the host's zone.

        That is the same host-dependence in a new place, so naive values are
        left exactly as they are: with no offset, str() is already stable.
        """

        naive = datetime(2026, 9, 9, 10, 42, 33, 166800)

        self.assertEqual(
            json.dumps(
                {"occurred_at": str(naive)}, separators=(",", ":"), sort_keys=True
            ),
            AuditLedger._canonical({"occurred_at": naive}),
        )

    def test_a_chain_verifies_after_its_events_are_reread_in_another_zone(
        self,
    ) -> None:
        """The in-memory analogue of the Postgres round trip, no database.

        Rebuilding each event with its timestamp rendered in Asia/Kolkata is
        what psycopg does to a TIMESTAMPTZ on a non-UTC host.
        """

        import dataclasses

        ledger = AuditLedger()
        for index in range(3):
            ledger.append("refund_decided", {"probe": index})

        self.assertIsNone(ledger.first_invalid_link())

        ledger._events = [
            dataclasses.replace(
                event, occurred_at=event.occurred_at.astimezone(KOLKATA)
            )
            for event in ledger.events
        ]

        self.assertIsNone(
            ledger.first_invalid_link(),
            "Re-reading the very same events in a different timezone reported "
            "tampering. Nothing was tampered with.",
        )


DATABASE_URL = os.getenv("INTENTGUARD_DATABASE_URL", "postgresql:///intentguard")


def postgres_available() -> bool:
    try:
        import psycopg
    except ImportError:
        return False
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=3) as connection:
            connection.execute("SELECT 1 FROM audit_events LIMIT 1")
        return True
    except Exception:
        return False


@unittest.skipUnless(postgres_available(), "PostgreSQL audit tables are unavailable")
class PostgresChainVerifiesOutsideUtcTest(unittest.TestCase):
    """Section H, reproduced against the database that exhibited it.

    ``occurred_at`` is TIMESTAMPTZ, so the value psycopg returns carries the
    session's offset rather than the one it was written with. Before the fix
    this test failed with ``first_invalid_link() == 1``.
    """

    def setUp(self) -> None:
        import psycopg

        with psycopg.connect(DATABASE_URL) as connection:
            connection.execute("TRUNCATE audit_events, audit_metadata")
        self._saved_pgtz = os.environ.get("PGTZ")

    def tearDown(self) -> None:
        if self._saved_pgtz is None:
            os.environ.pop("PGTZ", None)
        else:
            os.environ["PGTZ"] = self._saved_pgtz

    def test_a_utc_written_chain_verifies_when_read_from_kolkata(self) -> None:
        from intentguard.audit import PostgresAuditLedger

        os.environ["PGTZ"] = "UTC"
        writer = PostgresAuditLedger(DATABASE_URL)
        try:
            for index in range(3):
                writer.append("refund_decided", {"probe": index})
        finally:
            writer.close()

        os.environ["PGTZ"] = "Asia/Kolkata"
        reader = PostgresAuditLedger(DATABASE_URL)
        try:
            events = reader.events

            # Without this guard the test passes when PGTZ is ignored, which
            # would make it prove nothing at all.
            self.assertEqual(
                {timedelta(hours=5, minutes=30)},
                {event.occurred_at.utcoffset() for event in events},
                "The reading session is not actually in Asia/Kolkata, so this "
                "test never exercised the bug it exists to guard.",
            )
            self.assertEqual(3, len(events))
            self.assertIsNone(
                reader.first_invalid_link(),
                "A chain written in UTC reported itself broken to a reader in "
                "another timezone. Nothing was tampered with.",
            )
        finally:
            reader.close()
