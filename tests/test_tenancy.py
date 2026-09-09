"""Organisations, membership, and API keys.

One contract class runs against both stores, so the Postgres implementation is
differentially tested against a known-good in-memory reference rather than
trusted -- the pattern Decisions #7 established for the budget ledger.
"""

from __future__ import annotations

import os
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from intentguard.tenancy import (  # noqa: E402
    ApiKeyError,
    InMemoryTenancyStore,
    PostgresTenancyStore,
    generate_api_key,
    hash_api_key,
    key_prefix,
)

NOW = datetime(2026, 9, 3, 12, tzinfo=timezone.utc)


class KeyFormatTest(unittest.TestCase):
    def test_keys_are_prefixed_unique_and_not_stored_in_the_clear(self) -> None:
        first, prefix, digest = generate_api_key()
        second, _, _ = generate_api_key()

        self.assertTrue(first.startswith("ig_live_"), first[:8])
        self.assertNotEqual(first, second)
        self.assertEqual(prefix, key_prefix(first))
        self.assertEqual(digest, hash_api_key(first))
        # The digest must not leak the secret it was derived from.
        self.assertNotIn(first.split("_")[-1], digest)

    def test_prefix_is_short_enough_to_index_and_long_enough_to_narrow(self) -> None:
        secret, prefix, _ = generate_api_key()
        self.assertEqual(16, len(prefix))
        self.assertTrue(secret.startswith(prefix))


class TenancyContract:
    """Behaviour both stores must share."""

    store: object

    def unique(self, label: str) -> str:
        return f"{label}-{uuid.uuid4().hex[:12]}"

    def make_org(self, name: str = "Acme Support"):
        return self.store.create_organization(name, self.unique("acme"))

    def test_organisation_round_trips(self) -> None:
        created = self.make_org()
        self.assertEqual(created, self.store.get_organization(created.org_id))
        self.assertTrue(created.org_id.startswith("org_"))

    def test_slugs_are_unique(self) -> None:
        slug = self.unique("dupe")
        self.store.create_organization("First", slug)
        with self.assertRaises(ValueError):
            self.store.create_organization("Second", slug)

    def test_membership_maps_a_token_subject_to_one_organisation(self) -> None:
        org = self.make_org()
        subject = self.unique("subject")
        self.store.add_member(org.org_id, subject, frozenset({"operator"}))

        found = self.store.membership(subject)
        self.assertEqual((org.org_id, frozenset({"operator"})), found)

    def test_an_unknown_subject_has_no_organisation(self) -> None:
        self.assertIsNone(self.store.membership(self.unique("nobody")))

    def test_a_key_authenticates_into_its_own_organisation(self) -> None:
        org = self.make_org()
        issued = self.store.issue_key(
            org.org_id,
            name="support agent",
            roles=frozenset({"agent"}),
            agent_id="refund-bot",
            customer_id="customer-1",
        )

        principal = self.store.authenticate_key(issued.secret, now=NOW)

        self.assertEqual(org.org_id, principal.org_id)
        self.assertEqual(frozenset({"agent"}), principal.roles)
        self.assertEqual("refund-bot", principal.agent_id)
        self.assertEqual("customer-1", principal.customer_id)
        self.assertEqual(f"key:{issued.record.key_id}", principal.subject)

    def test_an_unknown_key_is_refused(self) -> None:
        unknown, _, _ = generate_api_key()
        with self.assertRaises(ApiKeyError):
            self.store.authenticate_key(unknown, now=NOW)

    def test_a_near_miss_key_is_refused(self) -> None:
        """Sharing a prefix is not sharing a secret."""

        org = self.make_org()
        issued = self.store.issue_key(
            org.org_id, name="k", roles=frozenset({"agent"})
        )
        tampered = issued.secret[:-1] + ("a" if issued.secret[-1] != "a" else "b")

        self.assertEqual(key_prefix(issued.secret), key_prefix(tampered))
        with self.assertRaises(ApiKeyError):
            self.store.authenticate_key(tampered, now=NOW)

    def test_a_revoked_key_stops_working(self) -> None:
        org = self.make_org()
        issued = self.store.issue_key(
            org.org_id, name="k", roles=frozenset({"agent"})
        )
        self.store.authenticate_key(issued.secret, now=NOW)

        self.assertTrue(self.store.revoke_key(org.org_id, issued.record.key_id))

        with self.assertRaises(ApiKeyError):
            self.store.authenticate_key(issued.secret, now=NOW)

    def test_an_expired_key_stops_working(self) -> None:
        org = self.make_org()
        issued = self.store.issue_key(
            org.org_id,
            name="k",
            roles=frozenset({"agent"}),
            expires_at=NOW + timedelta(hours=1),
        )
        self.store.authenticate_key(issued.secret, now=NOW)

        with self.assertRaises(ApiKeyError):
            self.store.authenticate_key(issued.secret, now=NOW + timedelta(hours=2))

    def test_one_organisation_cannot_revoke_another_organisation_key(self) -> None:
        owner = self.make_org("Owner")
        intruder = self.make_org("Intruder")
        issued = self.store.issue_key(
            owner.org_id, name="k", roles=frozenset({"agent"})
        )

        self.assertFalse(
            self.store.revoke_key(intruder.org_id, issued.record.key_id)
        )
        # Still usable, because the revoke was refused rather than silently applied.
        self.store.authenticate_key(issued.secret, now=NOW)

    def test_listing_keys_is_scoped_to_one_organisation(self) -> None:
        first, second = self.make_org("First"), self.make_org("Second")
        self.store.issue_key(first.org_id, name="a", roles=frozenset({"agent"}))
        self.store.issue_key(first.org_id, name="b", roles=frozenset({"agent"}))
        self.store.issue_key(second.org_id, name="c", roles=frozenset({"agent"}))

        self.assertEqual(2, len(self.store.list_keys(first.org_id)))
        self.assertEqual(1, len(self.store.list_keys(second.org_id)))
        self.assertEqual(
            {"c"}, {record.name for record in self.store.list_keys(second.org_id)}
        )

    def test_listed_keys_never_carry_the_secret(self) -> None:
        org = self.make_org()
        issued = self.store.issue_key(
            org.org_id, name="k", roles=frozenset({"agent"})
        )
        listed = self.store.list_keys(org.org_id)[0]

        self.assertNotIn(issued.secret, str(listed))
        self.assertEqual(issued.record.prefix, listed.prefix)

    def test_last_used_is_recorded(self) -> None:
        org = self.make_org()
        issued = self.store.issue_key(
            org.org_id, name="k", roles=frozenset({"agent"})
        )
        self.assertIsNone(self.store.list_keys(org.org_id)[0].last_used_at)

        self.store.authenticate_key(issued.secret, now=NOW)

        self.assertIsNotNone(self.store.list_keys(org.org_id)[0].last_used_at)

    def test_issuing_against_an_unknown_organisation_fails(self) -> None:
        with self.assertRaises(KeyError):
            self.store.issue_key(
                "org_missing", name="k", roles=frozenset({"agent"})
            )


class InMemoryTenancyTest(TenancyContract, unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryTenancyStore()


DATABASE_URL = os.getenv("INTENTGUARD_DATABASE_URL", "postgresql:///intentguard")


def postgres_available() -> bool:
    try:
        import psycopg
    except ImportError:
        return False
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=3) as connection:
            connection.execute("SELECT 1 FROM organizations LIMIT 1")
        return True
    except Exception:
        return False


@unittest.skipUnless(
    postgres_available(), "PostgreSQL tenancy migration is unavailable"
)
class PostgresTenancyTest(TenancyContract, unittest.TestCase):
    def setUp(self) -> None:
        self.store = PostgresTenancyStore(DATABASE_URL)
        self.addCleanup(self.store.close)

    def test_a_subject_belongs_to_only_one_organisation(self) -> None:
        """ADR 004 defers multi-org membership; this is that decision, enforced."""

        first, second = self.make_org("First"), self.make_org("Second")
        subject = self.unique("subject")
        self.store.add_member(first.org_id, subject, frozenset({"operator"}))

        with self.assertRaises(ValueError):
            self.store.add_member(second.org_id, subject, frozenset({"operator"}))
