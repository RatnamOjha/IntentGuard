from __future__ import annotations

import sys
import os
import unittest
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from intentguard.intent import (  # noqa: E402
    InMemoryIntentKeyRegistry,
    InMemoryNonceStore,
    IntentReplayError,
    IntentSigningKey,
    IntentVerificationError,
    IntentVerifier,
    encode_public_key,
    passport_payload,
    sign_passport,
    PostgresIntentKeyRegistry,
    PostgresNonceStore,
)
from intentguard.models import IntentPassport  # noqa: E402
from intentguard.policy_engine import PolicyEngine  # noqa: E402


NOW = datetime.now(timezone.utc).replace(microsecond=0)
ISSUER = "https://consent.intentguard.test"
AUDIENCE = "intentguard-api"


class SignedIntentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.registry = InMemoryIntentKeyRegistry()
        self.registry.save(
            IntentSigningKey(
                key_id="consent-2026-08",
                issuer=ISSUER,
                public_key=encode_public_key(self.private_key.public_key()),
            )
        )
        self.verifier = IntentVerifier(
            audience=AUDIENCE,
            key_registry=self.registry,
            nonce_store=InMemoryNonceStore(),
            allowed_issuers=frozenset({ISSUER}),
        )

    def passport(self, **changes: object) -> IntentPassport:
        value = IntentPassport(
            intent_id=f"intent-{uuid.uuid4().hex}",
            customer_id="customer-01",
            agent_id="travel-01",
            action="book_hotel",
            max_amount=Decimal("18000"),
            currency="INR",
            required_attributes={"city": "BOM", "refundable": True},
            issuer=ISSUER,
            audience=AUDIENCE,
            issued_at=NOW - timedelta(seconds=5),
            not_before=NOW - timedelta(seconds=5),
            expires_at=NOW + timedelta(hours=1),
            nonce=f"nonce-{uuid.uuid4().hex}",
            key_id="consent-2026-08",
        )
        return replace(value, **changes)

    def test_valid_passport_is_registered(self) -> None:
        engine = PolicyEngine(intent_verifier=self.verifier)
        passport = sign_passport(self.passport(), self.private_key)
        engine.register_intent(passport, expected_customer_id="customer-01")
        self.assertEqual(passport, engine.list_intents(customer_id="customer-01")[0])

    def test_signed_fields_cannot_be_modified(self) -> None:
        signed = sign_passport(self.passport(), self.private_key)
        mutations = {
            "amount": replace(signed, max_amount=Decimal("18001")),
            "customer": replace(signed, customer_id="customer-02"),
            "agent": replace(signed, agent_id="payments-99"),
            "attributes": replace(
                signed,
                required_attributes={"city": "DEL", "refundable": False},
            ),
        }
        for label, passport in mutations.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                IntentVerificationError, "signature is invalid"
            ):
                self.verifier.verify_and_consume(passport, now=NOW)

    def test_expired_passport_is_rejected(self) -> None:
        passport = sign_passport(
            self.passport(expires_at=NOW - timedelta(minutes=1)), self.private_key
        )
        with self.assertRaisesRegex(IntentVerificationError, "expired"):
            self.verifier.verify_and_consume(passport, now=NOW)

    def test_not_before_is_enforced(self) -> None:
        passport = sign_passport(
            self.passport(not_before=NOW + timedelta(minutes=5)), self.private_key
        )
        with self.assertRaisesRegex(IntentVerificationError, "not valid yet"):
            self.verifier.verify_and_consume(passport, now=NOW)

    def test_wrong_audience_is_rejected(self) -> None:
        passport = sign_passport(
            self.passport(audience="another-gateway"), self.private_key
        )
        with self.assertRaisesRegex(IntentVerificationError, "audience"):
            self.verifier.verify_and_consume(passport, now=NOW)

    def test_customer_ownership_is_enforced(self) -> None:
        passport = sign_passport(self.passport(), self.private_key)
        with self.assertRaisesRegex(IntentVerificationError, "different customer"):
            self.verifier.verify_and_consume(
                passport, now=NOW, expected_customer_id="customer-02"
            )

    def test_unknown_key_is_rejected(self) -> None:
        passport = sign_passport(
            self.passport(key_id="unknown-key"), self.private_key
        )
        with self.assertRaisesRegex(IntentVerificationError, "unknown signing key"):
            self.verifier.verify_and_consume(passport, now=NOW)

    def test_revoked_key_is_rejected(self) -> None:
        passport = sign_passport(self.passport(), self.private_key)
        self.registry.revoke(ISSUER, "consent-2026-08")
        with self.assertRaisesRegex(IntentVerificationError, "revoked"):
            self.verifier.verify_and_consume(passport, now=NOW)

    def test_reused_nonce_is_rejected(self) -> None:
        passport = sign_passport(self.passport(), self.private_key)
        self.verifier.verify_and_consume(passport, now=NOW)
        with self.assertRaisesRegex(IntentReplayError, "already been used"):
            self.verifier.verify_and_consume(passport, now=NOW)

    def test_key_rotation_keeps_new_key_working_after_old_key_revocation(self) -> None:
        new_private_key = Ed25519PrivateKey.generate()
        self.registry.save(
            IntentSigningKey(
                key_id="consent-2026-09",
                issuer=ISSUER,
                public_key=encode_public_key(new_private_key.public_key()),
            )
        )
        new_passport = sign_passport(
            self.passport(key_id="consent-2026-09"), new_private_key
        )
        self.registry.revoke(ISSUER, "consent-2026-08")
        self.verifier.verify_and_consume(new_passport, now=NOW)

    def test_key_id_cannot_be_rebound_to_different_key_material(self) -> None:
        replacement = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(ValueError, "cannot be rebound"):
            self.registry.save(
                IntentSigningKey(
                    key_id="consent-2026-08",
                    issuer=ISSUER,
                    public_key=encode_public_key(replacement.public_key()),
                )
            )


try:
    from fastapi.testclient import TestClient
except ImportError:
    TestClient = None


@unittest.skipIf(TestClient is None, "Install the API extra to test signed intent HTTP routes")
class SignedIntentApiTest(unittest.TestCase):
    def setUp(self) -> None:
        from intentguard.api import create_app
        from intentguard.auth import JwksAuthenticator
        from tests.jwt_test_support import AUDIENCE as JWT_AUDIENCE, ISSUER as JWT_ISSUER, JWKS

        self.private_key = Ed25519PrivateKey.generate()
        registry = InMemoryIntentKeyRegistry()
        verifier = IntentVerifier(
            audience=AUDIENCE,
            key_registry=registry,
            nonce_store=InMemoryNonceStore(),
        )
        engine = PolicyEngine(intent_verifier=verifier)
        authenticator = JwksAuthenticator(
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            jwks=JWKS,
            minimum_rsa_bits=512,
        )
        self.client = TestClient(create_app(engine, authenticator=authenticator))

    @staticmethod
    def headers(role: str, *, customer_id: str | None = None) -> dict[str, str]:
        from tests.jwt_test_support import bearer

        return bearer(
            subject=f"{role}-user",
            roles=[role],
            customer_id=customer_id,
        )

    def register_key(self) -> None:
        response = self.client.post(
            "/v1/intent-keys",
            headers=self.headers("admin"),
            json={
                "key_id": "consent-2026-08",
                "issuer": ISSUER,
                "public_key": encode_public_key(self.private_key.public_key()),
            },
        )
        self.assertEqual(201, response.status_code, response.text)

    def signed_payload(self) -> dict[str, object]:
        passport = sign_passport(
            IntentPassport(
                intent_id=f"intent-{uuid.uuid4().hex}",
                customer_id="customer-01",
                agent_id="travel-01",
                action="book_hotel",
                max_amount=Decimal("18000"),
                currency="INR",
                required_attributes={"refundable": True},
                issuer=ISSUER,
                audience=AUDIENCE,
                issued_at=NOW - timedelta(seconds=5),
                not_before=NOW - timedelta(seconds=5),
                expires_at=NOW + timedelta(hours=1),
                nonce=f"nonce-{uuid.uuid4().hex}",
                key_id="consent-2026-08",
            ),
            self.private_key,
        )
        return {**passport_payload(passport), "signature": passport.signature}

    def test_admin_registers_key_and_customer_submits_signed_passport(self) -> None:
        self.register_key()
        response = self.client.post(
            "/v1/intents",
            headers=self.headers("customer", customer_id="customer-01"),
            json=self.signed_payload(),
        )
        self.assertEqual(201, response.status_code, response.text)
        self.assertTrue(response.json()["signature"])

    def test_http_replay_returns_conflict(self) -> None:
        self.register_key()
        payload = self.signed_payload()
        headers = self.headers("customer", customer_id="customer-01")
        self.assertEqual(201, self.client.post("/v1/intents", headers=headers, json=payload).status_code)
        replay = self.client.post("/v1/intents", headers=headers, json=payload)
        self.assertEqual(409, replay.status_code)
        events = self.client.get(
            "/v1/audit/events", headers=self.headers("admin")
        ).json()
        self.assertEqual("nonce_replay", events[-1]["payload"]["reason"])


DATABASE_URL = os.getenv("INTENTGUARD_DATABASE_URL", "postgresql:///intentguard")


def postgres_signed_intents_available() -> bool:
    try:
        import psycopg
        with psycopg.connect(DATABASE_URL, connect_timeout=3) as connection:
            connection.execute("SELECT 1 FROM intent_signing_keys LIMIT 1")
            connection.execute("SELECT 1 FROM intent_nonces LIMIT 1")
        return True
    except Exception:
        return False


@unittest.skipUnless(
    postgres_signed_intents_available(),
    "PostgreSQL signed-intent migration is unavailable",
)
class PostgresSignedIntentTest(unittest.TestCase):
    def test_key_rotation_and_nonce_replay_survive_verifier_restart(self) -> None:
        issuer = f"https://consent-{uuid.uuid4().hex}.test"
        private_key = Ed25519PrivateKey.generate()
        registry = PostgresIntentKeyRegistry(DATABASE_URL)
        nonce_store = PostgresNonceStore(DATABASE_URL)
        self.addCleanup(registry.close)
        self.addCleanup(nonce_store.close)
        registry.save(
            IntentSigningKey(
                key_id="rotation-1",
                issuer=issuer,
                public_key=encode_public_key(private_key.public_key()),
            )
        )
        passport = sign_passport(
            IntentPassport(
                intent_id=f"intent-{uuid.uuid4().hex}",
                customer_id="customer-01",
                agent_id="travel-01",
                action="book_hotel",
                max_amount=Decimal("100"),
                currency="INR",
                expires_at=NOW + timedelta(hours=1),
                issuer=issuer,
                audience=AUDIENCE,
                issued_at=NOW,
                not_before=NOW,
                nonce=f"nonce-{uuid.uuid4().hex}",
                key_id="rotation-1",
            ),
            private_key,
        )
        first = IntentVerifier(
            audience=AUDIENCE, key_registry=registry, nonce_store=nonce_store
        )
        first.verify_and_consume(passport, now=NOW)

        restarted_registry = PostgresIntentKeyRegistry(DATABASE_URL)
        restarted_nonces = PostgresNonceStore(DATABASE_URL)
        self.addCleanup(restarted_registry.close)
        self.addCleanup(restarted_nonces.close)
        restarted = IntentVerifier(
            audience=AUDIENCE,
            key_registry=restarted_registry,
            nonce_store=restarted_nonces,
        )
        with self.assertRaises(IntentReplayError):
            restarted.verify_and_consume(passport, now=NOW)
