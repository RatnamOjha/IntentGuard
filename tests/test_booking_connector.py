from __future__ import annotations

import sys
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from intentguard.booking_connector import (  # noqa: E402
    ClientCredentialsTokenProvider,
    CircuitBreaker,
    EngineGovernanceGateway,
    InMemoryExecutionStore,
    ProtectedBookingConnector,
    create_connector_app,
)
from intentguard.execution_lease import (  # noqa: E402
    ExecutionLeaseSigner,
    ExecutionLeaseVerifier,
    InMemoryLeaseKeyRegistry,
    LeaseVerificationKey,
    PostgresLeaseKeyRegistry,
)
from intentguard.booking_connector import PostgresExecutionStore  # noqa: E402
from intentguard.models import ActionRequest, AgentProfile, IntentPassport  # noqa: E402
from intentguard.policy_engine import PolicyEngine  # noqa: E402


NOW = datetime.now(timezone.utc)


class TimeoutProvider:
    def book(self, command):  # noqa: ANN001, ANN201
        raise TimeoutError("provider timeout")


class CountingTimeoutProvider:
    def __init__(self) -> None:
        self.calls = 0

    def book(self, command):  # noqa: ANN001, ANN201
        self.calls += 1
        raise TimeoutError("provider timeout")


class FailingProvider:
    def book(self, command):  # noqa: ANN001, ANN201
        raise RuntimeError("provider returned 500")


class FleetStoppingProvider:
    def __init__(self, engine: PolicyEngine) -> None:
        self.engine = engine

    def book(self, command):  # noqa: ANN001, ANN201
        self.engine.stop_fleet(reason="incident during provider call")
        return "TOO-LATE"


class ClientCredentialsTokenProviderTest(unittest.TestCase):
    def test_service_account_token_is_cached(self) -> None:
        class TokenResponse:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict[str, object]:
                return {"access_token": "connector-token", "expires_in": 60}

        provider = ClientCredentialsTokenProvider(
            "http://identity/token", "connector", "secret"
        )
        with patch("httpx.post", return_value=TokenResponse()) as request:
            self.assertEqual("connector-token", provider())
            self.assertEqual("connector-token", provider())

        request.assert_called_once()
        self.assertEqual(
            "client_credentials", request.call_args.kwargs["data"]["grant_type"]
        )


class ProtectedBookingConnectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = InMemoryLeaseKeyRegistry()
        self.engine = PolicyEngine(
            lease_signer=ExecutionLeaseSigner(
                Ed25519PrivateKey.generate(),
                issuer="intentguard-test-gateway",
                audience="booking-test",
                key_registry=self.keys,
            )
        )
        self.engine.register_agent(
            AgentProfile(
                agent_id="travel-01",
                name="Travel Agent",
                allowed_actions=frozenset({"book_hotel"}),
                max_action_amount=Decimal("20000"),
                daily_budget=Decimal("50000"),
            )
        )
        self.engine.register_intent(
            IntentPassport(
                intent_id="intent-01",
                customer_id="customer-01",
                agent_id="travel-01",
                action="book_hotel",
                max_amount=Decimal("18000"),
                currency="INR",
                expires_at=NOW + timedelta(hours=1),
                required_attributes={"refundable": True},
            )
        )
        self.store = InMemoryExecutionStore()
        self.client = self.make_client()

    def make_client(self, provider=None, circuit_breaker=None) -> TestClient:  # noqa: ANN001
        connector = ProtectedBookingConnector(
            verifier=ExecutionLeaseVerifier(
                audience="booking-test", key_registry=self.keys
            ),
            governance=EngineGovernanceGateway(self.engine),
            execution_store=self.store,
            provider=provider,
            circuit_breaker=circuit_breaker,
        )
        return TestClient(create_connector_app(connector))

    def authorization(self, *, expired: bool = False):  # noqa: ANN201
        request_id = f"request-{uuid.uuid4().hex}"
        now = NOW - timedelta(minutes=2) if expired else datetime.now(timezone.utc)
        ttl = timedelta(seconds=1) if expired else timedelta(seconds=30)
        result = self.engine.authorize_action(
            ActionRequest(
                request_id=request_id,
                agent_id="travel-01",
                customer_id="customer-01",
                action="book_hotel",
                amount=Decimal("4500"),
                currency="INR",
                intent_id="intent-01",
                risk_score=1,
                attributes={"refundable": True},
            ),
            now=now,
            lease_ttl=ttl,
        )
        return result

    @staticmethod
    def payload(result) -> dict[str, object]:  # noqa: ANN001
        return {
            "request_id": result.decision.request_id,
            "reservation_id": result.reservation.reservation_id,
            "agent_id": "travel-01",
            "customer_id": "customer-01",
            "action": "book_hotel",
            "hotel": "Intent Inn",
            "amount": "4500",
            "currency": "INR",
            "refundable": True,
            "lease_token": result.lease.token,
        }

    def test_direct_execution_without_lease_is_rejected(self) -> None:
        payload = self.payload(self.authorization())
        payload.pop("lease_token")
        response = self.client.post("/v1/bookings", json=payload)
        self.assertEqual(401, response.status_code)

    def test_valid_signed_lease_executes_and_commits(self) -> None:
        result = self.authorization()
        response = self.client.post("/v1/bookings", json=self.payload(result))
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual("booked", response.json()["status"])
        self.assertEqual(
            "committed",
            self.engine.get_reservation(result.reservation.reservation_id).status.value,
        )

    def test_duplicate_execution_returns_cached_provider_response(self) -> None:
        result = self.authorization()
        payload = self.payload(result)
        first = self.client.post("/v1/bookings", json=payload)
        second = self.client.post("/v1/bookings", json=payload)
        self.assertEqual(200, first.status_code)
        self.assertEqual(200, second.status_code)
        self.assertEqual(first.json()["provider_reference"], second.json()["provider_reference"])
        self.assertTrue(second.json()["idempotent_replay"])

    def test_reused_request_id_with_modified_booking_is_rejected(self) -> None:
        result = self.authorization()
        payload = self.payload(result)
        self.assertEqual(200, self.client.post("/v1/bookings", json=payload).status_code)
        payload["hotel"] = "Tampered Hotel"
        self.assertEqual(409, self.client.post("/v1/bookings", json=payload).status_code)

    def test_modified_amount_is_rejected(self) -> None:
        payload = self.payload(self.authorization())
        payload["amount"] = "4501"
        response = self.client.post("/v1/bookings", json=payload)
        self.assertEqual(409, response.status_code)
        self.assertIn("amount", response.json()["detail"])

    def test_wrong_reservation_is_rejected(self) -> None:
        payload = self.payload(self.authorization())
        payload["reservation_id"] = "res_wrong"
        response = self.client.post("/v1/bookings", json=payload)
        self.assertEqual(409, response.status_code)
        self.assertIn("reservation_id", response.json()["detail"])

    def test_request_agent_action_and_currency_are_bound(self) -> None:
        changes = {
            "request_id": "request-tampered",
            "agent_id": "attacker-agent",
            "action": "book_flight",
            "currency": "USD",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                payload = self.payload(self.authorization())
                payload[field] = value
                response = self.client.post("/v1/bookings", json=payload)
                self.assertEqual(409, response.status_code)
                self.assertIn(field, response.json()["detail"])

    def test_modified_lease_signature_is_rejected(self) -> None:
        payload = self.payload(self.authorization())
        token = str(payload["lease_token"])
        payload["lease_token"] = token[:-1] + ("A" if token[-1] != "A" else "B")
        response = self.client.post("/v1/bookings", json=payload)
        self.assertEqual(401, response.status_code)
        self.assertIn("signature", response.json()["detail"])

    def test_stale_lease_is_rejected(self) -> None:
        response = self.client.post(
            "/v1/bookings", json=self.payload(self.authorization(expired=True))
        )
        self.assertEqual(401, response.status_code)
        self.assertIn("expired", response.json()["detail"])

    def test_provider_timeout_releases_reservation(self) -> None:
        result = self.authorization()
        response = self.make_client(TimeoutProvider()).post(
            "/v1/bookings", json=self.payload(result)
        )
        self.assertEqual(504, response.status_code)
        self.assertEqual(
            "released",
            self.engine.get_reservation(result.reservation.reservation_id).status.value,
        )

    def test_timeout_storm_opens_circuit_and_fails_fast(self) -> None:
        provider = CountingTimeoutProvider()
        breaker = CircuitBreaker(failure_threshold=2, recovery_seconds=60)
        client = self.make_client(provider, breaker)

        for expected_status in (504, 504, 502):
            result = self.authorization()
            response = client.post("/v1/bookings", json=self.payload(result))
            self.assertEqual(expected_status, response.status_code)
            self.assertEqual(
                "released",
                self.engine.get_reservation(result.reservation.reservation_id).status.value,
            )

        self.assertEqual(2, provider.calls)
        self.assertEqual("open", breaker.state)

    def test_provider_500_releases_reservation(self) -> None:
        result = self.authorization()
        response = self.make_client(FailingProvider()).post(
            "/v1/bookings", json=self.payload(result)
        )
        self.assertEqual(502, response.status_code)
        self.assertEqual(
            "released",
            self.engine.get_reservation(result.reservation.reservation_id).status.value,
        )

    def test_fleet_stop_during_execution_prevents_commit(self) -> None:
        result = self.authorization()
        response = self.make_client(FleetStoppingProvider(self.engine)).post(
            "/v1/bookings", json=self.payload(result)
        )
        self.assertEqual(409, response.status_code)
        self.assertTrue(self.engine.fleet_stopped)
        self.assertEqual(
            "released",
            self.engine.get_reservation(result.reservation.reservation_id).status.value,
        )

    def test_connector_role_can_use_internal_commit_boundary(self) -> None:
        from intentguard.api import create_app
        from intentguard.auth import JwksAuthenticator
        from tests.jwt_test_support import AUDIENCE, ISSUER, JWKS, bearer

        result = self.authorization()
        gateway = TestClient(
            create_app(
                self.engine,
                authenticator=JwksAuthenticator(
                    issuer=ISSUER,
                    audience=AUDIENCE,
                    jwks=JWKS,
                    minimum_rsa_bits=512,
                ),
            )
        )
        response = gateway.post(
            f"/v1/connectors/reservations/{result.reservation.reservation_id}/commit",
            json={"lease_id": result.lease.lease_id},
            headers=bearer(subject="booking-connector", roles=["connector"]),
        )
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual("committed", response.json()["status"])


DATABASE_URL = os.getenv("INTENTGUARD_DATABASE_URL", "postgresql:///intentguard")


def postgres_connector_available() -> bool:
    try:
        import psycopg
        with psycopg.connect(DATABASE_URL, connect_timeout=3) as connection:
            connection.execute("SELECT 1 FROM lease_signing_keys LIMIT 1")
            connection.execute("SELECT 1 FROM connector_executions LIMIT 1")
        return True
    except Exception:
        return False


@unittest.skipUnless(
    postgres_connector_available(),
    "PostgreSQL protected-connector migration is unavailable",
)
class PostgresConnectorPersistenceTest(unittest.TestCase):
    def test_key_and_idempotent_result_survive_connector_restart(self) -> None:
        issuer = f"gateway-{uuid.uuid4().hex}"
        request_id = f"request-{uuid.uuid4().hex}"
        registry = PostgresLeaseKeyRegistry(DATABASE_URL)
        store = PostgresExecutionStore(DATABASE_URL)
        self.addCleanup(registry.close)
        self.addCleanup(store.close)
        registry.save(LeaseVerificationKey("key-1", issuer, "public-material"))
        self.assertEqual("public-material", registry.get(issuer, "key-1").public_key)
        self.assertEqual(("new", None), store.claim(request_id, "fingerprint"))
        store.complete(request_id, {"status": "booked"})

        restarted = PostgresExecutionStore(DATABASE_URL)
        self.addCleanup(restarted.close)
        self.assertEqual(
            ("cached", {"status": "booked"}),
            restarted.claim(request_id, "fingerprint"),
        )
        self.assertEqual(
            ("conflict", None),
            restarted.claim(request_id, "different"),
        )


if __name__ == "__main__":
    unittest.main()
