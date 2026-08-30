from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

try:
    from fastapi.testclient import TestClient
except ImportError:
    TestClient = None

from intentguard import AgentProfile, IntentPassport, PolicyEngine  # noqa: E402
from intentguard.auth import JwksAuthenticator  # noqa: E402
from tests.jwt_test_support import (  # noqa: E402
    AUDIENCE,
    ISSUER,
    JWKS,
    bearer,
    token,
)


@unittest.skipIf(TestClient is None, "Install the api and dev extras to test FastAPI")
class AuthenticatedApiTest(unittest.TestCase):
    def setUp(self) -> None:
        from intentguard.api import create_app

        self.engine = PolicyEngine()
        self.engine.register_agent(
            AgentProfile(
                agent_id="travel-01",
                name="Travel Agent",
                allowed_actions=frozenset({"book_flight"}),
                max_action_amount=Decimal("20000"),
                daily_budget=Decimal("30000"),
            )
        )
        self.engine.register_intent(
            IntentPassport(
                intent_id="intent-01",
                customer_id="customer-01",
                agent_id="travel-01",
                action="book_flight",
                max_amount=Decimal("18000"),
                currency="INR",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                required_attributes={"refundable": True},
            )
        )
        auth = JwksAuthenticator(
            issuer=ISSUER,
            audience=AUDIENCE,
            jwks=JWKS,
            minimum_rsa_bits=512,
        )
        self.client = TestClient(create_app(self.engine, authenticator=auth))

    @staticmethod
    def action(request_id: str = "request-01", **changes: object) -> dict:
        value = {
            "request_id": request_id,
            "agent_id": "travel-01",
            "customer_id": "customer-01",
            "action": "book_flight",
            "amount": "15000",
            "currency": "INR",
            "intent_id": "intent-01",
            "risk_score": 20,
            "attributes": {"refundable": True},
        }
        value.update(changes)
        return value

    @staticmethod
    def agent_headers(*, subject: str = "agent-user", roles=None) -> dict[str, str]:
        return bearer(
            subject=subject,
            roles=roles or ["agent"],
            agent_id="travel-01",
            customer_id="customer-01",
        )

    def test_missing_token(self) -> None:
        response = self.client.post("/v1/actions/authorize", json=self.action())
        self.assertEqual(401, response.status_code)
        self.assertEqual("Bearer", response.headers["www-authenticate"])

    def test_invalid_signature(self) -> None:
        encoded = token(roles=["agent"], agent_id="travel-01")
        response = self.client.post(
            "/v1/actions/authorize",
            json=self.action(),
            headers={"Authorization": "Bearer " + encoded[:-8] + "AAAAAAAA"},
        )
        self.assertEqual(401, response.status_code)

    def test_expired_token(self) -> None:
        headers = bearer(
            roles=["agent"],
            agent_id="travel-01",
            customer_id="customer-01",
            expires_delta=timedelta(seconds=-1),
        )
        response = self.client.post(
            "/v1/actions/authorize", json=self.action(), headers=headers
        )
        self.assertEqual(401, response.status_code)

    def test_wrong_role(self) -> None:
        response = self.client.post(
            "/v1/actions/authorize",
            json=self.action(),
            headers=bearer(
                roles=["customer"],
                agent_id="travel-01",
                customer_id="customer-01",
            ),
        )
        self.assertEqual(403, response.status_code)

    def test_agent_impersonation(self) -> None:
        response = self.client.post(
            "/v1/actions/authorize",
            json=self.action(agent_id="payments-02"),
            headers=self.agent_headers(),
        )
        self.assertEqual(403, response.status_code)

    def test_customer_impersonation(self) -> None:
        response = self.client.post(
            "/v1/intents",
            headers=bearer(
                subject="customer-user",
                roles=["customer"],
                customer_id="customer-01",
            ),
            json={
                "intent_id": "forged-intent",
                "customer_id": "victim-customer",
                "agent_id": "travel-01",
                "action": "book_flight",
                "max_amount": "1000",
                "currency": "INR",
                "expires_at": (
                    datetime.now(timezone.utc) + timedelta(hours=1)
                ).isoformat(),
            },
        )
        self.assertEqual(403, response.status_code)

    def test_reviewer_cannot_approve_own_request(self) -> None:
        headers = self.agent_headers(
            subject="dual-role-user", roles=["agent", "reviewer"]
        )
        payload = self.action("reviewer-own-request", risk_score=85)
        created = self.client.post(
            "/v1/actions/authorize", json=payload, headers=headers
        )
        self.assertEqual("review", created.json()["decision"]["decision"])

        approved = self.client.post(
            "/v1/approvals/reviewer-own-request/approve",
            json={"reviewer": "forged-reviewer", "reason": "self approval"},
            headers=headers,
        )
        self.assertEqual(409, approved.status_code)
        self.assertIn("own request", approved.json()["detail"])

    def test_operator_cannot_approve_request_they_created(self) -> None:
        headers = self.agent_headers(
            subject="operator-user", roles=["agent", "operator", "reviewer"]
        )
        self.client.post(
            "/v1/actions/authorize",
            json=self.action("operator-own-request", risk_score=85),
            headers=headers,
        )
        response = self.client.post(
            "/v1/approvals/operator-own-request/approve",
            json={"reason": "operator self approval"},
            headers=headers,
        )
        self.assertEqual(409, response.status_code)

    def test_operator_identity_comes_from_verified_claim(self) -> None:
        response = self.client.put(
            "/v1/agents/travel-01/policy",
            headers=bearer(subject="verified-operator", roles=["operator"]),
            json={
                "allowed_actions": ["book_flight", "book_hotel"],
                "max_action_amount": "20000",
                "daily_budget": "30000",
                "active": True,
                "operator": "forged-operator",
                "reason": "expand travel policy",
            },
        )
        self.assertEqual(200, response.status_code)
        event = next(
            item
            for item in reversed(self.engine.audit_ledger.events)
            if item.event_type == "policy.updated"
        )
        self.assertEqual("verified-operator", event.payload["operator"])


if __name__ == "__main__":
    unittest.main()
