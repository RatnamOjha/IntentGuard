from __future__ import annotations

import sys
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from intentguard import ActionRequest, AgentProfile, Decision, IntentPassport, PolicyEngine
from intentguard.auth import JwksAuthenticator
from intentguard.policy import (
    InMemoryPolicyRepository,
    OpaCliPolicyEvaluator,
    PolicyService,
    PolicyEvaluationError,
    PolicyVersion,
    PostgresPolicyRepository,
    find_opa_executable,
    initial_policy,
)
from tests.jwt_test_support import AUDIENCE, ISSUER, JWKS, bearer


OPA = find_opa_executable()
NOW = datetime(2026, 8, 28, 12, tzinfo=timezone.utc)


def policy_input(**request_changes: object) -> dict:
    request = {
        "request_id": "dry-run-1",
        "agent_id": "travel-01",
        "action": "book_hotel",
        "amount": 4500,
        "currency": "INR",
        "customer_id": "customer-01",
        "attributes": {"refundable": True},
    }
    request.update(request_changes)
    return {
        "fleet_stopped": False,
        "request": request,
        "agent": {
            "known": True,
            "active": True,
            "revoked": False,
            "allowed_actions": ["book_hotel"],
            "max_action_amount": 20000,
            "remaining_daily_budget": 30000,
        },
        "intent": {
            "known": True,
            "agent_id": "travel-01",
            "action": "book_hotel",
            "customer_id": "customer-01",
            "currency": "INR",
            "max_amount": 18000,
            "expired": False,
            "required_attributes": {"refundable": True},
        },
        "risk": {"declared": 10, "derived": 10, "effective": 10, "under_declared": False},
        "config": {
            "review_risk_threshold": 70,
            "large_booking_threshold": 10000,
            "review_merchant_categories": ["cash_equivalent", "restricted_travel"],
        },
    }


@unittest.skipUnless(OPA, "OPA CLI is unavailable")
class PolicyAsCodeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = InMemoryPolicyRepository(initial_policy())
        self.evaluator = OpaCliPolicyEvaluator(OPA, self.repository)
        self.service = PolicyService(self.evaluator)
        self.engine = PolicyEngine(policy_evaluator=self.evaluator, review_risk_threshold=70)
        self.engine.register_agent(
            AgentProfile("travel-01", "Travel", frozenset({"book_hotel"}), Decimal("20000"), Decimal("30000"))
        )
        self.engine.register_intent(
            IntentPassport(
                "intent-01", "customer-01", "travel-01", "book_hotel",
                Decimal("18000"), "INR", NOW + timedelta(hours=1),
                {"refundable": True},
            )
        )

    def request(self, *, amount: str = "4500", risk: int = 10, refundable: bool = True, request_id: str = "request-1") -> ActionRequest:
        return ActionRequest(request_id, "travel-01", "book_hotel", Decimal(amount), "INR", "intent-01", risk, {"refundable": refundable}, "customer-01", occurred_at=NOW)

    def test_required_policy_matrix(self) -> None:
        cases = [
            ("refundable-under-limit", self.request(), Decision.ALLOW),
            ("non-refundable-without-consent", self.request(refundable=False), Decision.DENY),
            ("over-intent-limit", self.request(amount="19000"), Decision.DENY),
            ("high-risk", self.request(risk=90), Decision.REVIEW),
        ]
        for name, request, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(expected, self.engine.evaluate(request, now=NOW).decision)

        self.engine.revoke_agent("travel-01")
        self.assertEqual(Decision.DENY, self.engine.evaluate(self.request(), now=NOW).decision)
        self.engine.restore_agent("travel-01")
        self.engine.stop_fleet(reason="matrix")
        self.assertEqual(Decision.DENY, self.engine.evaluate(self.request(), now=NOW).decision)

    def test_large_booking_and_merchant_category_require_review(self) -> None:
        self.assertEqual(Decision.REVIEW, self.engine.evaluate(self.request(amount="11000"), now=NOW).decision)
        value = policy_input(attributes={"refundable": True, "merchant_category": "cash_equivalent"})
        self.assertEqual(Decision.REVIEW, self.evaluator.evaluate_source(initial_policy().source, value).decision)

    def test_validate_dry_run_publish_compare_and_rollback(self) -> None:
        source = initial_policy().source.replace('"large_booking_threshold": 10000', '"large_booking_threshold": 10000')
        # Change the input-driven threshold reference into a fixed stricter rule.
        source = source.replace("input.config.large_booking_threshold", "1000")
        draft = self.service.create_draft(source, created_by="operator-1", description="Review bookings from 1,000")
        self.assertEqual("draft", draft.status)
        self.assertEqual(Decision.REVIEW, self.evaluator.evaluate_source(source, policy_input()).decision)
        comparison = self.service.compare("rego-1", draft.version_id, [policy_input()])
        self.assertEqual(1, comparison["changed"])
        self.assertEqual("published", self.service.publish(draft.version_id).status)
        self.assertEqual(Decision.REVIEW, self.evaluator.evaluate(policy_input()).decision)
        self.assertEqual("published", self.service.rollback("rego-1").status)
        self.assertEqual(Decision.ALLOW, self.evaluator.evaluate(policy_input()).decision)

    def test_invalid_rego_is_rejected_without_changing_active_policy(self) -> None:
        with self.assertRaises(ValueError):
            self.service.create_draft("package broken\nallow if {", created_by="operator", description="bad")
        self.assertEqual("rego-1", self.repository.active().version_id)

    def test_opa_outage_fails_closed_before_budget_reservation(self) -> None:
        unavailable = OpaCliPolicyEvaluator("missing-opa-executable", InMemoryPolicyRepository(initial_policy()))
        engine = PolicyEngine(policy_evaluator=unavailable)
        engine.register_agent(AgentProfile("travel-01", "Travel", frozenset({"book_hotel"}), Decimal("20000"), Decimal("30000")))
        engine.register_intent(IntentPassport("intent-01", "customer-01", "travel-01", "book_hotel", Decimal("18000"), "INR", NOW + timedelta(hours=1)))
        with self.assertRaises(PolicyEvaluationError):
            engine.authorize_action(self.request(), now=NOW)
        self.assertEqual(Decimal("0"), engine.budget_ledger.exposure("travel-01", NOW.date()).reserved)


@unittest.skipUnless(OPA, "OPA CLI is unavailable")
class PolicyApiTest(unittest.TestCase):
    def test_operator_policy_lifecycle_endpoints(self) -> None:
        try:
            from fastapi.testclient import TestClient
            from intentguard.api import create_app
        except ImportError:
            self.skipTest("API extras unavailable")
        repository = InMemoryPolicyRepository(initial_policy())
        engine = PolicyEngine(policy_evaluator=OpaCliPolicyEvaluator(OPA, repository))
        auth = JwksAuthenticator(issuer=ISSUER, audience=AUDIENCE, jwks=JWKS, minimum_rsa_bits=512)
        client = TestClient(create_app(engine, authenticator=auth))
        headers = bearer(subject="operator-1", roles=["operator"])
        versions = client.get("/v1/policies", headers=headers)
        self.assertEqual(200, versions.status_code)
        source = initial_policy().source.replace("input.config.large_booking_threshold", "1000")
        draft = client.post("/v1/policies/drafts", headers=headers, json={"source": source, "description": "stricter review"})
        self.assertEqual(201, draft.status_code, draft.text)
        published = client.post(f"/v1/policies/{draft.json()['version_id']}/publish", headers=headers)
        self.assertEqual(200, published.status_code)
        rolled_back = client.post("/v1/policies/rego-1/rollback", headers=headers)
        self.assertEqual(200, rolled_back.status_code)


DATABASE_URL = os.getenv("INTENTGUARD_DATABASE_URL", "postgresql:///intentguard")


def postgres_policy_available() -> bool:
    try:
        import psycopg
        with psycopg.connect(DATABASE_URL, connect_timeout=3) as connection:
            connection.execute("SELECT 1 FROM policy_versions LIMIT 1")
        return True
    except Exception:
        return False


@unittest.skipUnless(postgres_policy_available(), "PostgreSQL policy migration is unavailable")
class PostgresPolicyRepositoryTest(unittest.TestCase):
    def test_draft_survives_repository_reconstruction(self) -> None:
        version_id = f"rego-test-{uuid.uuid4().hex}"
        first = PostgresPolicyRepository(DATABASE_URL)
        try:
            first.save(
                PolicyVersion(
                    version_id,
                    initial_policy().source,
                    "draft",
                    datetime.now(timezone.utc),
                    "integration-test",
                    "restart persistence",
                )
            )
        finally:
            first.close()
        restarted = PostgresPolicyRepository(DATABASE_URL)
        try:
            restored = restarted.get(version_id)
            self.assertIsNotNone(restored)
            self.assertEqual("draft", restored.status)
            self.assertEqual(initial_policy().source, restored.source)
        finally:
            restarted.close()


if __name__ == "__main__":
    unittest.main()
