from __future__ import annotations

import unittest
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from fastapi.testclient import TestClient

from intentguard.abuse import (
    AbuseLimits,
    RateLimiterUnavailable,
    RedisSlidingWindowRateLimiter,
    SlidingWindowRateLimiter,
)
from intentguard.api import create_app
from intentguard.models import ActionRequest, AgentProfile, Decision, IntentPassport
from intentguard.policy_engine import PolicyEngine
from tests.test_api import admin_headers, test_authenticator


def limits(**overrides: int) -> AbuseLimits:
    values = {
        "window_seconds": 60,
        "agent_requests": 50,
        "customer_requests": 50,
        "operator_requests": 50,
        "connector_requests": 50,
        "max_request_body_bytes": 1_048_576,
        "max_outstanding_reservations": 20,
        "max_pending_approvals": 20,
        "max_audit_page_size": 200,
    }
    values.update(overrides)
    return AbuseLimits(**values)


class RateLimiterTest(unittest.TestCase):
    def test_sliding_window_recovers_after_the_window(self) -> None:
        now = [100.0]
        limiter = SlidingWindowRateLimiter(clock=lambda: now[0])

        self.assertTrue(
            limiter.consume(scope="agent", key="a", limit=1, window_seconds=10).allowed
        )
        refused = limiter.consume(scope="agent", key="a", limit=1, window_seconds=10)
        self.assertFalse(refused.allowed)
        self.assertEqual(10, refused.retry_after_seconds)
        now[0] += 10.01
        self.assertTrue(
            limiter.consume(scope="agent", key="a", limit=1, window_seconds=10).allowed
        )

    def test_redis_limiter_uses_one_atomic_script(self) -> None:
        calls: list[tuple[list[str], list[object]]] = []

        class FakeRedis:
            def register_script(self, script):  # noqa: ANN001, ANN201
                self.script = script

                def execute(*, keys, args):  # noqa: ANN001, ANN202
                    calls.append((keys, args))
                    return [1, 4, 0]

                return execute

        client = FakeRedis()
        limiter = RedisSlidingWindowRateLimiter(client)
        result = limiter.consume(
            scope="agent", key="travel-01", limit=5, window_seconds=60
        )

        self.assertTrue(result.allowed)
        self.assertEqual(4, result.remaining)
        self.assertEqual(["intentguard:rate:agent:travel-01"], calls[0][0])
        self.assertIn("ZREMRANGEBYSCORE", client.script)
        self.assertIn("ZADD", client.script)


class ApiAbuseControlTest(unittest.TestCase):
    def make_client(self, configured_limits: AbuseLimits) -> TestClient:
        client = TestClient(
            create_app(
                PolicyEngine(),
                authenticator=test_authenticator(),
                abuse_limits=configured_limits,
            )
        )
        client.headers.update(admin_headers())
        return client

    def seed(self, client: TestClient) -> None:
        now = datetime.now(timezone.utc)
        self.assertEqual(
            201,
            client.post(
                "/v1/agents",
                json={
                    "agent_id": "travel-01",
                    "name": "Travel Agent",
                    "allowed_actions": ["book_flight"],
                    "max_action_amount": "20000",
                    "daily_budget": "50000",
                },
            ).status_code,
        )
        self.assertEqual(
            201,
            client.post(
                "/v1/intents",
                json={
                    "intent_id": "intent-01",
                    "customer_id": "customer-01",
                    "agent_id": "travel-01",
                    "action": "book_flight",
                    "max_amount": "18000",
                    "currency": "INR",
                    "expires_at": (now + timedelta(hours=1)).isoformat(),
                    "required_attributes": {"refundable": True},
                },
            ).status_code,
        )

    @staticmethod
    def action(request_id: str) -> dict[str, object]:
        return {
            "request_id": request_id,
            "agent_id": "travel-01",
            "action": "book_flight",
            "amount": "1000",
            "currency": "INR",
            "intent_id": "intent-01",
            "risk_score": 10,
            "attributes": {"refundable": True},
        }

    def test_agent_customer_and_operator_limits_are_independent(self) -> None:
        client = self.make_client(
            limits(agent_requests=1, customer_requests=2, operator_requests=10)
        )
        self.seed(client)

        first_action = client.post("/v1/actions/authorize", json=self.action("rate-1"))
        second_action = client.post("/v1/actions/authorize", json=self.action("rate-2"))
        self.assertEqual(200, first_action.status_code)
        self.assertEqual(429, second_action.status_code)
        self.assertEqual("0", second_action.headers["X-RateLimit-Remaining"])
        self.assertIn("Retry-After", second_action.headers)

        message = {
            "message": "book a refundable flight for INR 1000",
            "customer_id": "customer-01",
            "agent_id": "travel-01",
        }
        self.assertEqual(200, client.post("/v1/agent/message", json=message).status_code)
        self.assertEqual(429, client.post("/v1/agent/message", json=message).status_code)

        self.assertEqual(200, client.get("/v1/fleet/status").status_code)

    def test_operator_limit_is_enforced(self) -> None:
        client = self.make_client(limits(operator_requests=1))
        self.assertEqual(200, client.get("/v1/fleet/status").status_code)
        self.assertEqual(429, client.get("/v1/fleet/status").status_code)

    def test_distributed_limiter_outage_fails_closed(self) -> None:
        class UnavailableLimiter:
            def consume(self, **kwargs):  # noqa: ANN003, ANN201
                raise RateLimiterUnavailable("redis unavailable")

        client = TestClient(
            create_app(
                PolicyEngine(),
                authenticator=test_authenticator(),
                abuse_limits=limits(),
                rate_limiter=UnavailableLimiter(),
            )
        )
        response = client.get("/v1/fleet/status", headers=admin_headers())
        self.assertEqual(503, response.status_code)
        self.assertIn("failed closed", response.json()["detail"])

    def test_oversized_body_is_rejected_before_authentication(self) -> None:
        client = self.make_client(limits(max_request_body_bytes=128))
        response = client.post(
            "/v1/agents",
            content=b"{" + b'"padding":"' + b"x" * 200 + b'"}',
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(413, response.status_code)

    def test_audit_events_are_cursor_paginated_and_bounded(self) -> None:
        client = self.make_client(limits(max_audit_page_size=2))
        self.seed(client)
        self.assertEqual(
            204,
            client.post("/v1/fleet/stop", json={"reason": "pagination seed"}).status_code,
        )

        first = client.get("/v1/audit/events", params={"limit": 2})
        self.assertEqual(200, first.status_code)
        self.assertEqual(2, len(first.json()))
        cursor = int(first.headers["X-Next-Sequence"])
        second = client.get(
            "/v1/audit/events", params={"limit": 2, "after_sequence": cursor}
        )
        self.assertEqual(200, second.status_code)
        self.assertTrue(all(event["sequence"] > cursor for event in second.json()))
        self.assertEqual(
            422, client.get("/v1/audit/events", params={"limit": 3}).status_code
        )

        retention = client.get("/v1/audit/retention")
        self.assertEqual("append_only_archive", retention.json()["mode"])
        self.assertFalse(retention.json()["automatic_deletion"])


class ResourceBoundTest(unittest.TestCase):
    def engine(self, **kwargs: int) -> tuple[PolicyEngine, datetime]:
        now = datetime(2026, 8, 29, 12, tzinfo=timezone.utc)
        engine = PolicyEngine(review_risk_threshold=70, **kwargs)
        engine.register_agent(
            AgentProfile(
                "travel-01", "Travel", frozenset({"book_flight"}),
                Decimal("20000"), Decimal("100000"),
            )
        )
        engine.register_intent(
            IntentPassport(
                "intent-01", "customer-01", "travel-01", "book_flight",
                Decimal("18000"), "INR", now + timedelta(hours=1),
                {"refundable": True},
            )
        )
        return engine, now

    @staticmethod
    def request(request_id: str, *, risk: int = 10) -> ActionRequest:
        return ActionRequest(
            request_id=request_id,
            agent_id="travel-01",
            customer_id="customer-01",
            action="book_flight",
            amount=Decimal("1000"),
            currency="INR",
            intent_id="intent-01",
            risk_score=risk,
            attributes={"refundable": True},
        )

    def test_outstanding_reservation_limit_fails_closed(self) -> None:
        engine, now = self.engine(max_outstanding_reservations=1)
        first = engine.authorize_action(self.request("hold-1"), now=now)
        second = engine.authorize_action(self.request("hold-2"), now=now)

        self.assertIsNotNone(first.reservation)
        self.assertEqual(Decision.DENY, second.decision.decision)
        self.assertIn(
            "OUTSTANDING_RESERVATION_LIMIT",
            {finding.code for finding in second.decision.findings},
        )

    def test_approval_queue_capacity_fails_closed(self) -> None:
        engine, now = self.engine(max_pending_approvals=1)
        first = engine.authorize_action(self.request("review-1", risk=90), now=now)
        second = engine.authorize_action(self.request("review-2", risk=90), now=now)

        self.assertEqual(Decision.REVIEW, first.decision.decision)
        self.assertEqual(Decision.DENY, second.decision.decision)
        self.assertIn(
            "APPROVAL_QUEUE_FULL",
            {finding.code for finding in second.decision.findings},
        )
        self.assertEqual(1, len(engine.list_approvals()))


if __name__ == "__main__":
    unittest.main()
