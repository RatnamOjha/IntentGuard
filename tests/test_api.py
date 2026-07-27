from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

try:
    from fastapi.testclient import TestClient
except ImportError:  # Allows domain-only test runs before API extras are installed.
    TestClient = None

from intentguard import PolicyEngine  # noqa: E402


@unittest.skipIf(TestClient is None, "Install the api and dev extras to test FastAPI")
class ApiTest(unittest.TestCase):
    def setUp(self) -> None:
        from intentguard.api import create_app

        self.client = TestClient(create_app(PolicyEngine()))
        self.now = datetime.now(timezone.utc)
        agent_response = self.client.post(
            "/v1/agents",
            json={
                "agent_id": "travel-01",
                "name": "Travel Agent",
                "allowed_actions": ["book_flight"],
                "max_action_amount": "20000",
                "daily_budget": "30000",
            },
        )
        self.assertEqual(201, agent_response.status_code)
        intent_response = self.client.post(
            "/v1/intents",
            json={
                "intent_id": "intent-01",
                "customer_id": "customer-01",
                "agent_id": "travel-01",
                "action": "book_flight",
                "max_amount": "18000",
                "currency": "INR",
                "expires_at": (self.now + timedelta(hours=1)).isoformat(),
                "required_attributes": {"refundable": True},
            },
        )
        self.assertEqual(201, intent_response.status_code)

    def action(self, request_id: str = "request-01") -> dict[str, object]:
        return {
            "request_id": request_id,
            "agent_id": "travel-01",
            "action": "book_flight",
            "amount": "15000",
            "currency": "INR",
            "intent_id": "intent-01",
            "risk_score": 20,
            "attributes": {"refundable": True},
        }

    def test_authorize_and_commit_flow(self) -> None:
        authorization = self.client.post(
            "/v1/actions/authorize", json=self.action()
        )
        self.assertEqual(200, authorization.status_code)
        body = authorization.json()
        self.assertEqual("allow", body["decision"]["decision"])
        self.assertEqual("held", body["reservation"]["status"])

        committed = self.client.post(
            f"/v1/reservations/{body['reservation']['reservation_id']}/commit",
            json={"lease_id": body["lease"]["lease_id"]},
        )
        self.assertEqual(200, committed.status_code)
        self.assertEqual("committed", committed.json()["status"])

    def test_fleet_stop_blocks_authorization(self) -> None:
        stopped = self.client.post(
            "/v1/fleet/stop", json={"reason": "incident drill"}
        )
        self.assertEqual(204, stopped.status_code)

        authorization = self.client.post(
            "/v1/actions/authorize", json=self.action("request-after-stop")
        )
        self.assertEqual("deny", authorization.json()["decision"]["decision"])
        status_response = self.client.get("/v1/fleet/status")
        self.assertTrue(status_response.json()["stopped"])
        self.assertEqual(1, status_response.json()["fleet_epoch"])

    def test_audit_events_are_exposed(self) -> None:
        self.client.post("/v1/actions/authorize", json=self.action())
        response = self.client.get("/v1/audit/events")
        self.assertEqual(200, response.status_code)
        event_types = {event["event_type"] for event in response.json()}
        self.assertIn("policy.evaluated", event_types)
        self.assertIn("budget.reserved", event_types)
        self.assertIn("gateway.authorization.completed", event_types)

        status_response = self.client.get("/v1/audit/status")
        self.assertTrue(status_response.json()["verified"])
        self.assertGreater(status_response.json()["event_count"], 0)

    def test_human_review_can_be_approved_and_committed(self) -> None:
        payload = self.action("request-review")
        payload["risk_score"] = 85
        authorization = self.client.post(
            "/v1/actions/authorize",
            json=payload,
        )
        self.assertEqual("review", authorization.json()["decision"]["decision"])

        approvals = self.client.get("/v1/approvals").json()
        self.assertEqual("pending", approvals[0]["status"])
        approved = self.client.post(
            "/v1/approvals/request-review/approve",
            json={
                "reviewer": "Ratnam Ojha",
                "reason": "Verified with the card member",
            },
        )
        self.assertEqual(200, approved.status_code)
        approved_body = approved.json()
        self.assertEqual("allow", approved_body["decision"]["decision"])
        self.assertEqual("held", approved_body["reservation"]["status"])

        committed = self.client.post(
            (
                f"/v1/reservations/"
                f"{approved_body['reservation']['reservation_id']}/commit"
            ),
            json={"lease_id": approved_body["lease"]["lease_id"]},
        )
        self.assertEqual("committed", committed.json()["status"])

    def test_human_review_can_be_rejected(self) -> None:
        payload = self.action("request-rejected")
        payload["risk_score"] = 85
        self.client.post("/v1/actions/authorize", json=payload)

        rejected = self.client.post(
            "/v1/approvals/request-rejected/reject",
            json={
                "reviewer": "Ratnam Ojha",
                "reason": "Card member denied the request",
            },
        )
        self.assertEqual(200, rejected.status_code)
        self.assertEqual("rejected", rejected.json()["status"])

    def test_demo_bootstrap_is_idempotent_and_exposes_agents(self) -> None:
        from intentguard.api import create_app

        demo_client = TestClient(create_app(PolicyEngine()))
        first = demo_client.post("/v1/demo/bootstrap")
        second = demo_client.post("/v1/demo/bootstrap")

        self.assertEqual(200, first.status_code)
        self.assertEqual(3, len(first.json()["agents"]))
        self.assertEqual(
            first.json()["agents"],
            second.json()["agents"],
        )
        agents = demo_client.get("/v1/agents").json()
        self.assertEqual(
            {"Atlas", "Nova", "Orbit"},
            {agent["name"] for agent in agents},
        )

    def test_agent_can_be_revoked_and_restored(self) -> None:
        revoked = self.client.post("/v1/agents/travel-01/revoke")
        self.assertEqual(204, revoked.status_code)
        denied = self.client.post(
            "/v1/actions/authorize", json=self.action("request-revoked")
        )
        self.assertEqual("deny", denied.json()["decision"]["decision"])

        restored = self.client.post("/v1/agents/travel-01/restore")
        self.assertEqual(204, restored.status_code)
        allowed = self.client.post(
            "/v1/actions/authorize", json=self.action("request-restored")
        )
        self.assertEqual("allow", allowed.json()["decision"]["decision"])

        events = self.client.get("/v1/audit/events").json()
        self.assertIn("agent.restored", {event["event_type"] for event in events})

    def test_restore_unknown_agent_returns_not_found(self) -> None:
        response = self.client.post("/v1/agents/unknown-agent/restore")
        self.assertEqual(404, response.status_code)

    def test_default_cors_allows_vinext_dashboard(self) -> None:
        for origin in (
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:3001",
            "http://127.0.0.1:3001",
        ):
            with self.subTest(origin=origin):
                response = self.client.options(
                    "/health",
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "GET",
                    },
                )
                self.assertEqual(200, response.status_code)
                self.assertEqual(
                    origin,
                    response.headers["access-control-allow-origin"],
                )

    def test_cors_origins_can_be_configured(self) -> None:
        from intentguard.api import create_app

        with patch.dict(
            "os.environ",
            {"INTENTGUARD_CORS_ORIGINS": "https://console.example.test"},
        ):
            client = TestClient(create_app(PolicyEngine()))
        response = client.options(
            "/health",
            headers={
                "Origin": "https://console.example.test",
                "Access-Control-Request-Method": "GET",
            },
        )
        self.assertEqual(200, response.status_code)
        self.assertEqual(
            "https://console.example.test",
            response.headers["access-control-allow-origin"],
        )


if __name__ == "__main__":
    unittest.main()
