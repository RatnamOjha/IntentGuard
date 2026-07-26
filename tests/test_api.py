from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
