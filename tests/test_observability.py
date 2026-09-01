from __future__ import annotations

import json
import logging
import unittest
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from intentguard.api import create_app
from intentguard.booking_connector import create_connector_app
from intentguard.observability import JsonFormatter, install_observability
from intentguard.policy_engine import PolicyEngine
from tests.test_api import admin_headers, test_authenticator


class RequestObservabilityTest(unittest.TestCase):
    def test_correlation_and_w3c_trace_context_are_returned(self) -> None:
        app = FastAPI()
        install_observability(app, service_name="observability-test")

        @app.get("/probe")
        def probe() -> dict[str, bool]:
            return {"ok": True}

        trace_id = "1" * 32
        response = TestClient(app).get(
            "/probe",
            headers={
                "x-correlation-id": "portfolio-demo-17",
                "traceparent": f"00-{trace_id}-{'2' * 16}-01",
            },
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual("portfolio-demo-17", response.headers["x-correlation-id"])
        self.assertEqual(trace_id, response.headers["x-trace-id"])

    def test_json_formatter_emits_machine_readable_fields(self) -> None:
        record = logging.LogRecord(
            "intentguard.test", logging.INFO, __file__, 1,
            "request complete", (), None,
        )
        record.fields = {"status": 200, "latency_ms": 3.25}

        payload = json.loads(JsonFormatter().format(record))

        self.assertEqual("request complete", payload["message"])
        self.assertEqual(200, payload["status"])
        self.assertEqual(3.25, payload["latency_ms"])


class GovernanceMetricsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(
            create_app(PolicyEngine(), authenticator=test_authenticator())
        )
        self.client.headers.update(admin_headers())
        now = datetime.now(timezone.utc)
        self.assertEqual(
            201,
            self.client.post(
                "/v1/agents",
                json={
                    "agent_id": "travel-01",
                    "name": "Travel Agent",
                    "allowed_actions": ["book_flight"],
                    "max_action_amount": "20000",
                    "daily_budget": "30000",
                },
            ).status_code,
        )
        self.assertEqual(
            201,
            self.client.post(
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

    def test_authorization_and_llm_metrics_are_scrapeable(self) -> None:
        authorization = self.client.post(
            "/v1/actions/authorize",
            json={
                "request_id": "observed-request",
                "agent_id": "travel-01",
                "action": "book_flight",
                "amount": "15000",
                "currency": "INR",
                "intent_id": "intent-01",
                "risk_score": 20,
                "attributes": {"refundable": True},
            },
            headers={**admin_headers(), "x-correlation-id": "authorization-17"},
        )
        self.assertEqual(200, authorization.status_code)
        self.assertEqual(
            "authorization-17", authorization.headers["x-correlation-id"]
        )

        message = self.client.post(
            "/v1/agent/message",
            json={
                "message": "book a refundable flight for INR 12000",
                "customer_id": "customer-01",
                "agent_id": "travel-01",
            },
        )
        self.assertEqual(200, message.status_code)

        metrics = self.client.get("/metrics").text
        self.assertIn(
            'intentguard_authorization_requests_total{decision="allow"} 2.0',
            metrics,
        )
        self.assertIn("intentguard_policy_evaluation_duration_seconds_count 2.0", metrics)
        self.assertIn(
            'intentguard_llm_duration_seconds_count{model="scripted-v2",provider="deterministic",status="proposal"}',
            metrics,
        )
        self.assertNotIn("customer-01", metrics)
        self.assertNotIn("observed-request", metrics)


class ConnectorMetricsTest(unittest.TestCase):
    def test_connector_rejection_is_counted(self) -> None:
        client = TestClient(create_connector_app(object()))  # type: ignore[arg-type]
        response = client.post(
            "/v1/bookings",
            json={
                "request_id": "connector-observed",
                "reservation_id": "res-observed",
                "agent_id": "travel-01",
                "customer_id": "customer-01",
                "hotel": "Safe Hotel",
                "amount": "1000",
                "currency": "INR",
                "refundable": True,
            },
        )
        self.assertEqual(401, response.status_code)

        metrics = client.get("/metrics").text
        self.assertIn(
            'intentguard_connector_failures_total{reason="missing_lease"} 1.0',
            metrics,
        )
        self.assertNotIn("connector-observed", metrics)


if __name__ == "__main__":
    unittest.main()
