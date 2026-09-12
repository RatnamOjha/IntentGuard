from __future__ import annotations

import os
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
from intentguard.auth import JwksAuthenticator  # noqa: E402
from tests.jwt_test_support import (  # noqa: E402
    AUDIENCE,
    ISSUER,
    JWKS,
    bearer,
)


def test_authenticator() -> JwksAuthenticator:
    return JwksAuthenticator(
        issuer=ISSUER, audience=AUDIENCE, jwks=JWKS, minimum_rsa_bits=512
    )


def admin_headers(
    *, customer_id: str = "customer-01", agent_id: str = "travel-01"
) -> dict[str, str]:
    return bearer(
        subject="api-test-admin",
        roles=["admin"],
        customer_id=customer_id,
        agent_id=agent_id,
    )


@unittest.skipIf(TestClient is None, "Install the api and dev extras to test FastAPI")
class ApiTest(unittest.TestCase):
    def setUp(self) -> None:
        from intentguard.api import create_app

        self.client = TestClient(
            create_app(PolicyEngine(), authenticator=test_authenticator())
        )
        self.client.headers.update(admin_headers())
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

    def test_container_health_endpoints_are_public_and_describe_dependencies(self) -> None:
        # /health/ready reports its backing services from the environment, so
        # the environment has to be pinned here. Inheriting it made this fail
        # for anyone with INTENTGUARD_DATABASE_URL exported -- which is exactly
        # what the README tells you to do for local Postgres runs.
        with patch.dict(
            os.environ,
            {"INTENTGUARD_DATABASE_URL": "", "INTENTGUARD_REDIS_URL": ""},
            clear=False,
        ):
            os.environ.pop("INTENTGUARD_DATABASE_URL", None)
            os.environ.pop("INTENTGUARD_REDIS_URL", None)
            live = self.client.get("/health/live", headers={"Authorization": ""})
            ready = self.client.get("/health/ready", headers={"Authorization": ""})

            self.assertEqual({"status": "ok"}, live.json())
            self.assertEqual(200, ready.status_code)
            self.assertEqual("ready", ready.json()["status"])
            self.assertEqual("memory", ready.json()["database"])
            self.assertEqual("memory", ready.json()["rate_limiter"])

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

    def test_stale_lease_is_rejected_and_audited(self) -> None:
        authorization = self.client.post(
            "/v1/actions/authorize",
            json=self.action("request-stale-lease"),
        ).json()
        self.client.post(
            "/v1/fleet/stop",
            json={"reason": "Stale lease demonstration"},
        )

        rejected = self.client.post(
            (
                f"/v1/reservations/"
                f"{authorization['reservation']['reservation_id']}/commit"
            ),
            json={"lease_id": authorization["lease"]["lease_id"]},
        )

        self.assertEqual(409, rejected.status_code)
        self.assertIn("fleet stop", rejected.json()["detail"])
        events = self.client.get("/v1/audit/events").json()
        connector_event = next(
            event
            for event in reversed(events)
            if event["event_type"] == "connector.execution.rejected"
        )
        self.assertEqual(
            "request-stale-lease",
            connector_event["payload"]["request_id"],
        )

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
                "reviewer": "Demo Operator",
                "reason": "Verified with the card member",
            },
            headers=bearer(subject="reviewer-01", roles=["reviewer"]),
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
                "reviewer": "Demo Operator",
                "reason": "Card member denied the request",
            },
            headers=bearer(subject="reviewer-01", roles=["reviewer"]),
        )
        self.assertEqual(200, rejected.status_code)
        self.assertEqual("rejected", rejected.json()["status"])

    def test_demo_bootstrap_is_idempotent_and_exposes_agents(self) -> None:
        from intentguard.api import create_app

        demo_client = TestClient(
            create_app(PolicyEngine(), authenticator=test_authenticator())
        )
        demo_client.headers.update(
            admin_headers(customer_id="demo-customer", agent_id="agt_refund_01")
        )
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
            {"Ada", "Bo", "Cy"},
            {agent["name"] for agent in agents},
        )

    def test_operator_can_update_agent_policy(self) -> None:
        response = self.client.put(
            "/v1/agents/travel-01/policy",
            json={
                "allowed_actions": ["book_flight", "book_hotel"],
                "max_action_amount": "25000",
                "daily_budget": "40000",
                "active": True,
                "operator": "Demo Operator",
                "reason": "Expand the travel pilot",
            },
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual("2026.07.r1", response.json()["policy_version"])
        self.assertIn(
            "book_hotel",
            response.json()["agent"]["allowed_actions"],
        )

    def test_demo_benchmark_returns_measured_evidence(self) -> None:
        response = self.client.get("/v1/demo/benchmark")

        self.assertEqual(200, response.status_code)
        body = response.json()
        self.assertGreaterEqual(body["acceptance"]["total"], 20)
        self.assertEqual(
            body["acceptance"]["total"],
            body["acceptance"]["passed"],
        )
        self.assertEqual(0, body["acceptance"]["failed"])
        self.assertEqual(
            "in_process_policy_engine",
            body["engine_latency_ms"]["scope"],
        )
        self.assertEqual(0, body["concurrency"]["overspend_violations"])
        self.assertTrue(body["audit_chain_verified"])

    def test_authorization_probe_uses_isolated_full_policy_path(self) -> None:
        response = self.client.post(
            "/v1/demo/benchmark/authorize-probe",
            json={"request_id": "api-probe-01"},
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual("allow", response.json()["decision"])
        self.assertGreaterEqual(response.json()["server_processing_ms"], 0)
        agent_ids = {
            agent["agent_id"] for agent in self.client.get("/v1/agents").json()
        }
        self.assertEqual({"travel-01"}, agent_ids)
        self.assertNotIn("benchmark-agent", agent_ids)

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
            client = TestClient(
                create_app(PolicyEngine(), authenticator=test_authenticator())
            )
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


@unittest.skipIf(TestClient is None, "Install the api and dev extras to test FastAPI")
class AgentEndpointTest(unittest.TestCase):
    """The agent endpoint, pinned to the scripted planner so it never calls out."""

    def setUp(self) -> None:
        from intentguard.agent import GovernedAgent, ScriptedPlanner
        from intentguard.api import create_app

        self.engine = PolicyEngine()
        app = create_app(self.engine, authenticator=test_authenticator())
        # A developer with a key exported must not make this suite hit the
        # network, so the planner is replaced rather than inherited.
        app.state.agent = GovernedAgent(self.engine, planner=ScriptedPlanner())
        self.client = TestClient(app)
        self.client.headers.update(
            admin_headers(customer_id="demo-customer", agent_id="agt_refund_01")
        )
        self.client.post("/v1/demo/bootstrap")

    def _say(self, message: str, customer_id: str = "demo-customer") -> dict:
        response = self.client.post(
            "/v1/agent/message",
            json={
                "message": message,
                "customer_id": customer_id,
                "agent_id": "agt_refund_01",
            },
        )
        self.assertEqual(200, response.status_code)
        return response.json()

    def test_a_compliant_request_is_allowed(self) -> None:
        body = self._say("issue a refund for 380")

        self.assertEqual("allow", body["decision"])
        self.assertEqual("scripted", body["planner"])
        self.assertIsNotNone(body["authorization"]["lease"])
        self.assertEqual("scripted-v2", body["trace"]["model"])
        self.assertEqual("scripted-rules-v2", body["trace"]["prompt_version"])
        self.assertNotIn("refundable hotel", str(body["trace"]))

    def test_an_out_of_policy_request_is_refused_with_reasons(self) -> None:
        body = self._say("issue a refund for 4200")

        self.assertEqual("deny", body["decision"])
        self.assertTrue(body["blocked_reasons"])
        self.assertIsNone(body["authorization"]["lease"])

    def test_intents_are_scoped_to_the_requesting_customer(self) -> None:
        response = self.client.get(
            "/v1/agent/intents",
            params={"customer_id": "someone-else", "agent_id": "agt_refund_01"},
        )

        self.assertEqual(403, response.status_code)

    def test_refusals_reach_the_audit_trail(self) -> None:
        self._say("issue a refund for 4200")

        status = self.client.get("/v1/audit/status").json()
        self.assertTrue(status["verified"])


if __name__ == "__main__":
    unittest.main()


class ClaimOverHttpTest(unittest.TestCase):
    """The claim has to survive the HTTP boundary, and be refused if malformed."""

    def setUp(self) -> None:
        from intentguard.api import create_app

        self.client = TestClient(
            create_app(PolicyEngine(), authenticator=test_authenticator())
        )
        # The token names the one agent it may act for, so it has to name Ada.
        self.client.headers.update(admin_headers(agent_id="ada"))
        self.now = datetime.now(timezone.utc)
        self.client.post(
            "/v1/agents",
            json={
                "agent_id": "ada",
                "name": "Ada",
                "allowed_actions": ["refund_order"],
                "max_action_amount": "5000",
                "daily_budget": "50000",
            },
        )
        self.client.post(
            "/v1/intents",
            json={
                "intent_id": "intent-refund",
                "customer_id": "customer-01",
                "agent_id": "ada",
                "action": "refund_order",
                "max_amount": "5000",
                "currency": "INR",
                "expires_at": (self.now + timedelta(hours=1)).isoformat(),
            },
        )

    def action(self, request_id: str, claim: dict | None) -> dict:
        body: dict = {
            "request_id": request_id,
            "agent_id": "ada",
            "action": "refund_order",
            "amount": "4200",
            "currency": "INR",
            "intent_id": "intent-refund",
            "risk_score": 10,
        }
        if claim is not None:
            body["claim"] = claim
        return body

    def post(self, request_id: str, claim: dict | None):
        return self.client.post(
            "/v1/actions/authorize", json=self.action(request_id, claim)
        )

    def test_a_claim_with_evidence_earns_the_full_refund(self) -> None:
        response = self.post(
            "claim-ok",
            {
                "reason": "defect",
                "order_value": "4200",
                "days_since_delivery": 2,
                "order_reference": "ORD-4418",
                "artifacts": [{"kind": "photo", "reference": "img-991"}],
                "complaint": "Arrived smashed, the box was crushed.",
            },
        )
        self.assertEqual(200, response.status_code)
        decision = response.json()["decision"]
        self.assertEqual("allow", decision["decision"])
        self.assertEqual("refund_to_source", decision["remedy"]["kind"])

    def test_the_same_claim_without_evidence_is_refused_with_the_alternative(
        self,
    ) -> None:
        """The refusal has to carry what would have passed, or it teaches nothing."""

        response = self.post(
            "claim-bare",
            {
                "reason": "defect",
                "order_value": "4200",
                "days_since_delivery": 2,
                "order_reference": "ORD-4419",
                "artifacts": [],
            },
        )
        self.assertEqual(200, response.status_code)
        decision = response.json()["decision"]
        self.assertEqual("deny", decision["decision"])
        self.assertIn(
            "REMEDY_NOT_PERMITTED",
            [finding["code"] for finding in decision["findings"]],
        )
        self.assertEqual("shipping_refund", decision["remedy"]["kind"])

    def test_an_unknown_reason_is_rejected_rather_than_interpreted(self) -> None:
        response = self.post(
            "claim-bogus",
            {
                "reason": "because_i_said_so",
                "order_value": "4200",
                "days_since_delivery": 2,
            },
        )
        self.assertEqual(422, response.status_code)

    def test_an_unexpected_claim_field_is_rejected_rather_than_ignored(self) -> None:
        """A misspelled constraint that is silently dropped is worse than an error."""

        response = self.post(
            "claim-extra",
            {
                "reason": "defect",
                "order_value": "4200",
                "days_since_delivery": 2,
                "evidenec": ["photo"],
            },
        )
        self.assertEqual(422, response.status_code)

    def test_evidence_cannot_be_asserted_without_citing_an_artifact(self) -> None:
        """The tightening: evidence is derived from citations, never supplied.

        Accepting an evidence list directly let a claim assert that a photo
        existed with nothing to check it against. It is now computed from the
        artifacts, so claiming one means naming a reference an investigator can
        take back to the order system.
        """

        response = self.post(
            "claim-bare-evidence",
            {
                "reason": "defect",
                "order_value": "4200",
                "days_since_delivery": 2,
                "evidence": ["photo"],
            },
        )
        self.assertEqual(422, response.status_code)

    def test_an_order_reference_cannot_carry_markup(self) -> None:
        """It reaches an operator's screen, so it is an id or it is rejected."""

        response = self.post(
            "claim-markup-ref",
            {
                "reason": "defect",
                "order_value": "4200",
                "days_since_delivery": 2,
                "order_reference": "<script>alert(1)</script>",
            },
        )
        self.assertEqual(422, response.status_code)

    def test_the_complaint_text_never_reaches_the_audit_chain(self) -> None:
        """An append-only chain cannot be redacted, so prose must not go in it.

        Presence and length are recorded, which is what an investigator needs
        to know a statement existed. The statement itself stays on the decision
        record, where retention rules can still reach it.
        """

        canary = "CANARY-7f3a-customer-wrote-this-prose"
        self.post(
            "claim-canary",
            {
                "reason": "defect",
                "order_value": "4200",
                "days_since_delivery": 2,
                "order_reference": "ORD-9001",
                "artifacts": [{"kind": "photo", "reference": "img-77"}],
                "complaint": canary,
            },
        )
        events = self.client.get("/v1/audit/events")
        self.assertEqual(200, events.status_code)
        body = events.text

        self.assertNotIn(
            canary,
            body,
            "The customer's words were written into the hash chain, which can "
            "never be redacted.",
        )
        # ...but the fact of it, and the citation, must be there to audit.
        self.assertIn("complaint_present", body)
        self.assertIn("photo:img-77", body)
        self.assertIn("ORD-9001", body)

    def test_omitting_the_claim_keeps_the_previous_behaviour(self) -> None:
        response = self.post("claim-none", None)
        self.assertEqual(200, response.status_code)
        self.assertIsNone(response.json()["decision"]["remedy"])
