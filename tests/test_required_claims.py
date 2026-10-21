"""Refund context must survive every entry point, and omission must deny."""

from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import httpx
from fastapi.testclient import TestClient

from intentguard.agent import ChatCompletionsPlanner, GovernedAgent, ScriptedPlanner
from intentguard.api import create_app
from intentguard.models import ActionRequest, AgentProfile, Decision, IntentPassport
from intentguard.policy import (
    InMemoryPolicyRepository,
    OpaCliPolicyEvaluator,
    find_opa_executable,
    initial_policy,
)
from intentguard.policy_engine import PolicyEngine
from tests.test_api import admin_headers, test_authenticator


OPA = find_opa_executable()
ACTIONS = ("refund_order", "refund_shipping", "issue_goodwill_credit")


class RequiredClaimTest(unittest.TestCase):
    evaluator = "builtin"

    def setUp(self) -> None:
        self.now = datetime.now(timezone.utc)
        policy = None
        if self.evaluator == "rego":
            policy = OpaCliPolicyEvaluator(
                OPA, InMemoryPolicyRepository(initial_policy())
            )
        self.engine = PolicyEngine(policy_evaluator=policy)
        self.engine.register_agent(
            AgentProfile(
                "ada",
                "Ada",
                frozenset((*ACTIONS, "book_hotel")),
                Decimal("500"),
                Decimal("5000"),
            )
        )
        for action in (*ACTIONS, "book_hotel"):
            self.engine.register_intent(
                IntentPassport(
                    f"intent-{action}",
                    "customer-01",
                    "ada",
                    action,
                    Decimal("500"),
                    "INR",
                    self.now + timedelta(hours=1),
                )
            )

    def arguments(self) -> dict:
        return {
            "intent_id": "intent-refund_order",
            "action": "refund_order",
            "amount": "100",
            "currency": "INR",
            "risk_score": 0,
            "attributes": {},
            "rationale": "Requested refund.",
        }

    def claim(self, *, photo: bool = False) -> dict:
        return {
            "reason": "defect",
            "order_value": "100",
            "days_since_delivery": 1,
            "order_reference": "ORD-42",
            "artifacts": [{"kind": "photo", "reference": "img-42"}] if photo else [],
            "complaint": "PRIVATE-COMPLAINT-CANARY",
        }

    def planner(self, arguments: dict) -> ChatCompletionsPlanner:
        return ChatCompletionsPlanner(
            api_key="xai-test-key",
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    json={
                        "choices": [
                            {
                                "message": {
                                    "tool_calls": [
                                        {
                                            "function": {
                                                "name": "propose_action",
                                                "arguments": json.dumps(arguments),
                                            }
                                        }
                                    ]
                                }
                            }
                        ],
                    },
                )
            ),
        )

    def send(self, planner):
        return GovernedAgent(self.engine, planner=planner).send(
            "Issue a refund of 100 rupees",
            customer_id="customer-01",
            agent_id="ada",
            now=self.now,
        )

    def assert_no_authority(self, result, code: str) -> None:
        self.assertEqual(Decision.DENY, result.decision.decision)
        self.assertIn(code, {item.code for item in result.decision.findings})
        self.assertIsNone(result.lease)
        self.assertIsNone(result.reservation)
        self.assertEqual((), self.engine.budget_ledger.held())
        self.assertEqual((), self.engine.list_approvals())

    def test_missing_claim_denies_each_refund_action_even_at_high_risk(self) -> None:
        for action in ACTIONS:
            with self.subTest(action=action):
                request = ActionRequest(
                    action,
                    "ada",
                    action,
                    Decimal("100"),
                    "INR",
                    f"intent-{action}",
                    100,
                    customer_id="customer-01",
                )
                result = self.engine.authorize_action(request, now=self.now)
                self.assert_no_authority(result, "CLAIM_REQUIRED")
                self.assertEqual(
                    result, self.engine.authorize_action(request, now=self.now)
                )
        evaluated = [
            e
            for e in self.engine.audit_ledger.events
            if e.event_type == "policy.evaluated"
        ]
        self.assertTrue(
            all("CLAIM_REQUIRED" in e.payload["finding_codes"] for e in evaluated)
        )

    def test_unrelated_actions_still_work_without_claims(self) -> None:
        result = self.engine.authorize_action(
            ActionRequest(
                "hotel",
                "ada",
                "book_hotel",
                Decimal("100"),
                "INR",
                "intent-book_hotel",
                0,
                customer_id="customer-01",
            ),
            now=self.now,
        )
        self.assertEqual(Decision.ALLOW, result.decision.decision)

    def test_scripted_chat_cannot_skip_claim_rules(self) -> None:
        self.assert_no_authority(self.send(ScriptedPlanner()).result, "CLAIM_REQUIRED")

    def test_model_chat_cannot_skip_claim_rules(self) -> None:
        for value in ("omit", None):
            args = self.arguments()
            if value is None:
                args["claim"] = None
            self.assert_no_authority(
                self.send(self.planner(args)).result, "CLAIM_REQUIRED"
            )

    def test_model_claim_reaches_policy_and_denies_wrong_remedy(self) -> None:
        turn = self.send(self.planner({**self.arguments(), "claim": self.claim()}))
        self.assert_no_authority(turn.result, "REMEDY_NOT_PERMITTED")
        self.assertEqual("shipping_refund", turn.result.decision.remedy.kind.value)
        self.assertEqual("ORD-42", turn.proposal.claim.order_reference)

    def test_model_citations_survive_into_authorization_and_audit(self) -> None:
        turn = self.send(
            self.planner({**self.arguments(), "claim": self.claim(photo=True)})
        )
        self.assertEqual(Decision.ALLOW, turn.decision)
        self.assertEqual("refund_to_source", turn.result.decision.remedy.kind.value)
        self.assertEqual(frozenset({"photo"}), turn.proposal.claim.evidence)
        evaluated = [
            e
            for e in self.engine.audit_ledger.events
            if e.event_type == "policy.evaluated"
        ][-1]
        self.assertEqual(["photo:img-42"], evaluated.payload["evidence_cited"])
        self.assertNotIn(
            "PRIVATE-COMPLAINT-CANARY", str(self.engine.audit_ledger.as_dicts())
        )

    def test_valid_shipping_and_credit_claims_still_authorize(self) -> None:
        for action, reason in (
            ("refund_shipping", "late"),
            ("issue_goodwill_credit", "changed_mind"),
        ):
            with self.subTest(action=action):
                args = {
                    **self.arguments(),
                    "action": action,
                    "intent_id": f"intent-{action}",
                    "claim": {**self.claim(), "reason": reason},
                }
                turn = self.send(self.planner(args))
                self.assertEqual(Decision.ALLOW, turn.decision)
                self.assertIsNotNone(turn.result.lease)

    def test_claim_survives_the_persistence_codec(self) -> None:
        from intentguard.persistence import _decode, _encode

        turn = self.send(
            self.planner({**self.arguments(), "claim": self.claim(photo=True)})
        )
        request, result = self.engine._authorizations[turn.result.decision.request_id]
        self.assertEqual(request, _decode(_encode(request)))
        self.assertEqual(result, _decode(_encode(result)))

    def test_malformed_model_claim_never_reaches_authorization(self) -> None:
        for claim in (
            {"reason": "defect"},
            {**self.claim(), "evidence": ["photo"]},
            {**self.claim(), "days_since_delivery": -1},
            {**self.claim(), "order_value": "NaN"},
            {**self.claim(), "order_reference": "<script>"},
        ):
            with self.subTest(claim=claim):
                turn = self.send(self.planner({**self.arguments(), "claim": claim}))
                self.assertIsNone(turn.result)
                self.assertIsNotNone(turn.error)
        self.assertEqual((), self.engine.budget_ledger.held())

    def test_http_omission_and_null_deny_without_reserving(self) -> None:
        with TestClient(
            create_app(self.engine, authenticator=test_authenticator())
        ) as client:
            client.headers.update(admin_headers(agent_id="ada"))
            for explicit_null in (False, True):
                payload = {
                    k: v for k, v in self.arguments().items() if k != "rationale"
                }
                payload.update(request_id=f"http-{explicit_null}", agent_id="ada")
                if explicit_null:
                    payload["claim"] = None
                response = client.post("/v1/actions/authorize", json=payload)
                self.assertEqual(200, response.status_code)
                body = response.json()
                self.assertEqual("deny", body["decision"]["decision"])
                self.assertIn(
                    "CLAIM_REQUIRED", {f["code"] for f in body["decision"]["findings"]}
                )
                self.assertIsNone(body["lease"])
                self.assertIsNone(body["reservation"])

    def test_http_chat_transports_the_same_claim_as_direct_authorization(self) -> None:
        app = create_app(self.engine, authenticator=test_authenticator())
        app.state.agent = GovernedAgent(
            self.engine,
            planner=self.planner(
                {
                    **self.arguments(),
                    "claim": self.claim(),
                }
            ),
        )
        with TestClient(app) as client:
            client.headers.update(admin_headers(agent_id="ada"))
            response = client.post(
                "/v1/agent/message",
                json={
                    "customer_id": "customer-01",
                    "agent_id": "ada",
                    "message": "Issue a refund of 100 rupees",
                },
            )
            self.assertEqual(200, response.status_code)
            self.assertEqual("deny", response.json()["decision"])
            self.assertEqual(
                "ORD-42", response.json()["proposal"]["claim"]["order_reference"]
            )


@unittest.skipUnless(OPA, "OPA CLI is unavailable")
class RequiredClaimRegoTest(RequiredClaimTest):
    evaluator = "rego"

    def test_previously_published_policy_cannot_allow_missing_claim(self) -> None:
        # Editing the bundled source does not update a policy in PostgreSQL.
        # Simulate an older published policy that omits the new claim guard.
        source = """package intentguard.authorization
import rego.v1
decision := {"decision": "allow", "findings": [
    {"code": "POLICY_SATISFIED", "message": "Allowed", "blocking": false}
], "remedy": null}
"""
        self.engine.policy_evaluator = OpaCliPolicyEvaluator(
            OPA,
            InMemoryPolicyRepository(initial_policy(source)),
        )
        turn = self.send(ScriptedPlanner())
        self.assert_no_authority(turn.result, "CLAIM_REQUIRED")
        self.assertNotIn(
            "POLICY_SATISFIED", {f.code for f in turn.result.decision.findings}
        )
