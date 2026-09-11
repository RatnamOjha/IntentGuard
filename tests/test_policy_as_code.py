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
from intentguard.models import ClaimReason, RefundClaim, RemedyKind
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

# CI installs OPA, so a skip there means the binary was installed and never
# found -- which is how a broken lookup once let CI report green while every
# test of the policy engine was skipped. With this set, not finding OPA is a
# failure rather than a quiet skip. Contributors without OPA still skip.
REQUIRE_OPA = os.getenv("INTENTGUARD_REQUIRE_OPA_TESTS") == "1"


class OpaAvailabilityTest(unittest.TestCase):
    """Guards the guard: a skipped Rego suite must not look like a pass."""

    def test_opa_is_discoverable_where_it_is_required(self) -> None:
        if not REQUIRE_OPA:
            self.skipTest(
                "Set INTENTGUARD_REQUIRE_OPA_TESTS=1 to require a discoverable OPA"
            )
        self.assertIsNotNone(
            OPA,
            "INTENTGUARD_REQUIRE_OPA_TESTS=1 but find_opa_executable() returned "
            "None, so every Rego test below skipped. An installed-but-unfound "
            "policy engine is the failure this flag exists to make visible.",
        )


NOW = datetime(2026, 8, 28, 12, tzinfo=timezone.utc)


def _decision_engine_field(engine: "PolicyEngine", request: "ActionRequest") -> str:
    """The ``policy_engine`` recorded on the audit event for one decision."""

    engine.evaluate(request, now=NOW)
    evaluated = [
        event
        for event in engine.audit_ledger.events
        if event.event_type == "policy.evaluated"
    ]
    return evaluated[-1].payload["policy_engine"]


class AuditNamesTheEvaluatorTest(unittest.TestCase):
    """Every decision records which evaluator produced it.

    The Rego path always did; the built-in path recorded nothing, so the
    engine behind a decision could be inferred but not read. The two are not
    equivalent, which makes this the first field an investigator would want
    if they ever disagreed in production.
    """

    def _engine(self, evaluator: object | None) -> "PolicyEngine":
        engine = PolicyEngine(policy_evaluator=evaluator, review_risk_threshold=70)
        engine.register_agent(
            AgentProfile(
                "travel-01", "Travel", frozenset({"book_hotel"}),
                Decimal("20000"), Decimal("30000"),
            )
        )
        engine.register_intent(
            IntentPassport(
                "intent-01", "customer-01", "travel-01", "book_hotel",
                Decimal("18000"), "INR", NOW + timedelta(hours=1),
            )
        )
        return engine

    def _request(self) -> "ActionRequest":
        return ActionRequest(
            "audit-1", "travel-01", "book_hotel", Decimal("4500"), "INR",
            "intent-01", 10, {"refundable": True}, "customer-01", occurred_at=NOW,
        )

    def test_the_builtin_evaluator_names_itself(self) -> None:
        self.assertEqual(
            "builtin",
            _decision_engine_field(self._engine(None), self._request()),
        )

    @unittest.skipUnless(OPA, "OPA CLI is unavailable")
    def test_the_rego_evaluator_names_itself(self) -> None:
        evaluator = OpaCliPolicyEvaluator(
            OPA, InMemoryPolicyRepository(initial_policy())
        )
        self.assertEqual(
            "opa_rego",
            _decision_engine_field(self._engine(evaluator), self._request()),
        )

    @unittest.skipUnless(OPA, "OPA CLI is unavailable")
    def test_the_two_evaluators_are_distinguishable_in_the_record(self) -> None:
        """Recording a constant would satisfy both tests above but not this."""

        evaluator = OpaCliPolicyEvaluator(
            OPA, InMemoryPolicyRepository(initial_policy())
        )
        self.assertNotEqual(
            _decision_engine_field(self._engine(None), self._request()),
            _decision_engine_field(self._engine(evaluator), self._request()),
        )


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
            "large_payout_threshold": 10000,
            "review_merchant_categories": ["cash_equivalent"],
            "shipping_refund_cap": 150,
            "change_of_mind_days": 7,
        },
    }


@unittest.skipUnless(OPA, "OPA CLI is unavailable")
class PolicyAsCodeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = InMemoryPolicyRepository(initial_policy())
        self.evaluator = OpaCliPolicyEvaluator(OPA, self.repository)
        self.service = PolicyService(self.evaluator)
        # The payout threshold is opt-in, so a test of it has to configure it.
        self.engine = PolicyEngine(
            policy_evaluator=self.evaluator,
            review_risk_threshold=70,
            large_payout_threshold=Decimal("10000"),
        )
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

    def test_large_payout_and_merchant_category_require_review(self) -> None:
        self.assertEqual(Decision.REVIEW, self.engine.evaluate(self.request(amount="11000"), now=NOW).decision)
        value = policy_input(attributes={"refundable": True, "merchant_category": "cash_equivalent"})
        self.assertEqual(Decision.REVIEW, self.evaluator.evaluate_source(initial_policy().source, value).decision)

    def test_validate_dry_run_publish_compare_and_rollback(self) -> None:
        source = initial_policy().source.replace('"large_payout_threshold": 10000', '"large_payout_threshold": 10000')
        # Change the input-driven threshold reference into a fixed stricter rule.
        source = source.replace("input.config.large_payout_threshold", "1000")
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
        source = initial_policy().source.replace("input.config.large_payout_threshold", "1000")
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


#: deny is stricter than review, which is stricter than allow.
_STRICTNESS = {Decision.ALLOW: 0, Decision.REVIEW: 1, Decision.DENY: 2}

CLAIM_NOW = datetime(2026, 8, 28, 12, tzinfo=timezone.utc)


class ClaimFixture:
    """One agent, one intent per action, and identical thresholds per engine.

    A plain mixin rather than a base TestCase: the invariant matrix needs OPA
    and skips without it, while the remedy tests must still run on the
    built-in engine alone. Inheriting a class-level skip would have taken the
    second set out with the first.
    """

    def engine(self, evaluator: object | None) -> PolicyEngine:
        engine = PolicyEngine(
            policy_evaluator=evaluator,
            review_risk_threshold=70,
            large_payout_threshold=Decimal("10000"),
            shipping_refund_cap=Decimal("150"),
            change_of_mind_days=7,
        )
        actions = (
            "refund_order", "issue_goodwill_credit",
            "refund_shipping", "cancel_subscription",
        )
        engine.register_agent(
            AgentProfile(
                "ada", "Ada", frozenset(actions),
                Decimal("5000"), Decimal("50000"),
            )
        )
        for action in actions:
            engine.register_intent(
                IntentPassport(
                    f"intent-{action}", "customer-01", "ada", action,
                    Decimal("5000"), "INR", CLAIM_NOW + timedelta(hours=1),
                )
            )
        return engine

    def builtin_engine(self) -> PolicyEngine:
        return self.engine(None)

    def rego_engine(self) -> PolicyEngine:
        return self.engine(
            OpaCliPolicyEvaluator(OPA, InMemoryPolicyRepository(initial_policy()))
        )

    def request(
        self,
        action: str,
        amount: str,
        *,
        claim: RefundClaim | None = None,
        risk: int = 10,
        attributes: dict | None = None,
    ) -> ActionRequest:
        return ActionRequest(
            request_id=f"inv-{action}-{amount}-{risk}",
            agent_id="ada",
            action=action,
            amount=Decimal(amount),
            currency="INR",
            intent_id=f"intent-{action}",
            risk_score=risk,
            attributes=attributes or {},
            customer_id="customer-01",
            claim=claim,
            occurred_at=CLAIM_NOW,
        )

    def cases(self) -> list[tuple[str, ActionRequest]]:
        defect_photo = RefundClaim(
            ClaimReason.DEFECT, Decimal("4200"), 2, frozenset({"photo"})
        )
        defect_bare = RefundClaim(ClaimReason.DEFECT, Decimal("4200"), 2)
        late = RefundClaim(ClaimReason.LATE, Decimal("4200"), 1)
        undelivered = RefundClaim(ClaimReason.NOT_DELIVERED, Decimal("900"), 9)
        undelivered_scan = RefundClaim(
            ClaimReason.NOT_DELIVERED, Decimal("900"), 9, frozenset({"courier_scan"})
        )
        fresh_regret = RefundClaim(ClaimReason.CHANGED_MIND, Decimal("500"), 3)
        stale_regret = RefundClaim(ClaimReason.CHANGED_MIND, Decimal("500"), 30)
        return [
            ("no claim, inside every limit", self.request("refund_order", "380")),
            ("defect with photo, full refund",
             self.request("refund_order", "4200", claim=defect_photo)),
            ("defect with photo, over the agent's limit",
             self.request("refund_order", "9000", claim=defect_photo)),
            ("defect without photo, refund proposed",
             self.request("refund_order", "4200", claim=defect_bare)),
            ("defect without photo, shipping proposed",
             self.request("refund_shipping", "150", claim=defect_bare)),
            ("defect without photo, shipping over cap",
             self.request("refund_shipping", "400", claim=defect_bare)),
            ("late, refund proposed", self.request("refund_order", "4200", claim=late)),
            ("late, shipping proposed",
             self.request("refund_shipping", "150", claim=late)),
            ("undelivered without scan, credit proposed",
             self.request("issue_goodwill_credit", "900", claim=undelivered)),
            ("undelivered without scan, refund proposed",
             self.request("refund_order", "900", claim=undelivered)),
            ("undelivered with scan, refund proposed",
             self.request("refund_order", "900", claim=undelivered_scan)),
            ("change of mind inside the window",
             self.request("issue_goodwill_credit", "500", claim=fresh_regret)),
            ("change of mind outside the window",
             self.request("issue_goodwill_credit", "500", claim=stale_regret)),
            ("change of mind over the order value",
             self.request("issue_goodwill_credit", "900", claim=fresh_regret)),
            ("claim on an action that settles nothing",
             self.request("cancel_subscription", "100", claim=defect_photo)),
            ("high risk", self.request("refund_order", "380", risk=90)),
            ("flagged merchant category",
             self.request("refund_order", "380",
                          attributes={"merchant_category": "cash_equivalent"})),
            ("large payout", self.request("refund_order", "4900")),
            ("over the agent's per-action limit",
             self.request("refund_order", "9000")),
        ]


@unittest.skipUnless(OPA, "OPA CLI is unavailable")
class PermissivenessInvariantTest(ClaimFixture, unittest.TestCase):
    """The built-in evaluator may never be more permissive than Rego.

    Decisions I rejected both reconciling the two evaluators (once policies are
    customer-editable Rego, no Python reimplementation stays equivalent) and
    mandating OPA (it costs the zero-dependency boot). What is left is an
    invariant: divergence towards *stricter* is fine and expected, divergence
    towards *more permissive* is a bug. Equivalence is not required and is not
    asserted here.

    This is what makes the invariant real rather than a note. Before it
    existed, the built-in engine reviewed on risk alone while Rego also
    reviewed large payouts and flagged merchant categories, so it was quietly
    the weaker of the two in every environment that ran it.
    """

    #: Cases where the two legitimately differ, with the reason. Listing one
    #: here is a decision; discovering one is a bug. Empty is the goal.
    ACCEPTED_DIVERGENCE: dict[str, str] = {}

    def test_the_builtin_evaluator_is_never_more_permissive(self) -> None:
        builtin, rego = self.builtin_engine(), self.rego_engine()
        for name, request in self.cases():
            with self.subTest(case=name):
                left = builtin.evaluate(request, now=CLAIM_NOW).decision
                right = rego.evaluate(request, now=CLAIM_NOW).decision
                if name in self.ACCEPTED_DIVERGENCE:
                    continue
                self.assertGreaterEqual(
                    _STRICTNESS[left],
                    _STRICTNESS[right],
                    f"{name}: the built-in evaluator returned {left.value} where "
                    f"Rego returned {right.value}. Divergence towards stricter is "
                    f"allowed; this is the permissive direction, which Decisions I "
                    f"forbids. Either fix the built-in engine or record the case in "
                    f"ACCEPTED_DIVERGENCE with a reason.",
                )

    def test_the_matrix_actually_exercises_all_three_outcomes(self) -> None:
        """A matrix that only ever produced one outcome would prove nothing."""

        rego = self.rego_engine()
        seen = {
            rego.evaluate(request, now=CLAIM_NOW).decision
            for _, request in self.cases()
        }
        self.assertEqual({Decision.ALLOW, Decision.REVIEW, Decision.DENY}, seen)


class RemedyIsReportedTest(ClaimFixture, unittest.TestCase):
    """A refusal must say what would have passed, not only that it refused."""

    def records(self, request: ActionRequest) -> list:
        engines = [("builtin", self.builtin_engine())]
        if OPA:
            engines.append(("rego", self.rego_engine()))
        return [
            (name, engine.evaluate(request, now=CLAIM_NOW))
            for name, engine in engines
        ]

    def test_a_photoless_defect_refund_is_refused_with_shipping_as_the_answer(
        self,
    ) -> None:
        claim = RefundClaim(ClaimReason.DEFECT, Decimal("4200"), 2)
        request = self.request("refund_order", "4200", claim=claim)
        for name, record in self.records(request):
            with self.subTest(engine=name):
                self.assertEqual(Decision.DENY, record.decision)
                self.assertIn(
                    "REMEDY_NOT_PERMITTED",
                    [finding.code for finding in record.findings],
                )
                self.assertEqual(RemedyKind.SHIPPING_REFUND, record.remedy.kind)
                self.assertEqual(Decimal("150"), record.remedy.cap)

    def test_the_claim_cannot_reach_past_the_agents_own_limit(self) -> None:
        """The narrowing rule: evidence buys a better remedy, never more authority.

        The order was worth 9,000 and the claim carries a photo, so the remedy
        rules alone would permit 9,000. The agent may sign for 5,000, and that
        is what the reported cap has to say -- otherwise an agent could widen
        its own authority by describing the complaint generously.
        """

        claim = RefundClaim(
            ClaimReason.DEFECT, Decimal("9000"), 1, frozenset({"photo"})
        )
        request = self.request("refund_order", "9000", claim=claim)
        for name, record in self.records(request):
            with self.subTest(engine=name):
                self.assertEqual(Decision.DENY, record.decision)
                self.assertEqual(
                    Decimal("5000"),
                    record.remedy.cap,
                    "The remedy cap exceeded the agent's per-action limit, so a "
                    "generous claim would have bought authority the agent does "
                    "not have.",
                )

    def test_a_request_without_a_claim_reports_no_remedy(self) -> None:
        request = self.request("refund_order", "380")
        for name, record in self.records(request):
            with self.subTest(engine=name):
                self.assertEqual(Decision.ALLOW, record.decision)
                self.assertIsNone(record.remedy)
