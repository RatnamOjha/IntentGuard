from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from intentguard import (  # noqa: E402
    ActionRequest,
    AgentProfile,
    ApprovalStatus,
    Decision,
    IntentPassport,
    PolicyEngine,
)


class PolicyEngineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)
        self.engine = PolicyEngine(review_risk_threshold=70)
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
                expires_at=self.now + timedelta(hours=1),
                required_attributes={"refundable": True},
            )
        )

    def action(
        self,
        *,
        request_id: str = "request-01",
        amount: str = "15000",
        risk_score: int = 20,
        refundable: bool = True,
    ) -> ActionRequest:
        return ActionRequest(
            request_id=request_id,
            agent_id="travel-01",
            action="book_flight",
            amount=Decimal(amount),
            currency="INR",
            intent_id="intent-01",
            risk_score=risk_score,
            attributes={"refundable": refundable},
            occurred_at=self.now,
        )

    def test_allows_compliant_action(self) -> None:
        result = self.engine.evaluate(self.action(), now=self.now)
        self.assertEqual(Decision.ALLOW, result.decision)

    def test_denies_action_outside_customer_intent(self) -> None:
        result = self.engine.evaluate(
            self.action(amount="19000"),
            now=self.now,
        )
        self.assertEqual(Decision.DENY, result.decision)
        self.assertIn(
            "INTENT_AMOUNT_EXCEEDED",
            {finding.code for finding in result.findings},
        )

    def test_denies_attribute_mismatch(self) -> None:
        result = self.engine.evaluate(
            self.action(refundable=False),
            now=self.now,
        )
        self.assertEqual(Decision.DENY, result.decision)
        self.assertIn(
            "INTENT_ATTRIBUTE_MISMATCH",
            {finding.code for finding in result.findings},
        )

    def test_routes_high_risk_action_to_review(self) -> None:
        result = self.engine.evaluate(
            self.action(risk_score=75),
            now=self.now,
        )
        self.assertEqual(Decision.REVIEW, result.decision)

    def test_operator_can_approve_high_risk_action(self) -> None:
        authorization = self.engine.authorize_action(
            self.action(request_id="request-review", risk_score=80),
            now=self.now,
        )
        self.assertEqual(Decision.REVIEW, authorization.decision.decision)
        self.assertEqual(
            ApprovalStatus.PENDING,
            self.engine.list_approvals()[0].status,
        )

        approved = self.engine.approve_action(
            "request-review",
            reviewer="operator-01",
            reason="Verified with the card member",
            now=self.now + timedelta(seconds=1),
        )

        self.assertEqual(Decision.ALLOW, approved.decision.decision)
        self.assertIsNotNone(approved.reservation)
        self.assertIsNotNone(approved.lease)
        self.assertEqual(
            ApprovalStatus.APPROVED,
            self.engine.list_approvals()[0].status,
        )
        self.assertIn(
            "HUMAN_APPROVAL_GRANTED",
            {finding.code for finding in approved.decision.findings},
        )

    def test_operator_can_reject_high_risk_action(self) -> None:
        self.engine.authorize_action(
            self.action(request_id="request-rejected", risk_score=80),
            now=self.now,
        )

        rejected = self.engine.reject_action(
            "request-rejected",
            reviewer="operator-01",
            reason="Customer could not be verified",
            now=self.now + timedelta(seconds=1),
        )

        self.assertEqual(ApprovalStatus.REJECTED, rejected.status)
        self.assertIn(
            "approval.rejected",
            {event.event_type for event in self.engine.audit_ledger.events},
        )

    def test_enforces_daily_budget_after_execution(self) -> None:
        first = self.action(request_id="request-first", amount="17000")
        first_result = self.engine.evaluate(first, now=self.now)
        self.engine.record_execution(first, first_result, executed_at=self.now)

        second = self.action(request_id="request-second", amount="14000")
        second_result = self.engine.evaluate(second, now=self.now)
        self.assertEqual(Decision.DENY, second_result.decision)
        self.assertIn(
            "DAILY_BUDGET_EXCEEDED",
            {finding.code for finding in second_result.findings},
        )

    def test_operator_can_publish_agent_policy(self) -> None:
        updated = self.engine.update_agent_policy(
            "travel-01",
            allowed_actions=frozenset({"book_flight", "book_hotel"}),
            max_action_amount=Decimal("25000"),
            daily_budget=Decimal("40000"),
            active=True,
            operator="Demo Operator",
            reason="Expand the travel pilot",
        )

        self.assertIn("book_hotel", updated.allowed_actions)
        self.assertEqual("2026.07.r1", self.engine.policy_version)
        self.assertEqual(
            "policy.updated",
            self.engine.audit_ledger.events[-1].event_type,
        )

    def test_policy_budget_cannot_drop_below_current_exposure(self) -> None:
        request = self.action(amount="15000")
        decision = self.engine.evaluate(request, now=self.now)
        self.engine.record_execution(request, decision, executed_at=self.now)

        with self.assertRaises(ValueError):
            self.engine.update_agent_policy(
                "travel-01",
                allowed_actions=frozenset({"book_flight"}),
                max_action_amount=Decimal("20000"),
                daily_budget=Decimal("10000"),
                active=True,
                operator="Demo Operator",
                reason="Invalid reduction",
                now=self.now,
            )

    def test_revocation_is_immediate(self) -> None:
        self.engine.revoke_agent("travel-01")
        result = self.engine.evaluate(self.action(), now=self.now)
        self.assertEqual(Decision.DENY, result.decision)
        self.assertIn(
            "AGENT_REVOKED",
            {finding.code for finding in result.findings},
        )

    def test_restored_agent_can_act_again_and_is_audited(self) -> None:
        self.engine.revoke_agent("travel-01")
        self.engine.restore_agent("travel-01")

        result = self.engine.evaluate(self.action(), now=self.now)

        self.assertEqual(Decision.ALLOW, result.decision)
        self.assertEqual("agent.restored", self.engine.audit_ledger.events[-2].event_type)
        self.assertEqual(
            "travel-01",
            self.engine.audit_ledger.events[-2].payload["agent_id"],
        )

    def test_restoring_unknown_agent_fails(self) -> None:
        with self.assertRaises(KeyError):
            self.engine.restore_agent("unknown-agent")

    def test_fleet_stop_blocks_valid_action(self) -> None:
        self.engine.stop_fleet(reason="Incident response")
        result = self.engine.evaluate(self.action(), now=self.now)
        self.assertEqual(Decision.DENY, result.decision)
        self.assertIn(
            "FLEET_STOPPED",
            {finding.code for finding in result.findings},
        )

    def _finding(self, result, code):
        matches = [f for f in result.findings if f.code == code]
        self.assertEqual(1, len(matches), f"expected exactly one {code}")
        return matches[0]

    def test_agent_action_limit_carries_the_limit_and_the_breach(self) -> None:
        result = self.engine.evaluate(self.action(amount="25000"), now=self.now)
        finding = self._finding(result, "AGENT_ACTION_LIMIT")
        self.assertIsNotNone(finding.context)
        assert finding.context is not None
        self.assertEqual(Decimal("20000"), finding.context.limit)
        self.assertEqual(Decimal("25000"), finding.context.actual)
        self.assertIsNone(finding.context.permitted)

    def test_intent_amount_exceeded_carries_the_intent_ceiling(self) -> None:
        result = self.engine.evaluate(self.action(amount="19000"), now=self.now)
        finding = self._finding(result, "INTENT_AMOUNT_EXCEEDED")
        assert finding.context is not None
        self.assertEqual(Decimal("18000"), finding.context.limit)
        self.assertEqual(Decimal("19000"), finding.context.actual)

    def test_daily_budget_exceeded_carries_remaining_headroom(self) -> None:
        self.engine.register_intent(
            IntentPassport(
                intent_id="intent-big",
                customer_id="customer-01",
                agent_id="travel-01",
                action="book_flight",
                max_amount=Decimal("60000"),
                currency="INR",
                expires_at=self.now + timedelta(hours=1),
                required_attributes={"refundable": True},
            )
        )
        request = ActionRequest(
            request_id="request-budget",
            agent_id="travel-01",
            action="book_flight",
            amount=Decimal("40000"),
            currency="INR",
            intent_id="intent-big",
            risk_score=20,
            attributes={"refundable": True},
            occurred_at=self.now,
        )
        result = self.engine.evaluate(request, now=self.now)
        finding = self._finding(result, "DAILY_BUDGET_EXCEEDED")
        assert finding.context is not None
        # The whole daily budget is still available, so headroom is the cap.
        self.assertEqual(Decimal("30000"), finding.context.limit)
        self.assertEqual(Decimal("40000"), finding.context.actual)

    def test_action_not_permitted_carries_the_permitted_set(self) -> None:
        request = ActionRequest(
            request_id="request-forbidden",
            agent_id="travel-01",
            action="wire_transfer",
            amount=Decimal("100"),
            currency="INR",
            intent_id="intent-01",
            risk_score=20,
            attributes={"refundable": True},
            occurred_at=self.now,
        )
        result = self.engine.evaluate(request, now=self.now)
        finding = self._finding(result, "ACTION_NOT_PERMITTED")
        assert finding.context is not None
        self.assertEqual(frozenset({"book_flight"}), finding.context.permitted)
        self.assertIsNone(finding.context.limit)

    def test_boolean_checks_carry_no_context(self) -> None:
        """Only comparisons with operands worth showing get a context."""
        self.engine.stop_fleet(reason="Incident response")
        result = self.engine.evaluate(self.action(), now=self.now)
        self.assertIsNone(self._finding(result, "FLEET_STOPPED").context)

    def test_context_never_echoes_request_supplied_text(self) -> None:
        """Attacker-controlled attributes must not reach the operator's screen."""
        marker = "<script>alert(1)</script>"
        request = ActionRequest(
            request_id="request-inject",
            agent_id="travel-01",
            action="wire_transfer",
            amount=Decimal("25000"),
            currency="INR",
            intent_id="intent-01",
            risk_score=20,
            attributes={"refundable": True, "note": marker},
            occurred_at=self.now,
        )
        result = self.engine.evaluate(request, now=self.now)
        contexts = [f.context for f in result.findings if f.context is not None]
        self.assertTrue(contexts, "expected at least one finding with context")
        for context in contexts:
            self.assertNotIn(marker, str(context.permitted))
            for value in (context.limit, context.actual):
                self.assertTrue(value is None or isinstance(value, Decimal))


    def test_audit_chain_verifies(self) -> None:
        result = self.engine.evaluate(self.action(), now=self.now)
        self.engine.record_execution(
            self.action(),
            result,
            executed_at=self.now,
        )
        self.assertTrue(self.engine.audit_ledger.verify())


if __name__ == "__main__":
    unittest.main()
