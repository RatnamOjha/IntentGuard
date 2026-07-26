"""Runtime policy evaluation for financial agent actions."""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any

from .audit import AuditLedger
from .models import (
    ActionRequest,
    AgentProfile,
    Decision,
    DecisionRecord,
    IntentPassport,
    PolicyFinding,
)


class PolicyEngine:
    """Evaluates intercepted actions against identity, intent, and risk policy."""

    def __init__(
        self,
        *,
        policy_version: str = "2026.07",
        review_risk_threshold: int = 70,
        audit_ledger: AuditLedger | None = None,
    ) -> None:
        self.policy_version = policy_version
        self.review_risk_threshold = review_risk_threshold
        self.audit_ledger = audit_ledger or AuditLedger()
        self._agents: dict[str, AgentProfile] = {}
        self._intents: dict[str, IntentPassport] = {}
        self._revoked_agents: set[str] = set()
        self._daily_spend: dict[tuple[str, date], Decimal] = defaultdict(
            lambda: Decimal("0")
        )
        self._fleet_stopped = False

    def register_agent(self, agent: AgentProfile) -> None:
        self._agents[agent.agent_id] = agent
        self.audit_ledger.append(
            "agent.registered",
            {"agent_id": agent.agent_id, "name": agent.name},
        )

    def register_intent(self, intent: IntentPassport) -> None:
        self._intents[intent.intent_id] = intent
        self.audit_ledger.append(
            "intent.registered",
            {
                "intent_id": intent.intent_id,
                "agent_id": intent.agent_id,
                "customer_id": intent.customer_id,
            },
        )

    def revoke_agent(self, agent_id: str) -> None:
        self._revoked_agents.add(agent_id)
        self.audit_ledger.append("agent.revoked", {"agent_id": agent_id})

    def stop_fleet(self, *, reason: str) -> None:
        self._fleet_stopped = True
        self.audit_ledger.append("fleet.stopped", {"reason": reason})

    def resume_fleet(self) -> None:
        self._fleet_stopped = False
        self.audit_ledger.append("fleet.resumed", {})

    def evaluate(
        self,
        request: ActionRequest,
        *,
        now: datetime | None = None,
    ) -> DecisionRecord:
        evaluation_time = now or datetime.now(timezone.utc)
        findings: list[PolicyFinding] = []
        agent = self._agents.get(request.agent_id)
        intent = self._intents.get(request.intent_id)

        self._check(
            findings,
            condition=not self._fleet_stopped,
            code="FLEET_STOPPED",
            failure="The fleet emergency stop is active.",
        )
        self._check(
            findings,
            condition=agent is not None,
            code="AGENT_UNKNOWN",
            failure="The requesting agent is not registered.",
        )

        if agent is not None:
            self._check(
                findings,
                condition=agent.active,
                code="AGENT_INACTIVE",
                failure="The requesting agent is inactive.",
            )
            self._check(
                findings,
                condition=agent.agent_id not in self._revoked_agents,
                code="AGENT_REVOKED",
                failure="The requesting agent has been revoked.",
            )
            self._check(
                findings,
                condition=request.action in agent.allowed_actions,
                code="ACTION_NOT_PERMITTED",
                failure="The agent is not permitted to perform this action.",
            )
            self._check(
                findings,
                condition=request.amount <= agent.max_action_amount,
                code="AGENT_ACTION_LIMIT",
                failure="The action exceeds the agent's per-action limit.",
            )

        self._check(
            findings,
            condition=intent is not None,
            code="INTENT_UNKNOWN",
            failure="No authenticated customer intent matches this request.",
        )

        if intent is not None:
            self._check(
                findings,
                condition=intent.agent_id == request.agent_id,
                code="INTENT_AGENT_MISMATCH",
                failure="The intent was issued to a different agent.",
            )
            self._check(
                findings,
                condition=intent.action == request.action,
                code="INTENT_ACTION_MISMATCH",
                failure="The requested action is outside the customer's intent.",
            )
            self._check(
                findings,
                condition=not intent.is_expired(evaluation_time),
                code="INTENT_EXPIRED",
                failure="The customer's intent has expired.",
            )
            self._check(
                findings,
                condition=intent.currency == request.currency,
                code="INTENT_CURRENCY_MISMATCH",
                failure="The request currency differs from the authorized currency.",
            )
            self._check(
                findings,
                condition=request.amount <= intent.max_amount,
                code="INTENT_AMOUNT_EXCEEDED",
                failure="The amount exceeds the customer's authorized maximum.",
            )
            self._check_required_attributes(findings, intent, request)

        spent_today = (
            self._daily_spend[(request.agent_id, evaluation_time.date())]
            if agent is not None
            else Decimal("0")
        )
        remaining_budget = (
            max(agent.daily_budget - spent_today, Decimal("0"))
            if agent is not None
            else Decimal("0")
        )

        if agent is not None:
            self._check(
                findings,
                condition=request.amount <= remaining_budget,
                code="DAILY_BUDGET_EXCEEDED",
                failure="The action exceeds the agent's remaining daily budget.",
            )

        blocking_findings = [item for item in findings if item.blocking]
        if blocking_findings:
            decision = Decision.DENY
        elif request.risk_score >= self.review_risk_threshold:
            decision = Decision.REVIEW
            findings.append(
                PolicyFinding(
                    code="HUMAN_APPROVAL_REQUIRED",
                    message=(
                        "The action requires human approval because its risk "
                        "score exceeds the configured threshold."
                    ),
                    blocking=False,
                )
            )
        else:
            decision = Decision.ALLOW
            findings.append(
                PolicyFinding(
                    code="POLICY_SATISFIED",
                    message="The action satisfies all active runtime policies.",
                    blocking=False,
                )
            )

        record = DecisionRecord(
            request_id=request.request_id,
            decision=decision,
            findings=tuple(findings),
            remaining_daily_budget=remaining_budget,
            policy_version=self.policy_version,
        )
        self.audit_ledger.append(
            "policy.evaluated",
            {
                "request_id": request.request_id,
                "agent_id": request.agent_id,
                "decision": decision.value,
                "finding_codes": [item.code for item in findings],
                "policy_version": self.policy_version,
            },
        )
        return record

    def record_execution(
        self,
        request: ActionRequest,
        decision: DecisionRecord,
        *,
        executed_at: datetime | None = None,
    ) -> None:
        if decision.decision is not Decision.ALLOW:
            raise ValueError("Only allowed actions can be recorded as executed.")
        timestamp = executed_at or datetime.now(timezone.utc)
        self._daily_spend[(request.agent_id, timestamp.date())] += request.amount
        self.audit_ledger.append(
            "action.executed",
            {
                "request_id": request.request_id,
                "agent_id": request.agent_id,
                "amount": request.amount,
                "currency": request.currency,
            },
        )

    @staticmethod
    def _check(
        findings: list[PolicyFinding],
        *,
        condition: bool,
        code: str,
        failure: str,
    ) -> None:
        if not condition:
            findings.append(
                PolicyFinding(code=code, message=failure, blocking=True)
            )

    @staticmethod
    def _check_required_attributes(
        findings: list[PolicyFinding],
        intent: IntentPassport,
        request: ActionRequest,
    ) -> None:
        for key, expected in intent.required_attributes.items():
            actual: Any = request.attributes.get(key)
            if actual != expected:
                findings.append(
                    PolicyFinding(
                        code="INTENT_ATTRIBUTE_MISMATCH",
                        message=(
                            f"The request violates the authorized '{key}' "
                            f"constraint: expected {expected!r}, received {actual!r}."
                        ),
                        blocking=True,
                    )
                )

