"""Runtime policy evaluation for financial agent actions."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from threading import RLock
from typing import Any
from uuid import uuid4

from .audit import AuditLedger
from .models import (
    ActionRequest,
    AgentProfile,
    ApprovalStatus,
    AuthorizationLease,
    AuthorizationResult,
    BudgetReservation,
    Decision,
    DecisionRecord,
    HumanApproval,
    IntentPassport,
    PolicyFinding,
    ReservationStatus,
    RiskAssessment,
)


class PolicyEngine:
    """Evaluates intercepted actions against identity, intent, and risk policy."""

    # Gateway-derived risk weights, capped at 100 in total. Calibrated so that
    # sitting at the top of a limit the operator granted does not on its own
    # reach a default review threshold of 70 -- that is what the limit is for --
    # but doing so repeatedly, or while committing funds the customer never
    # agreed to make non-refundable, does. See _derive_risk.
    RISK_WEIGHT_INTENT_UTILIZATION = 35
    RISK_WEIGHT_BUDGET_EXPOSURE = 25
    RISK_WEIGHT_VELOCITY = 30
    RISK_POINTS_PER_PRIOR_AUTHORIZATION = 6
    RISK_WEIGHT_NON_REFUNDABLE = 20
    RISK_WEIGHT_UNCONSTRAINED_ATTRIBUTES = 15
    RISK_POINTS_PER_UNCONSTRAINED_ATTRIBUTE = 5

    def __init__(
        self,
        *,
        policy_version: str = "2026.07",
        review_risk_threshold: int = 70,
        audit_ledger: AuditLedger | None = None,
    ) -> None:
        self.policy_version = policy_version
        self._policy_revision = 0
        self.review_risk_threshold = review_risk_threshold
        self.audit_ledger = audit_ledger or AuditLedger()
        self._agents: dict[str, AgentProfile] = {}
        self._intents: dict[str, IntentPassport] = {}
        self._revoked_agents: set[str] = set()
        self._daily_spend: dict[tuple[str, date], Decimal] = defaultdict(
            lambda: Decimal("0")
        )
        self._reserved_spend: dict[tuple[str, date], Decimal] = defaultdict(
            lambda: Decimal("0")
        )
        self._reservations: dict[str, BudgetReservation] = {}
        self._authorization_counts: dict[tuple[str, date], int] = defaultdict(int)
        self._leases: dict[str, AuthorizationLease] = {}
        self._authorizations: dict[
            str, tuple[ActionRequest, AuthorizationResult]
        ] = {}
        self._approvals: dict[str, HumanApproval] = {}
        self._fleet_stopped = False
        self._fleet_epoch = 0
        self._lock = RLock()

    @property
    def fleet_stopped(self) -> bool:
        with self._lock:
            return self._fleet_stopped

    @property
    def fleet_epoch(self) -> int:
        with self._lock:
            return self._fleet_epoch

    def register_agent(self, agent: AgentProfile) -> None:
        with self._lock:
            self._agents[agent.agent_id] = agent
            self.audit_ledger.append(
                "agent.registered",
                {"agent_id": agent.agent_id, "name": agent.name},
            )

    def register_intent(self, intent: IntentPassport) -> None:
        with self._lock:
            self._intents[intent.intent_id] = intent
            self.audit_ledger.append(
                "intent.registered",
                {
                    "intent_id": intent.intent_id,
                    "agent_id": intent.agent_id,
                    "customer_id": intent.customer_id,
                },
            )

    def update_agent_policy(
        self,
        agent_id: str,
        *,
        allowed_actions: frozenset[str],
        max_action_amount: Decimal,
        daily_budget: Decimal,
        active: bool,
        operator: str,
        reason: str,
        now: datetime | None = None,
    ) -> AgentProfile:
        """Publish a new version of one agent's configurable policy envelope."""

        if not allowed_actions:
            raise ValueError("At least one permitted action is required.")
        if max_action_amount < 0 or daily_budget < 0:
            raise ValueError("Policy amounts cannot be negative.")

        with self._lock:
            current = self._agents.get(agent_id)
            if current is None:
                raise KeyError(f"Unknown agent: {agent_id}")
            today = (now or datetime.now(timezone.utc)).date()
            committed = self._daily_spend[(agent_id, today)]
            reserved = self._reserved_spend[(agent_id, today)]
            if daily_budget < committed + reserved:
                raise ValueError(
                    "The daily budget cannot be lower than today's committed "
                    "and reserved exposure."
                )

            updated = replace(
                current,
                allowed_actions=allowed_actions,
                max_action_amount=max_action_amount,
                daily_budget=daily_budget,
                active=active,
            )
            self._agents[agent_id] = updated
            self._policy_revision += 1
            self.policy_version = f"2026.07.r{self._policy_revision}"
            self.audit_ledger.append(
                "policy.updated",
                {
                    "agent_id": agent_id,
                    "operator": operator,
                    "reason": reason,
                    "policy_version": self.policy_version,
                    "previous": {
                        "allowed_actions": sorted(current.allowed_actions),
                        "max_action_amount": current.max_action_amount,
                        "daily_budget": current.daily_budget,
                        "active": current.active,
                    },
                    "current": {
                        "allowed_actions": sorted(updated.allowed_actions),
                        "max_action_amount": updated.max_action_amount,
                        "daily_budget": updated.daily_budget,
                        "active": updated.active,
                    },
                },
            )
            return updated

    def list_agent_states(
        self, *, now: datetime | None = None
    ) -> tuple[dict[str, Any], ...]:
        """Return operator-safe runtime and budget state for every agent."""

        snapshot_time = now or datetime.now(timezone.utc)
        with self._lock:
            self._expire_reservations_unlocked(snapshot_time)
            states: list[dict[str, Any]] = []
            for agent in sorted(self._agents.values(), key=lambda item: item.agent_id):
                key = (agent.agent_id, snapshot_time.date())
                spent = self._daily_spend[key]
                reserved = self._reserved_spend[key]
                states.append(
                    {
                        "agent_id": agent.agent_id,
                        "name": agent.name,
                        "active": agent.active,
                        "revoked": agent.agent_id in self._revoked_agents,
                        "allowed_actions": sorted(agent.allowed_actions),
                        "max_action_amount": agent.max_action_amount,
                        "daily_budget": agent.daily_budget,
                        "spent_today": spent,
                        "reserved_today": reserved,
                        "remaining_budget": max(
                            agent.daily_budget - spent - reserved,
                            Decimal("0"),
                        ),
                    }
                )
            return tuple(states)

    def list_approvals(self) -> tuple[HumanApproval, ...]:
        """Return newest human-review requests first."""

        with self._lock:
            return tuple(
                sorted(
                    self._approvals.values(),
                    key=lambda approval: approval.created_at,
                    reverse=True,
                )
            )

    def revoke_agent(self, agent_id: str) -> None:
        with self._lock:
            self._revoked_agents.add(agent_id)
            self.audit_ledger.append("agent.revoked", {"agent_id": agent_id})
            for reservation in tuple(self._reservations.values()):
                if (
                    reservation.agent_id == agent_id
                    and reservation.status is ReservationStatus.HELD
                ):
                    self._release_reservation_unlocked(
                        reservation,
                        status=ReservationStatus.RELEASED,
                        reason="agent_revoked",
                    )

    def restore_agent(self, agent_id: str) -> None:
        """Remove an agent's runtime revocation without changing its profile."""

        with self._lock:
            if agent_id not in self._agents:
                raise KeyError(f"Unknown agent: {agent_id}")
            was_revoked = agent_id in self._revoked_agents
            self._revoked_agents.discard(agent_id)
            self.audit_ledger.append(
                "agent.restored",
                {"agent_id": agent_id, "was_revoked": was_revoked},
            )

    def stop_fleet(self, *, reason: str) -> None:
        with self._lock:
            self._fleet_stopped = True
            self._fleet_epoch += 1
            self.audit_ledger.append(
                "fleet.stopped",
                {"reason": reason, "fleet_epoch": self._fleet_epoch},
            )
            for reservation in tuple(self._reservations.values()):
                if reservation.status is ReservationStatus.HELD:
                    self._release_reservation_unlocked(
                        reservation,
                        status=ReservationStatus.RELEASED,
                        reason="fleet_stopped",
                    )

    def resume_fleet(self) -> None:
        with self._lock:
            self._fleet_stopped = False
            self.audit_ledger.append(
                "fleet.resumed", {"fleet_epoch": self._fleet_epoch}
            )

    def evaluate(
        self,
        request: ActionRequest,
        *,
        now: datetime | None = None,
    ) -> DecisionRecord:
        with self._lock:
            self._expire_reservations_unlocked(now or datetime.now(timezone.utc))
            return self._evaluate_unlocked(request, now=now)

    def _evaluate_unlocked(
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
                condition=(
                    request.customer_id is None
                    or intent.customer_id == request.customer_id
                ),
                code="INTENT_CUSTOMER_MISMATCH",
                failure=(
                    "The intent belongs to a different customer than the one "
                    "this action is proposed for."
                ),
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
            + self._reserved_spend[(request.agent_id, evaluation_time.date())]
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

        derived_risk, risk_signals = self._derive_risk(
            request,
            agent,
            intent,
            exposure=spent_today,
            evaluation_time=evaluation_time,
        )
        risk = RiskAssessment(
            declared=request.risk_score,
            derived=derived_risk,
            signals=risk_signals,
        )

        # The agent is the untrusted party, so its self-reported score may only
        # raise the effective risk, never lower it below what the gateway
        # derived. Escalating your own risk is not an attack; hiding is.
        if risk.declared < self.review_risk_threshold <= risk.derived:
            findings.append(
                PolicyFinding(
                    code="RISK_SCORE_UNDER_DECLARED",
                    message=(
                        f"The agent declared a risk score of {risk.declared}, "
                        f"but the gateway derived {risk.derived} from "
                        f"{', '.join(risk.signals)}. The derived score applies."
                    ),
                    blocking=False,
                )
            )

        blocking_findings = [item for item in findings if item.blocking]
        if blocking_findings:
            decision = Decision.DENY
        elif risk.effective >= self.review_risk_threshold:
            decision = Decision.REVIEW
            findings.append(
                PolicyFinding(
                    code="HUMAN_APPROVAL_REQUIRED",
                    message=(
                        "The action requires human approval because its "
                        f"effective risk score of {risk.effective} meets the "
                        "configured threshold."
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
            risk=risk,
        )
        self.audit_ledger.append(
            "policy.evaluated",
            {
                "request_id": request.request_id,
                "agent_id": request.agent_id,
                "decision": decision.value,
                "finding_codes": [item.code for item in findings],
                "policy_version": self.policy_version,
                "declared_risk": risk.declared,
                "derived_risk": risk.derived,
                "effective_risk": risk.effective,
                "risk_signals": list(risk.signals),
            },
        )
        return record

    def authorize_action(
        self,
        request: ActionRequest,
        *,
        now: datetime | None = None,
        lease_ttl: timedelta = timedelta(seconds=30),
    ) -> AuthorizationResult:
        """Atomically evaluate an action and reserve its budget when allowed."""

        evaluation_time = now or datetime.now(timezone.utc)
        if lease_ttl.total_seconds() <= 0:
            raise ValueError("The execution lease TTL must be positive.")
        with self._lock:
            self._expire_reservations_unlocked(evaluation_time)
            existing = self._authorizations.get(request.request_id)
            if existing is not None:
                previous_request, previous_result = existing
                conflicts = self._conflicting_fields(previous_request, request)
                if conflicts:
                    # Record the attempt before refusing it. A rejected tamper
                    # that leaves no trace is invisible to an investigator.
                    self.audit_ledger.append(
                        "authorization.rejected",
                        {
                            "request_id": request.request_id,
                            "agent_id": request.agent_id,
                            "reason": "request_id_reuse_with_different_action_data",
                            "conflicting_fields": list(conflicts),
                        },
                    )
                    raise ValueError(
                        "The request ID was already used with different action data."
                    )
                if previous_result.reservation is not None:
                    current_reservation = self._reservations[
                        previous_result.reservation.reservation_id
                    ]
                    previous_result = replace(
                        previous_result,
                        reservation=current_reservation,
                    )
                    self._authorizations[request.request_id] = (
                        previous_request,
                        previous_result,
                    )
                return previous_result

            decision = self._evaluate_unlocked(request, now=evaluation_time)
            if decision.decision is Decision.REVIEW:
                approval = HumanApproval(
                    request_id=request.request_id,
                    agent_id=request.agent_id,
                    action=request.action,
                    amount=request.amount,
                    currency=request.currency,
                    risk_score=(
                        decision.risk.effective
                        if decision.risk is not None
                        else request.risk_score
                    ),
                    created_at=evaluation_time,
                )
                self._approvals[request.request_id] = approval
                result = AuthorizationResult(decision=decision)
                self._authorizations[request.request_id] = (request, result)
                self.audit_ledger.append(
                    "approval.requested",
                    {
                        "request_id": request.request_id,
                        "agent_id": request.agent_id,
                        "action": request.action,
                        "amount": request.amount,
                        "currency": request.currency,
                        "risk_score": approval.risk_score,
                        "declared_risk": request.risk_score,
                    },
                )
                return result
            if decision.decision is Decision.DENY:
                result = AuthorizationResult(decision=decision)
                self._authorizations[request.request_id] = (request, result)
                return result

            return self._issue_authorization_unlocked(
                request,
                decision,
                evaluation_time=evaluation_time,
                lease_ttl=lease_ttl,
            )

    def approve_action(
        self,
        request_id: str,
        *,
        reviewer: str,
        reason: str,
        now: datetime | None = None,
        lease_ttl: timedelta = timedelta(seconds=30),
    ) -> AuthorizationResult:
        """Approve a pending review and issue a fresh bounded execution lease."""

        if lease_ttl.total_seconds() <= 0:
            raise ValueError("The execution lease TTL must be positive.")
        resolution_time = now or datetime.now(timezone.utc)
        with self._lock:
            self._expire_reservations_unlocked(resolution_time)
            approval = self._approvals.get(request_id)
            if approval is None:
                raise KeyError(f"Unknown approval request: {request_id}")
            if approval.status is ApprovalStatus.APPROVED:
                return self._authorizations[request_id][1]
            if approval.status is ApprovalStatus.REJECTED:
                raise ValueError("The approval request has already been rejected.")

            request, _ = self._authorizations[request_id]
            current_decision = self._evaluate_unlocked(
                request,
                now=resolution_time,
            )
            if current_decision.decision is Decision.DENY:
                raise ValueError(
                    "The action no longer satisfies runtime policy: "
                    f"{current_decision.explanation}"
                )

            approved_decision = replace(
                current_decision,
                decision=Decision.ALLOW,
                findings=tuple(
                    finding
                    for finding in current_decision.findings
                    if finding.code != "HUMAN_APPROVAL_REQUIRED"
                )
                + (
                    PolicyFinding(
                        code="HUMAN_APPROVAL_GRANTED",
                        message=f"Operator {reviewer} approved the high-risk action.",
                        blocking=False,
                    ),
                ),
            )
            self._approvals[request_id] = replace(
                approval,
                status=ApprovalStatus.APPROVED,
                reviewer=reviewer,
                reason=reason,
                resolved_at=resolution_time,
            )
            self.audit_ledger.append(
                "approval.approved",
                {
                    "request_id": request_id,
                    "agent_id": request.agent_id,
                    "reviewer": reviewer,
                    "reason": reason,
                },
            )
            return self._issue_authorization_unlocked(
                request,
                approved_decision,
                evaluation_time=resolution_time,
                lease_ttl=lease_ttl,
            )

    def reject_action(
        self,
        request_id: str,
        *,
        reviewer: str,
        reason: str,
        now: datetime | None = None,
    ) -> HumanApproval:
        """Reject a pending review and replace its decision with a final denial."""

        resolution_time = now or datetime.now(timezone.utc)
        with self._lock:
            approval = self._approvals.get(request_id)
            if approval is None:
                raise KeyError(f"Unknown approval request: {request_id}")
            if approval.status is ApprovalStatus.REJECTED:
                return approval
            if approval.status is ApprovalStatus.APPROVED:
                raise ValueError("The approval request has already been approved.")

            request, previous_result = self._authorizations[request_id]
            rejected_decision = replace(
                previous_result.decision,
                decision=Decision.DENY,
                findings=tuple(
                    finding
                    for finding in previous_result.decision.findings
                    if finding.code != "HUMAN_APPROVAL_REQUIRED"
                )
                + (
                    PolicyFinding(
                        code="HUMAN_APPROVAL_REJECTED",
                        message=f"Operator {reviewer} rejected the high-risk action.",
                        blocking=True,
                    ),
                ),
            )
            self._authorizations[request_id] = (
                request,
                AuthorizationResult(decision=rejected_decision),
            )
            rejected = replace(
                approval,
                status=ApprovalStatus.REJECTED,
                reviewer=reviewer,
                reason=reason,
                resolved_at=resolution_time,
            )
            self._approvals[request_id] = rejected
            self.audit_ledger.append(
                "approval.rejected",
                {
                    "request_id": request_id,
                    "agent_id": request.agent_id,
                    "reviewer": reviewer,
                    "reason": reason,
                },
            )
            return rejected

    def _issue_authorization_unlocked(
        self,
        request: ActionRequest,
        decision: DecisionRecord,
        *,
        evaluation_time: datetime,
        lease_ttl: timedelta,
    ) -> AuthorizationResult:
        """Reserve budget and issue a lease while the engine lock is held."""

        expires_at = evaluation_time + lease_ttl
        reservation = BudgetReservation(
            reservation_id=f"res_{uuid4().hex}",
            request_id=request.request_id,
            agent_id=request.agent_id,
            amount=request.amount,
            currency=request.currency,
            budget_date=evaluation_time.date(),
            expires_at=expires_at,
        )
        lease = AuthorizationLease(
            lease_id=f"lease_{uuid4().hex}",
            request_id=request.request_id,
            agent_id=request.agent_id,
            reservation_id=reservation.reservation_id,
            fleet_epoch=self._fleet_epoch,
            issued_at=evaluation_time,
            expires_at=expires_at,
        )
        key = (request.agent_id, reservation.budget_date)
        self._reserved_spend[key] += request.amount
        self._authorization_counts[key] += 1
        self._reservations[reservation.reservation_id] = reservation
        self._leases[lease.lease_id] = lease

        decision = replace(
            decision,
            remaining_daily_budget=max(
                decision.remaining_daily_budget - request.amount,
                Decimal("0"),
            ),
        )
        result = AuthorizationResult(
            decision=decision,
            reservation=reservation,
            lease=lease,
        )
        self._authorizations[request.request_id] = (request, result)
        self.audit_ledger.append(
            "budget.reserved",
            {
                "reservation_id": reservation.reservation_id,
                "request_id": request.request_id,
                "agent_id": request.agent_id,
                "amount": request.amount,
                "currency": request.currency,
                "expires_at": expires_at,
                "fleet_epoch": self._fleet_epoch,
            },
        )
        return result

    @staticmethod
    def _conflicting_fields(
        previous: ActionRequest, current: ActionRequest
    ) -> tuple[str, ...]:
        """Name the action fields that differ, ignoring client/server timestamps.

        Only the field names are returned. The submitted values are attacker
        controlled and are deliberately not copied into the audit payload.
        """

        return tuple(
            field
            for field in (
                "request_id",
                "agent_id",
                "action",
                "amount",
                "currency",
                "intent_id",
                "risk_score",
                "attributes",
                "customer_id",
            )
            if getattr(previous, field) != getattr(current, field)
        )

    @classmethod
    def _same_idempotent_request(
        cls, previous: ActionRequest, current: ActionRequest
    ) -> bool:
        """Compare action semantics while ignoring client/server timestamp drift."""

        return not cls._conflicting_fields(previous, current)

    def commit_reservation(
        self,
        reservation_id: str,
        *,
        lease_id: str,
        now: datetime | None = None,
    ) -> BudgetReservation:
        """Consume a held reservation after the protected action succeeds."""

        commit_time = now or datetime.now(timezone.utc)
        with self._lock:
            self._expire_reservations_unlocked(commit_time)
            reservation = self._require_reservation_unlocked(reservation_id)
            lease = self._leases.get(lease_id)
            if lease is None or lease.reservation_id != reservation_id:
                raise ValueError("The execution lease is invalid for this reservation.")
            if lease.is_expired(commit_time):
                raise ValueError("The execution lease has expired.")
            if lease.fleet_epoch != self._fleet_epoch or self._fleet_stopped:
                raise ValueError("The execution lease was invalidated by a fleet stop.")
            if reservation.agent_id in self._revoked_agents:
                raise ValueError("The execution lease belongs to a revoked agent.")
            if reservation.status is not ReservationStatus.HELD:
                raise ValueError(
                    f"Reservation is {reservation.status.value}, not held."
                )

            key = (reservation.agent_id, reservation.budget_date)
            self._reserved_spend[key] -= reservation.amount
            self._daily_spend[key] += reservation.amount
            committed = replace(
                reservation,
                status=ReservationStatus.COMMITTED,
            )
            self._reservations[reservation_id] = committed
            self.audit_ledger.append(
                "budget.committed",
                {
                    "reservation_id": reservation_id,
                    "request_id": reservation.request_id,
                    "agent_id": reservation.agent_id,
                    "amount": reservation.amount,
                    "currency": reservation.currency,
                },
            )
            return committed

    def release_reservation(
        self,
        reservation_id: str,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> BudgetReservation:
        """Release a held reservation after failure or cancellation."""

        with self._lock:
            self._expire_reservations_unlocked(now or datetime.now(timezone.utc))
            reservation = self._require_reservation_unlocked(reservation_id)
            if reservation.status is not ReservationStatus.HELD:
                raise ValueError(
                    f"Reservation is {reservation.status.value}, not held."
                )
            return self._release_reservation_unlocked(
                reservation,
                status=ReservationStatus.RELEASED,
                reason=reason,
            )

    def get_reservation(self, reservation_id: str) -> BudgetReservation | None:
        with self._lock:
            self._expire_reservations_unlocked(datetime.now(timezone.utc))
            return self._reservations.get(reservation_id)

    def _require_reservation_unlocked(
        self, reservation_id: str
    ) -> BudgetReservation:
        reservation = self._reservations.get(reservation_id)
        if reservation is None:
            raise KeyError(f"Unknown reservation: {reservation_id}")
        return reservation

    def _expire_reservations_unlocked(self, now: datetime) -> None:
        for reservation in tuple(self._reservations.values()):
            if (
                reservation.status is ReservationStatus.HELD
                and now >= reservation.expires_at
            ):
                self._release_reservation_unlocked(
                    reservation,
                    status=ReservationStatus.EXPIRED,
                    reason="lease_expired",
                )

    def _release_reservation_unlocked(
        self,
        reservation: BudgetReservation,
        *,
        status: ReservationStatus,
        reason: str,
    ) -> BudgetReservation:
        key = (reservation.agent_id, reservation.budget_date)
        self._reserved_spend[key] -= reservation.amount
        released = replace(reservation, status=status)
        self._reservations[reservation.reservation_id] = released
        self.audit_ledger.append(
            "budget.released",
            {
                "reservation_id": reservation.reservation_id,
                "request_id": reservation.request_id,
                "agent_id": reservation.agent_id,
                "amount": reservation.amount,
                "currency": reservation.currency,
                "status": status.value,
                "reason": reason,
            },
        )
        return released

    def record_execution(
        self,
        request: ActionRequest,
        decision: DecisionRecord,
        *,
        executed_at: datetime | None = None,
    ) -> None:
        """Record spend for an already-executed action, re-checking the cap.

        A :class:`DecisionRecord` only observes the budget; it does not hold it.
        By the time an action is recorded the headroom the decision saw may be
        gone, so the cap is re-checked here against live committed and reserved
        exposure. Callers that need the funds held across the gap should use
        :meth:`authorize_action` and :meth:`commit_reservation` instead.
        """

        with self._lock:
            if decision.decision is not Decision.ALLOW:
                raise ValueError("Only allowed actions can be recorded as executed.")
            if decision.request_id != request.request_id:
                raise ValueError("The decision belongs to a different request.")
            timestamp = executed_at or datetime.now(timezone.utc)
            self._expire_reservations_unlocked(timestamp)
            agent = self._agents.get(request.agent_id)
            if agent is None:
                raise KeyError(f"Unknown agent: {request.agent_id}")

            key = (request.agent_id, timestamp.date())
            exposure = self._daily_spend[key] + self._reserved_spend[key]
            if request.amount > agent.daily_budget - exposure:
                self.audit_ledger.append(
                    "action.execution_rejected",
                    {
                        "request_id": request.request_id,
                        "agent_id": request.agent_id,
                        "amount": request.amount,
                        "currency": request.currency,
                        "reason": "daily_budget_exceeded",
                    },
                )
                raise ValueError(
                    "The action exceeds the agent's remaining daily budget."
                )

            self._daily_spend[key] += request.amount
            self.audit_ledger.append(
                "action.executed",
                {
                    "request_id": request.request_id,
                    "agent_id": request.agent_id,
                    "amount": request.amount,
                    "currency": request.currency,
                },
            )

    def _derive_risk(
        self,
        request: ActionRequest,
        agent: AgentProfile | None,
        intent: IntentPassport | None,
        *,
        exposure: Decimal,
        evaluation_time: datetime,
    ) -> tuple[int, tuple[str, ...]]:
        """Score an action from state the requesting agent cannot forge.

        Every input here comes from the operator-registered agent profile, the
        separately registered customer intent, or the engine's own spend and
        authorization history. Nothing is taken from the agent's self-reported
        risk. Weights are deliberately calibrated so that no single dimension at
        100% reaches ``review_risk_threshold`` on its own: sitting at the top of
        a limit the operator granted is not by itself suspicious, but doing so
        repeatedly, or while deviating from the authorized envelope, is.
        """

        score = 0
        signals: list[str] = []

        def add(points: int, signal: str) -> None:
            nonlocal score
            if points > 0:
                score += points
                signals.append(signal)

        if intent is not None and intent.max_amount > 0:
            ratio = min(request.amount / intent.max_amount, Decimal("1"))
            add(
                int(ratio * self.RISK_WEIGHT_INTENT_UTILIZATION),
                f"intent_utilization={ratio:.2f}",
            )

        if agent is not None and agent.daily_budget > 0:
            ratio = min(
                (exposure + request.amount) / agent.daily_budget, Decimal("1")
            )
            add(
                int(ratio * self.RISK_WEIGHT_BUDGET_EXPOSURE),
                f"budget_exposure={ratio:.2f}",
            )

        prior = self._authorization_counts[
            (request.agent_id, evaluation_time.date())
        ]
        add(
            min(
                prior * self.RISK_POINTS_PER_PRIOR_AUTHORIZATION,
                self.RISK_WEIGHT_VELOCITY,
            ),
            f"prior_authorizations_today={prior}",
        )

        # A non-refundable commitment the customer never asked to be refundable
        # is a real exposure. If the intent required refundable=True, a false
        # value is already a blocking mismatch and is not double counted here.
        constrained = intent.required_attributes if intent is not None else {}
        if request.attributes.get("refundable") is False and (
            "refundable" not in constrained
        ):
            add(self.RISK_WEIGHT_NON_REFUNDABLE, "non_refundable")

        unconstrained = sorted(
            key for key in request.attributes if key not in constrained
        )
        if unconstrained:
            add(
                min(
                    len(unconstrained) * self.RISK_POINTS_PER_UNCONSTRAINED_ATTRIBUTE,
                    self.RISK_WEIGHT_UNCONSTRAINED_ATTRIBUTES,
                ),
                f"unconstrained_attributes={','.join(unconstrained)}",
            )

        return min(score, 100), tuple(signals)

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
