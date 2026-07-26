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
    AuthorizationLease,
    AuthorizationResult,
    BudgetReservation,
    Decision,
    DecisionRecord,
    IntentPassport,
    PolicyFinding,
    ReservationStatus,
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
        self._reserved_spend: dict[tuple[str, date], Decimal] = defaultdict(
            lambda: Decimal("0")
        )
        self._reservations: dict[str, BudgetReservation] = {}
        self._leases: dict[str, AuthorizationLease] = {}
        self._authorizations: dict[
            str, tuple[ActionRequest, AuthorizationResult]
        ] = {}
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
                if not self._same_idempotent_request(previous_request, request):
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
            if decision.decision is not Decision.ALLOW:
                result = AuthorizationResult(decision=decision)
                self._authorizations[request.request_id] = (request, result)
                return result

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
    def _same_idempotent_request(
        previous: ActionRequest, current: ActionRequest
    ) -> bool:
        """Compare action semantics while ignoring client/server timestamp drift."""

        return (
            previous.request_id == current.request_id
            and previous.agent_id == current.agent_id
            and previous.action == current.action
            and previous.amount == current.amount
            and previous.currency == current.currency
            and previous.intent_id == current.intent_id
            and previous.risk_score == current.risk_score
            and previous.attributes == current.attributes
        )

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
            if reservation.status is not ReservationStatus.HELD:
                raise ValueError(
                    f"Reservation is {reservation.status.value}, not held."
                )
            if lease.is_expired(commit_time):
                raise ValueError("The execution lease has expired.")
            if lease.fleet_epoch != self._fleet_epoch or self._fleet_stopped:
                raise ValueError("The execution lease was invalidated by a fleet stop.")
            if reservation.agent_id in self._revoked_agents:
                raise ValueError("The execution lease belongs to a revoked agent.")

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
        with self._lock:
            if decision.decision is not Decision.ALLOW:
                raise ValueError("Only allowed actions can be recorded as executed.")
            if decision.request_id != request.request_id:
                raise ValueError("The decision belongs to a different request.")
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

