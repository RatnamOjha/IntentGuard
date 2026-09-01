"""Domain models used by the IntentGuard policy engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any


class Decision(str, Enum):
    """Possible outcomes returned by the runtime policy engine."""

    ALLOW = "allow"
    DENY = "deny"
    REVIEW = "review"


class ReservationStatus(str, Enum):
    """Lifecycle states for an atomic budget reservation."""

    HELD = "held"
    COMMITTED = "committed"
    RELEASED = "released"
    EXPIRED = "expired"


class ApprovalStatus(str, Enum):
    """Lifecycle states for a human-review request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass(frozen=True)
class AgentProfile:
    """Registration and policy envelope assigned to a financial agent."""

    agent_id: str
    name: str
    allowed_actions: frozenset[str]
    max_action_amount: Decimal
    daily_budget: Decimal
    active: bool = True


@dataclass(frozen=True)
class IntentPassport:
    """A machine-readable representation of authenticated customer intent."""

    intent_id: str
    customer_id: str
    agent_id: str
    action: str
    max_amount: Decimal
    currency: str
    expires_at: datetime
    required_attributes: dict[str, Any] = field(default_factory=dict)
    issuer: str = ""
    audience: str = ""
    issued_at: datetime | None = None
    not_before: datetime | None = None
    nonce: str = ""
    key_id: str = ""
    signature: str = ""

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at


@dataclass(frozen=True)
class ActionRequest:
    """An action proposed by an agent and intercepted before execution."""

    request_id: str
    agent_id: str
    action: str
    amount: Decimal
    currency: str
    intent_id: str
    risk_score: int
    attributes: dict[str, Any] = field(default_factory=dict)
    # The customer on whose behalf the action is proposed. Optional so existing
    # single-customer callers keep working, but when supplied the engine
    # requires the cited intent to belong to this customer. Authenticated
    # callers must always set it from the verified session, never from agent
    # input.
    customer_id: str | None = None
    # Verified token subject that submitted the action. The policy engine uses
    # this for separation of duties when a request reaches human review.
    submitted_by: str | None = None
    occurred_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@dataclass(frozen=True)
class PolicyFinding:
    """One policy observation supporting a decision."""

    code: str
    message: str
    blocking: bool


@dataclass(frozen=True)
class RiskAssessment:
    """Risk the gateway derived, and how the agent's own claim compared.

    ``declared`` is supplied by the agent and is untrusted. ``derived`` is
    computed by the gateway from state the agent cannot forge. ``effective`` is
    the maximum of the two: an agent may raise its own risk but never lower it.
    """

    declared: int
    derived: int
    signals: tuple[str, ...] = ()

    @property
    def effective(self) -> int:
        return max(self.declared, self.derived)

    @property
    def under_declared(self) -> bool:
        return self.declared < self.derived


@dataclass(frozen=True)
class DecisionRecord:
    """Complete, explainable result of a policy evaluation."""

    request_id: str
    decision: Decision
    findings: tuple[PolicyFinding, ...]
    remaining_daily_budget: Decimal
    policy_version: str
    risk: RiskAssessment | None = None

    @property
    def explanation(self) -> str:
        return " ".join(finding.message for finding in self.findings)


@dataclass(frozen=True)
class BudgetReservation:
    """Funds held against an agent budget before external execution."""

    reservation_id: str
    request_id: str
    agent_id: str
    amount: Decimal
    currency: str
    budget_date: date
    expires_at: datetime
    status: ReservationStatus = ReservationStatus.HELD


@dataclass(frozen=True)
class AuthorizationLease:
    """Short-lived, single-use authorization bound to a fleet epoch."""

    lease_id: str
    request_id: str
    agent_id: str
    reservation_id: str
    fleet_epoch: int
    issued_at: datetime
    expires_at: datetime
    action: str = ""
    amount: Decimal = Decimal("0")
    currency: str = ""
    issuer: str = ""
    audience: str = ""
    key_id: str = ""
    token: str = ""

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at


@dataclass(frozen=True)
class AuthorizationResult:
    """Policy decision plus execution artifacts when an action is allowed."""

    decision: DecisionRecord
    reservation: BudgetReservation | None = None
    lease: AuthorizationLease | None = None


@dataclass(frozen=True)
class HumanApproval:
    """Operator decision required before a high-risk action can execute."""

    request_id: str
    agent_id: str
    action: str
    amount: Decimal
    currency: str
    risk_score: int
    created_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    reviewer: str | None = None
    reason: str | None = None
    resolved_at: datetime | None = None
