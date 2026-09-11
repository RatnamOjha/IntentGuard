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


class ClaimReason(str, Enum):
    """Why the customer says the order went wrong.

    Closed set on purpose. A free-text reason would be attacker-controlled
    text reaching policy and an operator's screen, which is the mistake
    Decisions #5 avoided for the ledger and `FindingContext` avoided for
    findings.
    """

    DEFECT = "defect"
    NOT_DELIVERED = "not_delivered"
    LATE = "late"
    CHANGED_MIND = "changed_mind"


class RemedyKind(str, Enum):
    """How a claim may be settled, if at all."""

    REFUND_TO_SOURCE = "refund_to_source"
    STORE_CREDIT = "store_credit"
    SHIPPING_REFUND = "shipping_refund"
    RESCHEDULE = "reschedule"
    NONE = "none"


@dataclass(frozen=True)
class RefundClaim:
    """What the agent asserts about the complaint behind this action.

    **Every field here is an agent assertion, not a verified fact.** The
    gateway has no way to confirm a photo exists or that delivery was late;
    in a real deployment those come from the merchant's order system, and
    the honest description of this structure is "what the agent says".

    That is safe only because of one rule the engine enforces: *a claim may
    narrow the remedy, never widen it*. The permitted amount is always capped
    by the agent's own per-action limit and the customer's intent, so an agent
    that lies about the claim can at most reach what it was already authorised
    for. Evidence buys a better remedy **within** existing authority; it can
    never buy more authority. Break that rule and the claim becomes a
    self-service permission escalation.
    """

    reason: ClaimReason
    #: What the order was worth. Bounds a full refund.
    order_value: Decimal
    days_since_delivery: int
    #: Supporting material the agent says exists, e.g. "photo", "courier_scan".
    evidence: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Remedy:
    """The settlement policy permits for a claim -- an envelope, not an order.

    The agent chooses what to propose; policy says what may be honoured. When
    the two disagree the proposal is refused and this says what would have
    passed instead.
    """

    kind: RemedyKind
    #: Ceiling in the request's currency. Zero means "nothing is permitted".
    cap: Decimal


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
    # What the agent says the complaint is. Optional so every existing caller
    # keeps working; when absent the engine applies no claim-based rules.
    claim: RefundClaim | None = None
    occurred_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@dataclass(frozen=True)
class FindingContext:
    """The engine-derived values behind a finding, typed rather than free text.

    Only values the engine itself computed or read from policy belong here: a
    ceiling from an agent policy or intent, the amount the engine measured
    against it, or the set of actions a policy permits. Request-supplied text
    is deliberately excluded -- it is attacker-controlled, and echoing it back
    onto an operator's screen is the same mistake Decisions #5 avoided for the
    audit ledger, which records the *names* of conflicting fields and not their
    submitted values.
    """

    #: The ceiling the engine compared against, in the request's currency.
    limit: Decimal | None = None
    #: The value that breached ``limit``. Always engine-side, never echoed.
    actual: Decimal | None = None
    #: The actions this agent's policy permits. Unordered; sort for display.
    permitted: frozenset[str] | None = None


@dataclass(frozen=True)
class PolicyFinding:
    """One policy observation supporting a decision."""

    code: str
    message: str
    blocking: bool
    #: Present only for findings that compared a number or a permitted set.
    #: ``None`` for the boolean and membership checks, which have no operands
    #: worth showing.
    context: FindingContext | None = None


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
    #: What policy would permit for this claim. Present only when the request
    #: carried one. On a refusal this is the "what would have passed" answer.
    remedy: Remedy | None = None

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
