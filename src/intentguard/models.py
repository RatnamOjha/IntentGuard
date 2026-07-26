"""Domain models used by the IntentGuard policy engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any


class Decision(str, Enum):
    """Possible outcomes returned by the runtime policy engine."""

    ALLOW = "allow"
    DENY = "deny"
    REVIEW = "review"


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
class DecisionRecord:
    """Complete, explainable result of a policy evaluation."""

    request_id: str
    decision: Decision
    findings: tuple[PolicyFinding, ...]
    remaining_daily_budget: Decimal
    policy_version: str

    @property
    def explanation(self) -> str:
        return " ".join(finding.message for finding in self.findings)
