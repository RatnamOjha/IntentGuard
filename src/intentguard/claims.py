"""Shared claim payload validation for HTTP callers and model proposals.

Citations are assertions, not verified evidence. The same boundary validates both
entry points so planner output cannot claim evidence without a reference.
"""

from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from .models import ClaimReason, EvidenceArtifact, EvidenceKind, RefundClaim


class EvidenceArtifactPayload(BaseModel):
    """A citation, not an upload. The gateway never fetches the reference."""

    model_config = ConfigDict(extra="forbid")

    kind: EvidenceKind
    reference: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:/-]+$")


class ClaimPayload(BaseModel):
    """The complaint behind a proposed action, as the agent describes it.

    Closed enums rather than free text: a reason that reached policy as an
    arbitrary string would be attacker-controlled input steering a decision,
    and `extra="forbid"` means a misspelled field is a 422 rather than a
    silently ignored constraint.
    """

    model_config = ConfigDict(extra="forbid")

    reason: ClaimReason
    order_value: Decimal = Field(gt=0, allow_inf_nan=False)
    days_since_delivery: int = Field(ge=0, le=3650)
    #: The merchant's order or transaction id. Constrained rather than free
    #: text: it is shown to an operator and written to the audit trail, and
    #: an identifier has no business containing markup or newlines.
    order_reference: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$"
    )
    #: Evidence is *derived* from these, never accepted directly. A claim
    #: cannot assert that a photo exists without naming a reference that an
    #: investigator could take back to the order system and check.
    artifacts: list[EvidenceArtifactPayload] = Field(
        default_factory=list, max_length=16
    )
    #: The customer's words. Capped, and quarantined everywhere downstream --
    #: see RefundClaim.complaint.
    complaint: str | None = Field(default=None, max_length=2000)

    @property
    def derived_evidence(self) -> frozenset[str]:
        return frozenset(artifact.kind.value for artifact in self.artifacts)

    def to_claim(self) -> RefundClaim:
        """Preserve assertions and citations without treating them as verified facts."""
        return RefundClaim(
            reason=self.reason,
            order_value=self.order_value,
            days_since_delivery=self.days_since_delivery,
            evidence=self.derived_evidence,
            order_reference=self.order_reference,
            artifacts=tuple(
                EvidenceArtifact(kind=item.kind, reference=item.reference)
                for item in self.artifacts
            ),
            complaint=self.complaint,
        )
