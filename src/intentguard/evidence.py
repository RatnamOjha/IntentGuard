"""Storage for evidence images attached to a refund claim.

The threat model is narrow and worth stating. These bytes arrive from outside,
are chosen by whoever files the complaint, and are later rendered in an
operator's browser. Three things follow:

* **The declared type is not evidence of anything.** Every upload is sniffed
  and must match one of a small allowlist by magic bytes. A file that says
  ``image/png`` and does not begin with the PNG signature is refused.
* **SVG is never accepted.** It is a script-bearing document, not a picture,
  and it has no magic number -- which is why sniffing rejects it for free
  rather than by a rule someone could forget to keep.
* **Serving is as hostile as receiving.** The stored media type is the
  validated one, never the caller's claim, and the response carries nosniff,
  an inline disposition with a generated filename, and a CSP that permits
  nothing at all.

The gateway holds these only because the console needs to show them. Nothing
in policy reads an image, and no decision depends on one.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Protocol

from .models import EvidenceKind

#: Generous for a phone photo, small enough that a base64 body stays sane.
MAX_BYTES = 5 * 1024 * 1024

#: Magic-byte signatures for the only types accepted. Checked against the
#: bytes themselves; the caller's Content-Type is never trusted.
_SIGNATURES: tuple[tuple[str, tuple[bytes, ...]], ...] = (
    ("image/jpeg", (b"\xff\xd8\xff",)),
    ("image/png", (b"\x89PNG\r\n\x1a\n",)),
)

ALLOWED_MEDIA_TYPES = frozenset(media_type for media_type, _ in _SIGNATURES) | {
    "image/webp"
}

_EXTENSION = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
}


class EvidenceValidationError(ValueError):
    """The bytes are not something this service will store or serve."""


@dataclass(frozen=True)
class StoredEvidence:
    reference: str
    kind: EvidenceKind
    #: The sniffed type, not the declared one.
    media_type: str
    content: bytes
    uploaded_at: datetime
    uploaded_by: str

    @property
    def filename(self) -> str:
        return f"{self.reference}.{_EXTENSION.get(self.media_type, 'bin')}"


def sniff_media_type(content: bytes) -> str:
    """Identify the bytes, or refuse them.

    WebP needs both ends of its header checked: ``RIFF`` alone is a container
    that could hold audio just as easily.
    """

    for media_type, signatures in _SIGNATURES:
        if any(content.startswith(signature) for signature in signatures):
            return media_type
    if len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        return "image/webp"
    raise EvidenceValidationError(
        "Evidence must be a JPEG, PNG or WebP image. The uploaded bytes match "
        "none of those signatures. SVG is deliberately not accepted: it is a "
        "script-bearing document rather than a picture."
    )


def validate(content: bytes) -> str:
    if not content:
        raise EvidenceValidationError("The upload is empty.")
    if len(content) > MAX_BYTES:
        raise EvidenceValidationError(
            f"Evidence is limited to {MAX_BYTES // (1024 * 1024)} MiB; "
            f"this upload is {len(content) // 1024} KiB."
        )
    return sniff_media_type(content)


class EvidenceStore(Protocol):
    def put(
        self, *, kind: EvidenceKind, content: bytes, uploaded_by: str
    ) -> StoredEvidence: ...
    def get(self, reference: str) -> StoredEvidence | None: ...


class InMemoryEvidenceStore:
    """Process-local storage. Enough for the console; not durable."""

    def __init__(self, *, max_items: int = 200) -> None:
        self._items: dict[str, StoredEvidence] = {}
        self._order: list[str] = []
        self._max_items = max_items
        self._lock = RLock()

    def put(
        self, *, kind: EvidenceKind, content: bytes, uploaded_by: str
    ) -> StoredEvidence:
        media_type = validate(content)
        # Generated, never caller-supplied: the reference becomes part of a URL
        # and a filename, so it must not be somewhere a caller can steer.
        reference = f"ev_{secrets.token_hex(16)}"
        stored = StoredEvidence(
            reference=reference,
            kind=kind,
            media_type=media_type,
            content=content,
            uploaded_at=datetime.now(timezone.utc),
            uploaded_by=uploaded_by,
        )
        with self._lock:
            self._items[reference] = stored
            self._order.append(reference)
            while len(self._order) > self._max_items:
                self._items.pop(self._order.pop(0), None)
        return stored

    def get(self, reference: str) -> StoredEvidence | None:
        with self._lock:
            return self._items.get(reference)
