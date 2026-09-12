"""Evidence upload and serving.

These bytes arrive from outside, are chosen by whoever files the complaint,
and end up rendered in an operator's browser. The tests below are about that
path rather than about storage.
"""

from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from fastapi.testclient import TestClient  # noqa: E402

from intentguard import PolicyEngine  # noqa: E402
from intentguard.evidence import (  # noqa: E402
    MAX_BYTES,
    EvidenceValidationError,
    InMemoryEvidenceStore,
    sniff_media_type,
)
from intentguard.models import EvidenceKind  # noqa: E402
from tests.jwt_test_support import bearer  # noqa: E402
from tests.test_api import test_authenticator  # noqa: E402

# A real 1x1 PNG, not a handcrafted header.
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
    "YPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)
SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">'
    b"<script>alert(1)</script></svg>"
)


class SniffingTest(unittest.TestCase):
    """The declared type proves nothing; the bytes decide."""

    def test_real_images_are_recognised(self) -> None:
        self.assertEqual("image/png", sniff_media_type(PNG))
        self.assertEqual("image/jpeg", sniff_media_type(b"\xff\xd8\xff\xe0" + b"0" * 32))
        self.assertEqual(
            "image/webp",
            sniff_media_type(b"RIFF" + b"\x00" * 4 + b"WEBP" + b"0" * 32),
        )

    def test_svg_is_refused(self) -> None:
        """It is a script-bearing document, not a picture.

        It has no magic number, so signature sniffing rejects it as a
        consequence of how the check works rather than by a rule someone has
        to remember to keep.
        """

        with self.assertRaises(EvidenceValidationError):
            sniff_media_type(SVG)

    def test_a_riff_container_that_is_not_webp_is_refused(self) -> None:
        """RIFF alone could be audio. Both ends of the header have to match."""

        with self.assertRaises(EvidenceValidationError):
            sniff_media_type(b"RIFF" + b"\x00" * 4 + b"WAVE" + b"0" * 32)

    def test_html_is_refused(self) -> None:
        with self.assertRaises(EvidenceValidationError):
            sniff_media_type(b"<!doctype html><script>alert(1)</script>")


class StoreTest(unittest.TestCase):
    def test_references_are_generated_not_supplied(self) -> None:
        """The reference becomes a URL segment and a filename."""

        store = InMemoryEvidenceStore()
        first = store.put(kind=EvidenceKind.PHOTO, content=PNG, uploaded_by="c1")
        second = store.put(kind=EvidenceKind.PHOTO, content=PNG, uploaded_by="c1")

        self.assertNotEqual(first.reference, second.reference)
        self.assertTrue(first.reference.startswith("ev_"))
        self.assertTrue(first.filename.endswith(".png"))

    def test_oversized_content_is_refused(self) -> None:
        store = InMemoryEvidenceStore()
        with self.assertRaises(EvidenceValidationError):
            store.put(
                kind=EvidenceKind.PHOTO,
                content=PNG + b"\x00" * MAX_BYTES,
                uploaded_by="c1",
            )


def customer_headers(subject: str = "evidence-customer") -> dict[str, str]:
    return bearer(
        subject=subject,
        roles=["customer"],
        customer_id="customer-01",
        agent_id="ada",
    )


class EvidenceApiTest(unittest.TestCase):
    def setUp(self) -> None:
        from intentguard.api import create_app

        self.client = TestClient(
            create_app(PolicyEngine(), authenticator=test_authenticator())
        )

    def upload(self, content: bytes, kind: str = "photo"):
        return self.client.post(
            "/v1/evidence",
            json={
                "kind": kind,
                "content_base64": base64.b64encode(content).decode(),
            },
            headers=customer_headers(),
        )

    def test_a_photo_round_trips(self) -> None:
        created = self.upload(PNG)
        self.assertEqual(201, created.status_code)
        body = created.json()
        self.assertEqual("image/png", body["media_type"])

        fetched = self.client.get(
            f"/v1/evidence/{body['reference']}", headers=customer_headers()
        )
        self.assertEqual(200, fetched.status_code)
        self.assertEqual(PNG, fetched.content)

    def test_the_response_cannot_be_talked_into_executing(self) -> None:
        """Serving is as hostile as receiving."""

        reference = self.upload(PNG).json()["reference"]
        response = self.client.get(
            f"/v1/evidence/{reference}", headers=customer_headers()
        )

        self.assertEqual("image/png", response.headers["content-type"])
        self.assertEqual("nosniff", response.headers["x-content-type-options"])
        self.assertIn("default-src 'none'", response.headers["content-security-policy"])
        self.assertIn("sandbox", response.headers["content-security-policy"])
        self.assertTrue(
            response.headers["content-disposition"].startswith("inline;")
        )
        # The filename is generated, so nothing a caller sent reaches it.
        self.assertIn(reference, response.headers["content-disposition"])

    def test_an_svg_is_refused_at_the_boundary(self) -> None:
        response = self.upload(SVG)
        self.assertEqual(422, response.status_code)
        self.assertIn("SVG", response.json()["detail"])

    def test_content_that_is_not_base64_is_refused(self) -> None:
        response = self.client.post(
            "/v1/evidence",
            json={"kind": "photo", "content_base64": "not base64 at all!!"},
            headers=customer_headers(),
        )
        self.assertEqual(422, response.status_code)

    def test_an_unknown_reference_is_a_404_not_a_500(self) -> None:
        response = self.client.get(
            "/v1/evidence/ev_deadbeefdeadbeefdeadbeefdeadbeef",
            headers=customer_headers(),
        )
        self.assertEqual(404, response.status_code)

    def test_evidence_requires_authentication(self) -> None:
        reference = self.upload(PNG).json()["reference"]
        self.assertEqual(
            401, self.client.get(f"/v1/evidence/{reference}").status_code
        )
        self.assertEqual(401, self.client.post("/v1/evidence", json={}).status_code)

    def test_the_upload_is_recorded_in_the_audit_chain(self) -> None:
        """Bytes reaching the operator's screen should be attributable."""

        reference = self.upload(PNG).json()["reference"]
        events = self.client.get(
            "/v1/audit/events",
            headers=bearer(
                subject="op", roles=["operator"], customer_id="customer-01",
                agent_id="ada",
            ),
        )
        self.assertEqual(200, events.status_code)
        self.assertIn(reference, events.text)
        self.assertIn("evidence.stored", events.text)
