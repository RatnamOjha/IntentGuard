"""Small RS256 token factory used only by authentication tests."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

N = int(
    "116919977022714796681358840957735263500093282527647112998302498508041"
    "075007706974840223549038582744749182005610583262291780414730852414091"
    "48263274373356169"
)
E = 65537
D = int(
    "789379773765058151694475584151992340828635346750812794121777110866425"
    "598648994433984271784532352757888724472273285412645713338420818505064"
    "2164746016997233"
)
KID = "intentguard-test-key"
ISSUER = "https://identity.intentguard.test"
AUDIENCE = "intentguard-api"
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def integer_bytes(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KID,
            "n": b64(integer_bytes(N)),
            "e": b64(integer_bytes(E)),
        }
    ]
}


def token(
    *,
    subject: str = "user-01",
    roles: list[str] | None = None,
    expires_delta: timedelta = timedelta(minutes=5),
    **claims: Any,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "roles": roles or [],
        **claims,
    }
    header = {"alg": "RS256", "typ": "JWT", "kid": KID}
    encoded_header = b64(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    digest = SHA256_DIGEST_INFO + hashlib.sha256(signing_input).digest()
    size = (N.bit_length() + 7) // 8
    encoded_message = (
        b"\x00\x01" + b"\xff" * (size - len(digest) - 3) + b"\x00" + digest
    )
    signature = pow(int.from_bytes(encoded_message, "big"), D, N).to_bytes(
        size, "big"
    )
    return f"{encoded_header}.{encoded_payload}.{b64(signature)}"


def bearer(**claims: Any) -> dict[str, str]:
    return {"Authorization": f"Bearer {token(**claims)}"}
