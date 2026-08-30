"""Local-only JWKS server and token issuer for the authenticated demo.

This is deliberately not an account system. It binds only to loopback, creates
an ephemeral RSA key at startup, and lets local developers mint short-lived
tokens for any demo role. Use Keycloak or another real identity provider
outside local development.

Start it with ``python examples/local_jwks_server.py``. Then request a token:

    curl -X POST http://127.0.0.1:9000/token \
      -H "Content-Type: application/json" \
      -d '{"sub":"demo-admin","roles":["admin"],
           "agent_id":"agt_travel_01","customer_id":"demo-customer"}'
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import secrets
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

ISSUER = "http://127.0.0.1:9000"
AUDIENCE = "intentguard-api"
KEY_ID = "intentguard-local-dev"
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _integer_bytes(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _probable_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | 1 | (1 << (bits - 1))
        if any(candidate % prime == 0 for prime in (3, 5, 7, 11, 13, 17, 19)):
            continue
        odd_part = candidate - 1
        powers = 0
        while odd_part % 2 == 0:
            powers += 1
            odd_part //= 2
        probably_prime = True
        for _ in range(24):
            base = secrets.randbelow(candidate - 3) + 2
            value = pow(base, odd_part, candidate)
            if value in (1, candidate - 1):
                continue
            for _ in range(powers - 1):
                value = pow(value, 2, candidate)
                if value == candidate - 1:
                    break
            else:
                probably_prime = False
                break
        if probably_prime:
            return candidate


def _generate_key() -> tuple[int, int, int]:
    exponent = 65537
    while True:
        first, second = _probable_prime(1024), _probable_prime(1024)
        totient = (first - 1) * (second - 1)
        if first != second and math.gcd(exponent, totient) == 1:
            return first * second, exponent, pow(exponent, -1, totient)


MODULUS, EXPONENT, PRIVATE_EXPONENT = _generate_key()
JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KEY_ID,
            "n": _b64(_integer_bytes(MODULUS)),
            "e": _b64(_integer_bytes(EXPONENT)),
        }
    ]
}


def issue_token(request: dict[str, Any]) -> str:
    subject = request.get("sub")
    roles = request.get("roles")
    if not isinstance(subject, str) or not subject:
        raise ValueError("sub must be a non-empty string")
    if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
        raise ValueError("roles must be a list of strings")
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "roles": roles,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    for name in ("agent_id", "customer_id"):
        value = request.get(name)
        if value is not None:
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
            payload[name] = value
    header = {"alg": "RS256", "typ": "JWT", "kid": KEY_ID}
    encoded_header = _b64(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    digest = SHA256_DIGEST_INFO + hashlib.sha256(signing_input).digest()
    size = (MODULUS.bit_length() + 7) // 8
    encoded = b"\x00\x01" + b"\xff" * (size - len(digest) - 3) + b"\x00" + digest
    signature = pow(
        int.from_bytes(encoded, "big"), PRIVATE_EXPONENT, MODULUS
    ).to_bytes(size, "big")
    return f"{encoded_header}.{encoded_payload}.{_b64(signature)}"


class Handler(BaseHTTPRequestHandler):
    def _json(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/.well-known/jwks.json":
            self._json(200, JWKS)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/token":
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 4096:
                raise ValueError("request body must be between 1 and 4096 bytes")
            request = json.loads(self.rfile.read(length))
            if not isinstance(request, dict):
                raise ValueError("request body must be a JSON object")
            self._json(200, {"access_token": issue_token(request)})
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> None:
    print("Generating an ephemeral 2048-bit RSA key for local development...")
    server = ThreadingHTTPServer(("127.0.0.1", 9000), Handler)
    print(f"Local JWKS: {ISSUER}/.well-known/jwks.json")
    print("This issuer is for local development only; press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
