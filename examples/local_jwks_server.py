"""Local-only JWKS server and token issuer for the authenticated demo.

This is deliberately not an account system. It binds only to loopback, creates
an ephemeral RSA key at startup, and lets local developers mint short-lived
tokens for any demo role. Use Keycloak or another real identity provider
outside local development.

Start it with ``python examples/local_jwks_server.py``. Then request a token:

    curl -X POST http://127.0.0.1:9000/token \
      -H "Content-Type: application/json" \
      -d '{"sub":"demo-admin","roles":["admin"],
           "agent_id":"agt_refund_01","customer_id":"demo-customer"}'
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ISSUER = "http://127.0.0.1:9000"
AUDIENCE = "intentguard-api"
KEY_ID = "intentguard-local-dev"
KEY_SIZE_BITS = 2048


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _integer_bytes(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


# ``cryptography`` is already a hard dependency of the package, and it
# guarantees an exactly ``KEY_SIZE_BITS``-bit modulus. The previous
# hand-rolled generator built the modulus from two 1024-bit primes, which
# lands in [2^2046, 2^2048) -- so 38% of startups produced a 2047-bit key
# that the gateway correctly rejected as below its 2048-bit minimum.
PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537, key_size=KEY_SIZE_BITS
)
_PUBLIC_NUMBERS = PRIVATE_KEY.public_key().public_numbers()
JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KEY_ID,
            "n": _b64(_integer_bytes(_PUBLIC_NUMBERS.n)),
            "e": _b64(_integer_bytes(_PUBLIC_NUMBERS.e)),
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
    signature = PRIVATE_KEY.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
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
    print(
        f"Generated an ephemeral {PRIVATE_KEY.key_size}-bit RSA key "
        "for local development."
    )
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
