"""Minimal RS256 JWT validation against a JSON Web Key Set (JWKS).

The implementation deliberately uses only the standard library so the domain
package stays dependency-light. It supports the subset needed by IntentGuard:
RS256, key selection by ``kid``, issuer/audience/time validation, and Keycloak-
style realm roles. Signing and password handling belong to the identity
provider; this module only validates bearer tokens.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from time import monotonic
from typing import Any, Callable
from urllib.parse import urlparse
from urllib.request import urlopen


class AuthenticationError(ValueError):
    """A bearer token is missing, malformed, or cannot be trusted."""


class AuthorizationError(ValueError):
    """The authenticated principal lacks a required role or identity claim."""


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str]
    agent_id: str | None = None
    customer_id: str | None = None
    claims: dict[str, Any] | None = None

    def has_any_role(self, permitted: frozenset[str]) -> bool:
        return "admin" in self.roles or bool(self.roles & permitted)


def _b64url_decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise AuthenticationError("The bearer token is not valid base64url.") from exc


def _json_segment(value: str, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(_b64url_decode(value))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AuthenticationError(f"The JWT {label} is not valid JSON.") from exc
    if not isinstance(parsed, dict):
        raise AuthenticationError(f"The JWT {label} must be a JSON object.")
    return parsed


class JwksAuthenticator:
    """Validate RS256 access tokens using remote or injected public keys."""

    _DIGEST_INFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str | None = None,
        jwks: dict[str, Any] | None = None,
        cache_ttl_seconds: float = 300,
        timeout_seconds: float = 2,
        minimum_rsa_bits: int = 2048,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not issuer or not audience:
            raise ValueError("JWT issuer and audience are required.")
        if jwks_url is None and jwks is None:
            raise ValueError("Either a JWKS URL or an injected JWKS is required.")
        if jwks_url is not None and urlparse(jwks_url).scheme not in {"http", "https"}:
            raise ValueError("The JWKS URL must use HTTP or HTTPS.")
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.jwks_url = jwks_url
        self._static_jwks = jwks
        self.cache_ttl_seconds = cache_ttl_seconds
        self.timeout_seconds = timeout_seconds
        if minimum_rsa_bits < 512:
            raise ValueError("The minimum RSA key size cannot be below 512 bits.")
        self.minimum_rsa_bits = minimum_rsa_bits
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._cached_jwks: dict[str, Any] | None = None
        self._cached_at = 0.0
        self._lock = RLock()

    @classmethod
    def from_env(cls) -> "JwksAuthenticator":
        issuer = os.getenv("INTENTGUARD_JWT_ISSUER", "http://127.0.0.1:9000")
        return cls(
            issuer=issuer,
            audience=os.getenv("INTENTGUARD_JWT_AUDIENCE", "intentguard-api"),
            jwks_url=os.getenv(
                "INTENTGUARD_JWKS_URL",
                f"{issuer.rstrip('/')}/.well-known/jwks.json",
            ),
        )

    def authenticate(self, authorization: str | None) -> Principal:
        if not authorization:
            raise AuthenticationError("A bearer token is required.")
        scheme, separator, token = authorization.partition(" ")
        if separator == "" or scheme.lower() != "bearer" or not token.strip():
            raise AuthenticationError("Authorization must use the Bearer scheme.")
        claims = self.decode(token.strip())
        roles = self._roles(claims)
        return Principal(
            subject=str(claims["sub"]),
            roles=frozenset(roles),
            agent_id=self._optional_string(claims, "agent_id"),
            customer_id=self._optional_string(claims, "customer_id"),
            claims=claims,
        )

    def decode(self, token: str) -> dict[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            raise AuthenticationError("A JWT must contain three segments.")
        header = _json_segment(parts[0], "header")
        claims = _json_segment(parts[1], "payload")
        if header.get("alg") != "RS256":
            raise AuthenticationError("Only RS256 JWTs are accepted.")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AuthenticationError("The JWT header must contain a key ID.")
        key = self._key(kid)
        self._verify_signature(
            f"{parts[0]}.{parts[1]}".encode("ascii"),
            _b64url_decode(parts[2]),
            key,
        )
        self._validate_claims(claims)
        return claims

    def require_roles(
        self, principal: Principal, permitted: frozenset[str]
    ) -> Principal:
        if not principal.has_any_role(permitted):
            expected = ", ".join(sorted(permitted))
            raise AuthorizationError(f"One of these roles is required: {expected}.")
        return principal

    def _jwks(self, *, force_refresh: bool = False) -> dict[str, Any]:
        if self._static_jwks is not None:
            return self._static_jwks
        with self._lock:
            fresh = monotonic() - self._cached_at < self.cache_ttl_seconds
            if self._cached_jwks is not None and fresh and not force_refresh:
                return self._cached_jwks
            try:
                jwks_url = self.jwks_url
                if jwks_url is None:
                    raise AuthenticationError("The JWKS URL is not configured.")
                # The constructor restricts this URL to HTTP(S), preventing
                # urllib from opening local files or custom URL handlers.
                with urlopen(jwks_url, timeout=self.timeout_seconds) as response:  # nosec B310
                    value = json.load(response)
            except Exception as exc:
                raise AuthenticationError("The JWKS endpoint is unavailable.") from exc
            if not isinstance(value, dict) or not isinstance(value.get("keys"), list):
                raise AuthenticationError("The JWKS endpoint returned invalid data.")
            self._cached_jwks = value
            self._cached_at = monotonic()
            return value

    def _key(self, kid: str) -> dict[str, Any]:
        for refresh in (False, True):
            document = self._jwks(force_refresh=refresh)
            key = next(
                (item for item in document["keys"] if item.get("kid") == kid), None
            )
            if key is not None:
                if (
                    key.get("kty") != "RSA"
                    or key.get("use", "sig") != "sig"
                    or key.get("alg", "RS256") != "RS256"
                ):
                    raise AuthenticationError("The selected JWKS key cannot sign JWTs.")
                return key
            if self._static_jwks is not None:
                break
        raise AuthenticationError("The JWT was signed with an unknown key.")

    def _verify_signature(
        self, signing_input: bytes, signature: bytes, key: dict[str, Any]
    ) -> None:
        try:
            modulus = int.from_bytes(_b64url_decode(key["n"]), "big")
            exponent = int.from_bytes(_b64url_decode(key["e"]), "big")
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError("The RSA JWK is malformed.") from exc
        size = (modulus.bit_length() + 7) // 8
        if modulus.bit_length() < self.minimum_rsa_bits:
            raise AuthenticationError("The JWKS RSA key is too small.")
        if len(signature) != size:
            raise AuthenticationError("The JWT signature is invalid.")
        signature_value = int.from_bytes(signature, "big")
        if signature_value >= modulus:
            raise AuthenticationError("The JWT signature is invalid.")
        encoded = pow(signature_value, exponent, modulus).to_bytes(size, "big")
        digest_info = self._DIGEST_INFO_SHA256 + hashlib.sha256(signing_input).digest()
        padding_length = size - len(digest_info) - 3
        expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
        if padding_length < 8 or not hmac.compare_digest(encoded, expected):
            raise AuthenticationError("The JWT signature is invalid.")

    def _validate_claims(self, claims: dict[str, Any]) -> None:
        now = self._now().timestamp()
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise AuthenticationError("The JWT subject is required.")
        issuer = claims.get("iss")
        if not isinstance(issuer, str) or issuer.rstrip("/") != self.issuer:
            raise AuthenticationError("The JWT issuer is invalid.")
        audience = claims.get("aud")
        if isinstance(audience, str):
            audiences = {audience}
        elif isinstance(audience, list) and all(
            isinstance(item, str) for item in audience
        ):
            audiences = set(audience)
        else:
            raise AuthenticationError("The JWT audience is invalid.")
        if self.audience not in audiences:
            raise AuthenticationError("The JWT audience is invalid.")
        try:
            expires_at = float(claims["exp"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError("The JWT expiration is required.") from exc
        if not math.isfinite(expires_at) or now >= expires_at:
            raise AuthenticationError("The JWT has expired.")
        try:
            if "nbf" in claims:
                not_before = float(claims["nbf"])
                if not math.isfinite(not_before) or now < not_before:
                    raise AuthenticationError("The JWT is not active yet.")
        except (TypeError, ValueError) as exc:
            raise AuthenticationError("The JWT not-before claim is invalid.") from exc

    @staticmethod
    def _roles(claims: dict[str, Any]) -> set[str]:
        roles: set[str] = set()
        direct = claims.get("roles", claims.get("role", ()))
        if isinstance(direct, str):
            roles.add(direct)
        elif isinstance(direct, list):
            roles.update(item for item in direct if isinstance(item, str))
        realm_access = claims.get("realm_access")
        if isinstance(realm_access, dict) and isinstance(
            realm_access.get("roles"), list
        ):
            roles.update(
                item for item in realm_access["roles"] if isinstance(item, str)
            )
        return roles

    @staticmethod
    def _optional_string(claims: dict[str, Any], name: str) -> str | None:
        value = claims.get(name)
        return value if isinstance(value, str) and value else None
