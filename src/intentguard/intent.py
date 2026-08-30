"""Ed25519-signed customer intent passports and replay protection."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal
from threading import RLock
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .models import IntentPassport


class IntentVerificationError(ValueError):
    """A passport is not authentic, valid for this gateway, or fresh."""


class IntentReplayError(IntentVerificationError):
    """The passport nonce was already accepted."""


@dataclass(frozen=True)
class IntentSigningKey:
    key_id: str
    issuer: str
    public_key: str
    active: bool = True
    valid_from: datetime | None = None
    expires_at: datetime | None = None


class IntentKeyRegistry(Protocol):
    def get(self, issuer: str, key_id: str) -> IntentSigningKey | None: ...
    def save(self, key: IntentSigningKey) -> None: ...
    def revoke(self, issuer: str, key_id: str) -> IntentSigningKey: ...
    def list(self) -> tuple[IntentSigningKey, ...]: ...
    def close(self) -> None: ...


class NonceStore(Protocol):
    def consume(self, issuer: str, nonce: str, intent_id: str, consumed_at: datetime) -> bool: ...
    def close(self) -> None: ...


class InMemoryIntentKeyRegistry:
    def __init__(self) -> None:
        self._keys: dict[tuple[str, str], IntentSigningKey] = {}
        self._lock = RLock()

    def get(self, issuer: str, key_id: str) -> IntentSigningKey | None:
        with self._lock:
            return self._keys.get((issuer, key_id))

    def save(self, key: IntentSigningKey) -> None:
        with self._lock:
            current = self._keys.get((key.issuer, key.key_id))
            if current is not None and current.public_key != key.public_key:
                raise ValueError(
                    "An existing key ID cannot be rebound to different key material."
                )
            if current is not None and not current.active:
                key = replace(key, active=False)
            self._keys[(key.issuer, key.key_id)] = key

    def revoke(self, issuer: str, key_id: str) -> IntentSigningKey:
        with self._lock:
            current = self._keys.get((issuer, key_id))
            if current is None:
                raise KeyError(f"Unknown intent signing key: {issuer}/{key_id}")
            revoked = replace(current, active=False)
            self._keys[(issuer, key_id)] = revoked
            return revoked

    def list(self) -> tuple[IntentSigningKey, ...]:
        with self._lock:
            return tuple(sorted(self._keys.values(), key=lambda key: (key.issuer, key.key_id)))

    def close(self) -> None:
        return None


class InMemoryNonceStore:
    def __init__(self) -> None:
        self._nonces: set[tuple[str, str]] = set()
        self._lock = RLock()

    def consume(self, issuer: str, nonce: str, intent_id: str, consumed_at: datetime) -> bool:
        del intent_id, consumed_at
        with self._lock:
            key = (issuer, nonce)
            if key in self._nonces:
                return False
            self._nonces.add(key)
            return True

    def close(self) -> None:
        return None


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise IntentVerificationError("The passport contains invalid base64url data.") from exc


def encode_public_key(key: Ed25519PublicKey) -> str:
    return _b64encode(key.public_bytes(Encoding.Raw, PublicFormat.Raw))


def validate_public_key(value: str) -> None:
    """Raise when a registry value is not a raw Ed25519 public key."""

    try:
        Ed25519PublicKey.from_public_bytes(_b64decode(value))
    except ValueError as exc:
        raise IntentVerificationError(
            "The intent signing key is not a valid Ed25519 public key."
        ) from exc


def _canonical_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise IntentVerificationError("Passport timestamps must include a timezone.")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {key: _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    return value


def passport_payload(intent: IntentPassport) -> dict[str, Any]:
    return _canonical_value(
        {
            "intent_id": intent.intent_id,
            "customer_id": intent.customer_id,
            "agent_id": intent.agent_id,
            "action": intent.action,
            "max_amount": intent.max_amount,
            "currency": intent.currency,
            "required_attributes": intent.required_attributes,
            "issued_at": intent.issued_at,
            "not_before": intent.not_before,
            "expires_at": intent.expires_at,
            "audience": intent.audience,
            "nonce": intent.nonce,
            "key_id": intent.key_id,
            "issuer": intent.issuer,
        }
    )


def canonical_passport(intent: IntentPassport) -> bytes:
    return json.dumps(
        passport_payload(intent),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sign_passport(intent: IntentPassport, private_key: Ed25519PrivateKey) -> IntentPassport:
    """Return the passport with an Ed25519 signature over its canonical payload."""

    signature = private_key.sign(canonical_passport(intent))
    return replace(intent, signature=_b64encode(signature))


class IntentVerifier:
    def __init__(
        self,
        *,
        audience: str,
        key_registry: IntentKeyRegistry,
        nonce_store: NonceStore,
        allowed_issuers: frozenset[str] | None = None,
        clock_skew_seconds: int = 30,
    ) -> None:
        self.audience = audience
        self.key_registry = key_registry
        self.nonce_store = nonce_store
        self.allowed_issuers = allowed_issuers
        self.clock_skew_seconds = clock_skew_seconds

    def verify_and_consume(
        self,
        intent: IntentPassport,
        *,
        now: datetime | None = None,
        expected_customer_id: str | None = None,
    ) -> None:
        moment = now or datetime.now(timezone.utc)
        if moment.tzinfo is None:
            raise ValueError("Verification time must include a timezone.")
        required = {
            "issuer": intent.issuer,
            "audience": intent.audience,
            "nonce": intent.nonce,
            "key_id": intent.key_id,
            "signature": intent.signature,
            "issued_at": intent.issued_at,
            "not_before": intent.not_before,
        }
        missing = [name for name, value in required.items() if value in (None, "")]
        if missing:
            raise IntentVerificationError(
                "The signed passport is missing: " + ", ".join(sorted(missing)) + "."
            )
        if self.allowed_issuers is not None and intent.issuer not in self.allowed_issuers:
            raise IntentVerificationError("The passport issuer is not trusted.")
        if intent.audience != self.audience:
            raise IntentVerificationError("The passport audience is invalid.")
        if expected_customer_id is not None and intent.customer_id != expected_customer_id:
            raise IntentVerificationError("The passport belongs to a different customer.")
        skew = self.clock_skew_seconds
        if intent.not_before.timestamp() - skew > moment.timestamp():
            raise IntentVerificationError("The passport is not valid yet.")
        if intent.issued_at.timestamp() - skew > moment.timestamp():
            raise IntentVerificationError("The passport issue time is in the future.")
        if moment.timestamp() - skew >= intent.expires_at.timestamp():
            raise IntentVerificationError("The passport has expired.")

        key = self.key_registry.get(intent.issuer, intent.key_id)
        if key is None:
            raise IntentVerificationError("The passport references an unknown signing key.")
        if not key.active:
            raise IntentVerificationError("The passport signing key has been revoked.")
        if key.valid_from is not None and moment < key.valid_from:
            raise IntentVerificationError("The passport signing key is not valid yet.")
        if key.expires_at is not None and moment >= key.expires_at:
            raise IntentVerificationError("The passport signing key has expired.")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(_b64decode(key.public_key))
            public_key.verify(_b64decode(intent.signature), canonical_passport(intent))
        except (InvalidSignature, ValueError) as exc:
            raise IntentVerificationError("The passport signature is invalid.") from exc
        if not self.nonce_store.consume(
            intent.issuer, intent.nonce, intent.intent_id, moment
        ):
            raise IntentReplayError("The passport nonce has already been used.")

    def close(self) -> None:
        self.key_registry.close()
        self.nonce_store.close()


class PostgresIntentKeyRegistry:
    def __init__(self, conninfo: str) -> None:
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(conninfo, min_size=1, max_size=8, open=True, kwargs={"autocommit": True})
        self._pool.wait(timeout=10)

    def get(self, issuer: str, key_id: str) -> IntentSigningKey | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT key_id, issuer, public_key, active, valid_from, expires_at "
                "FROM intent_signing_keys WHERE issuer = %s AND key_id = %s",
                (issuer, key_id),
            ).fetchone()
        return None if row is None else IntentSigningKey(*row)

    def save(self, key: IntentSigningKey) -> None:
        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO intent_signing_keys
                    (key_id, issuer, public_key, active, valid_from, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (issuer, key_id) DO UPDATE SET
                    active = intent_signing_keys.active AND EXCLUDED.active,
                    valid_from = EXCLUDED.valid_from,
                    expires_at = EXCLUDED.expires_at,
                    updated_at = now()
                WHERE intent_signing_keys.public_key = EXCLUDED.public_key
                """,
                (key.key_id, key.issuer, key.public_key, key.active, key.valid_from, key.expires_at),
            )
            if connection.execute(
                "SELECT public_key = %s FROM intent_signing_keys "
                "WHERE issuer = %s AND key_id = %s",
                (key.public_key, key.issuer, key.key_id),
            ).fetchone() != (True,):
                raise ValueError(
                    "An existing key ID cannot be rebound to different key material."
                )

    def revoke(self, issuer: str, key_id: str) -> IntentSigningKey:
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                UPDATE intent_signing_keys SET active = FALSE, updated_at = now()
                WHERE issuer = %s AND key_id = %s
                RETURNING key_id, issuer, public_key, active, valid_from, expires_at
                """,
                (issuer, key_id),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown intent signing key: {issuer}/{key_id}")
        return IntentSigningKey(*row)

    def list(self) -> tuple[IntentSigningKey, ...]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                "SELECT key_id, issuer, public_key, active, valid_from, expires_at "
                "FROM intent_signing_keys ORDER BY issuer, key_id"
            ).fetchall()
        return tuple(IntentSigningKey(*row) for row in rows)

    def close(self) -> None:
        self._pool.close()


class PostgresNonceStore:
    def __init__(self, conninfo: str) -> None:
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(conninfo, min_size=1, max_size=8, open=True, kwargs={"autocommit": True})
        self._pool.wait(timeout=10)

    def consume(self, issuer: str, nonce: str, intent_id: str, consumed_at: datetime) -> bool:
        with self._pool.connection() as connection:
            result = connection.execute(
                """
                INSERT INTO intent_nonces (issuer, nonce, intent_id, consumed_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (issuer, nonce) DO NOTHING
                """,
                (issuer, nonce, intent_id, consumed_at),
            )
        return result.rowcount == 1

    def close(self) -> None:
        self._pool.close()
