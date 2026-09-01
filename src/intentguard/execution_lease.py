"""Signed, connector-verifiable execution lease capabilities."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
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

from .models import AuthorizationLease


class LeaseVerificationError(ValueError):
    pass


@dataclass(frozen=True)
class LeaseVerificationKey:
    key_id: str
    issuer: str
    public_key: str
    active: bool = True


@dataclass(frozen=True)
class ExecutionLeaseClaims:
    lease_id: str
    request_id: str
    reservation_id: str
    agent_id: str
    action: str
    amount: Decimal
    currency: str
    fleet_epoch: int
    issued_at: datetime
    expires_at: datetime
    issuer: str
    audience: str
    key_id: str


class LeaseKeyRegistry(Protocol):
    def get(self, issuer: str, key_id: str) -> LeaseVerificationKey | None: ...
    def save(self, key: LeaseVerificationKey) -> None: ...
    def revoke(self, issuer: str, key_id: str) -> None: ...
    def close(self) -> None: ...


class InMemoryLeaseKeyRegistry:
    def __init__(self) -> None:
        self._keys: dict[tuple[str, str], LeaseVerificationKey] = {}
        self._lock = RLock()

    def get(self, issuer: str, key_id: str) -> LeaseVerificationKey | None:
        with self._lock:
            return self._keys.get((issuer, key_id))

    def save(self, key: LeaseVerificationKey) -> None:
        with self._lock:
            current = self._keys.get((key.issuer, key.key_id))
            if current is not None and current.public_key != key.public_key:
                raise ValueError("A lease key ID cannot be rebound.")
            if current is not None and not current.active:
                key = LeaseVerificationKey(
                    key.key_id, key.issuer, key.public_key, active=False
                )
            self._keys[(key.issuer, key.key_id)] = key

    def revoke(self, issuer: str, key_id: str) -> None:
        with self._lock:
            current = self._keys.get((issuer, key_id))
            if current is None:
                raise KeyError(f"Unknown lease verification key: {issuer}/{key_id}")
            self._keys[(issuer, key_id)] = LeaseVerificationKey(
                current.key_id, current.issuer, current.public_key, active=False
            )

    def close(self) -> None:
        return None


class PostgresLeaseKeyRegistry:
    def __init__(self, conninfo: str) -> None:
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(
            conninfo, min_size=1, max_size=8, open=True,
            kwargs={"autocommit": True},
        )
        self._pool.wait(timeout=10)

    def get(self, issuer: str, key_id: str) -> LeaseVerificationKey | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT key_id, issuer, public_key, active "
                "FROM lease_signing_keys WHERE issuer = %s AND key_id = %s",
                (issuer, key_id),
            ).fetchone()
        return None if row is None else LeaseVerificationKey(*row)

    def save(self, key: LeaseVerificationKey) -> None:
        with self._pool.connection() as connection:
            connection.execute(
                """
                INSERT INTO lease_signing_keys (issuer, key_id, public_key, active)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (issuer, key_id) DO UPDATE SET
                    active = lease_signing_keys.active AND EXCLUDED.active,
                    updated_at = now()
                WHERE lease_signing_keys.public_key = EXCLUDED.public_key
                """,
                (key.issuer, key.key_id, key.public_key, key.active),
            )
            matches = connection.execute(
                "SELECT public_key = %s FROM lease_signing_keys "
                "WHERE issuer = %s AND key_id = %s",
                (key.public_key, key.issuer, key.key_id),
            ).fetchone()
        if matches != (True,):
            raise ValueError("A lease key ID cannot be rebound.")

    def revoke(self, issuer: str, key_id: str) -> None:
        with self._pool.connection() as connection:
            result = connection.execute(
                "UPDATE lease_signing_keys SET active = FALSE, updated_at = now() "
                "WHERE issuer = %s AND key_id = %s",
                (issuer, key_id),
            )
        if result.rowcount != 1:
            raise KeyError(f"Unknown lease verification key: {issuer}/{key_id}")

    def close(self) -> None:
        self._pool.close()


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str, *, canonical: bool = False) -> bytes:
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
        if canonical and _b64encode(decoded) != value:
            raise ValueError("Non-canonical Base64URL encoding")
        return decoded
    except (ValueError, TypeError, base64.binascii.Error) as exc:
        raise LeaseVerificationError("The execution lease is malformed.") from exc


def encode_lease_public_key(key: Ed25519PublicKey) -> str:
    return _b64encode(key.public_bytes(Encoding.Raw, PublicFormat.Raw))


def encode_lease_private_key(key: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat

    return _b64encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))


def decode_lease_private_key(value: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_b64decode(value))


def lease_key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "lease-" + hashlib.sha256(raw).hexdigest()[:16]


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("Lease timestamps must include a timezone.")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def lease_payload(lease: AuthorizationLease) -> dict[str, Any]:
    return {
        "lease_id": lease.lease_id,
        "request_id": lease.request_id,
        "reservation_id": lease.reservation_id,
        "agent_id": lease.agent_id,
        "action": lease.action,
        "amount": format(lease.amount, "f"),
        "currency": lease.currency,
        "fleet_epoch": lease.fleet_epoch,
        "issued_at": _timestamp(lease.issued_at),
        "expires_at": _timestamp(lease.expires_at),
        "issuer": lease.issuer,
        "audience": lease.audience,
        "key_id": lease.key_id,
    }


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


class ExecutionLeaseSigner:
    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        issuer: str,
        audience: str,
        key_registry: LeaseKeyRegistry,
        key_id: str | None = None,
    ) -> None:
        self.private_key = private_key
        self.issuer = issuer
        self.audience = audience
        self.key_registry = key_registry
        self.key_id = key_id or lease_key_id(private_key.public_key())
        self.key_registry.save(
            LeaseVerificationKey(
                key_id=self.key_id,
                issuer=issuer,
                public_key=encode_lease_public_key(private_key.public_key()),
            )
        )

    def sign(self, lease: AuthorizationLease) -> AuthorizationLease:
        from dataclasses import replace

        unsigned = replace(
            lease,
            issuer=self.issuer,
            audience=self.audience,
            key_id=self.key_id,
            token="",
        )
        payload = lease_payload(unsigned)
        encoded = _b64encode(_canonical(payload))
        signature = _b64encode(self.private_key.sign(encoded.encode("ascii")))
        return replace(unsigned, token=f"{encoded}.{signature}")

    def close(self) -> None:
        self.key_registry.close()


class ExecutionLeaseVerifier:
    def __init__(self, *, audience: str, key_registry: LeaseKeyRegistry) -> None:
        self.audience = audience
        self.key_registry = key_registry

    def verify(self, token: str, *, now: datetime | None = None) -> ExecutionLeaseClaims:
        if not token or token.count(".") != 1:
            raise LeaseVerificationError("A signed execution lease is required.")
        encoded, signature = token.split(".")
        try:
            payload = json.loads(_b64decode(encoded, canonical=True))
            claims = ExecutionLeaseClaims(
                lease_id=payload["lease_id"],
                request_id=payload["request_id"],
                reservation_id=payload["reservation_id"],
                agent_id=payload["agent_id"],
                action=payload["action"],
                amount=Decimal(payload["amount"]),
                currency=payload["currency"],
                fleet_epoch=int(payload["fleet_epoch"]),
                issued_at=datetime.fromisoformat(payload["issued_at"].replace("Z", "+00:00")),
                expires_at=datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00")),
                issuer=payload["issuer"],
                audience=payload["audience"],
                key_id=payload["key_id"],
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise LeaseVerificationError("The execution lease is malformed.") from exc
        if claims.audience != self.audience:
            raise LeaseVerificationError("The execution lease audience is invalid.")
        key = self.key_registry.get(claims.issuer, claims.key_id)
        if key is None:
            raise LeaseVerificationError("The execution lease key is unknown.")
        if not key.active:
            raise LeaseVerificationError("The execution lease key is revoked.")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(_b64decode(key.public_key))
            public_key.verify(
                _b64decode(signature, canonical=True), encoded.encode("ascii")
            )
        except (InvalidSignature, ValueError) as exc:
            raise LeaseVerificationError("The execution lease signature is invalid.") from exc
        moment = now or datetime.now(timezone.utc)
        if moment >= claims.expires_at:
            raise LeaseVerificationError("The execution lease has expired.")
        if claims.issued_at > moment:
            raise LeaseVerificationError("The execution lease is not valid yet.")
        return claims

    def close(self) -> None:
        self.key_registry.close()
