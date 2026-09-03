"""Organisations, membership, and API keys.

ADR 004 put organisation identity here rather than in an identity-provider
claim. Two consequences shape this module:

* An organisation can exist before anyone from it has logged in, which is what
  lets a design partner be issued a key on day one.
* Keycloak stays operator SSO. A validated token yields a subject; this module
  maps that subject to an organisation.

API keys are how a customer's agent authenticates. The secret is never stored.
``prefix`` is an indexed lookup handle and ``key_hash`` is SHA-256 of the whole
key, compared in constant time.

SHA-256 rather than Argon2 or bcrypt is deliberate. Password KDFs exist to make
brute force of low-entropy human-chosen secrets expensive; these keys carry 160
bits from ``secrets.token_bytes``, where the brute-force margin is already
astronomical, and this hash sits on the per-request authorization path.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any, Protocol
from uuid import uuid4

from .auth import AuthenticationError, Principal

# 160 bits of entropy in the secret half of the key.
_KEY_BYTES = 20
# How much of the key is stored in the clear, as the indexed lookup handle.
_PREFIX_LENGTH = 16
# Writing last_used_at on every request would turn each authorization into an
# extra write. Once a minute is enough to answer "is this key still in use".
_LAST_USED_RESOLUTION = timedelta(seconds=60)


class ApiKeyError(AuthenticationError):
    """A presented API key is unknown, revoked, or expired."""


@dataclass(frozen=True)
class Organization:
    org_id: str
    name: str
    slug: str
    created_at: datetime | None = None


@dataclass(frozen=True)
class ApiKeyRecord:
    """An issued key as it is stored. Never holds the secret itself."""

    key_id: str
    org_id: str
    name: str
    prefix: str
    roles: frozenset[str]
    agent_id: str | None = None
    customer_id: str | None = None
    created_at: datetime | None = None
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None

    def is_usable(self, now: datetime) -> bool:
        if self.revoked_at is not None:
            return False
        return self.expires_at is None or now < self.expires_at


@dataclass(frozen=True)
class IssuedApiKey:
    """The one and only time the secret is available. Show it, never store it."""

    record: ApiKeyRecord
    secret: str


def generate_api_key(environment: str = "live") -> tuple[str, str, str]:
    """Return ``(secret, prefix, key_hash)`` for a fresh key.

    The ``ig_`` prefix makes a leaked key greppable by secret scanners and
    identifiable on sight, which is worth more than the few bytes it costs.
    """

    if not environment.isalnum():
        raise ValueError("The key environment must be alphanumeric.")
    body = (
        base64.b32encode(secrets.token_bytes(_KEY_BYTES))
        .decode("ascii")
        .rstrip("=")
        .lower()
    )
    secret = f"ig_{environment}_{body}"
    return secret, secret[:_PREFIX_LENGTH], hash_api_key(secret)


def hash_api_key(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def key_prefix(secret: str) -> str:
    return secret[:_PREFIX_LENGTH]


def principal_for(record: ApiKeyRecord) -> Principal:
    """The same Principal shape a bearer token produces, so handlers cannot tell."""

    return Principal(
        subject=f"key:{record.key_id}",
        roles=record.roles,
        agent_id=record.agent_id,
        customer_id=record.customer_id,
        org_id=record.org_id,
    )


class TenancyStore(Protocol):
    """Organisations, their members, and their API keys."""

    def create_organization(self, name: str, slug: str) -> Organization: ...

    def get_organization(self, org_id: str) -> Organization | None: ...

    def add_member(
        self, org_id: str, subject: str, roles: frozenset[str]
    ) -> None: ...

    def membership(self, subject: str) -> tuple[str, frozenset[str]] | None:
        """The organisation a verified token subject belongs to, and its roles."""
        ...

    def issue_key(
        self,
        org_id: str,
        *,
        name: str,
        roles: frozenset[str],
        agent_id: str | None = None,
        customer_id: str | None = None,
        expires_at: datetime | None = None,
        environment: str = "live",
    ) -> IssuedApiKey: ...

    def authenticate_key(self, secret: str, *, now: datetime) -> Principal:
        """Resolve a presented key, or raise :class:`ApiKeyError`."""
        ...

    def list_keys(self, org_id: str) -> tuple[ApiKeyRecord, ...]: ...

    def revoke_key(self, org_id: str, key_id: str) -> bool: ...

    def close(self) -> None: ...


def _new_org_id() -> str:
    return f"org_{uuid4().hex}"


def _new_key_id() -> str:
    return f"key_{uuid4().hex}"


class InMemoryTenancyStore:
    """Single-process store for tests and local runs."""

    def __init__(self) -> None:
        self._organizations: dict[str, Organization] = {}
        self._slugs: dict[str, str] = {}
        self._members: dict[str, tuple[str, frozenset[str]]] = {}
        self._keys: dict[str, ApiKeyRecord] = {}
        self._hashes: dict[str, str] = {}
        self._lock = RLock()

    def create_organization(self, name: str, slug: str) -> Organization:
        with self._lock:
            if slug in self._slugs:
                raise ValueError(f"The organisation slug is taken: {slug}")
            organization = Organization(
                org_id=_new_org_id(),
                name=name,
                slug=slug,
                created_at=datetime.now(timezone.utc),
            )
            self._organizations[organization.org_id] = organization
            self._slugs[slug] = organization.org_id
            return organization

    def get_organization(self, org_id: str) -> Organization | None:
        with self._lock:
            return self._organizations.get(org_id)

    def add_member(self, org_id: str, subject: str, roles: frozenset[str]) -> None:
        with self._lock:
            if org_id not in self._organizations:
                raise KeyError(f"Unknown organisation: {org_id}")
            self._members[subject] = (org_id, frozenset(roles))

    def membership(self, subject: str) -> tuple[str, frozenset[str]] | None:
        with self._lock:
            return self._members.get(subject)

    def issue_key(
        self,
        org_id: str,
        *,
        name: str,
        roles: frozenset[str],
        agent_id: str | None = None,
        customer_id: str | None = None,
        expires_at: datetime | None = None,
        environment: str = "live",
    ) -> IssuedApiKey:
        with self._lock:
            if org_id not in self._organizations:
                raise KeyError(f"Unknown organisation: {org_id}")
            secret, prefix, digest = generate_api_key(environment)
            record = ApiKeyRecord(
                key_id=_new_key_id(),
                org_id=org_id,
                name=name,
                prefix=prefix,
                roles=frozenset(roles),
                agent_id=agent_id,
                customer_id=customer_id,
                created_at=datetime.now(timezone.utc),
                expires_at=expires_at,
            )
            self._keys[record.key_id] = record
            self._hashes[record.key_id] = digest
            return IssuedApiKey(record=record, secret=secret)

    def authenticate_key(self, secret: str, *, now: datetime) -> Principal:
        with self._lock:
            presented = hash_api_key(secret)
            prefix = key_prefix(secret)
            for key_id, record in self._keys.items():
                if record.prefix != prefix:
                    continue
                if not hmac.compare_digest(self._hashes[key_id], presented):
                    continue
                if not record.is_usable(now):
                    raise ApiKeyError("The API key is revoked or expired.")
                if (
                    record.last_used_at is None
                    or now - record.last_used_at >= _LAST_USED_RESOLUTION
                ):
                    self._keys[key_id] = replace_last_used(record, now)
                return principal_for(record)
            raise ApiKeyError("The API key is not recognised.")

    def list_keys(self, org_id: str) -> tuple[ApiKeyRecord, ...]:
        with self._lock:
            return tuple(
                sorted(
                    (
                        record
                        for record in self._keys.values()
                        if record.org_id == org_id
                    ),
                    key=lambda item: item.key_id,
                )
            )

    def revoke_key(self, org_id: str, key_id: str) -> bool:
        with self._lock:
            record = self._keys.get(key_id)
            if record is None or record.org_id != org_id:
                return False
            if record.revoked_at is not None:
                return False
            self._keys[key_id] = _replace(
                record, revoked_at=datetime.now(timezone.utc)
            )
            return True

    def close(self) -> None:
        return None


def _replace(record: ApiKeyRecord, **changes: Any) -> ApiKeyRecord:
    from dataclasses import replace as dataclass_replace

    return dataclass_replace(record, **changes)


def replace_last_used(record: ApiKeyRecord, now: datetime) -> ApiKeyRecord:
    return _replace(record, last_used_at=now)


class PostgresTenancyStore:
    """Shared store, so every replica sees the same organisations and keys."""

    def __init__(self, conninfo: str) -> None:
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(
            conninfo, min_size=1, max_size=8, open=True, kwargs={"autocommit": True}
        )
        self._pool.wait(timeout=10)

    def close(self) -> None:
        self._pool.close()

    def create_organization(self, name: str, slug: str) -> Organization:
        import psycopg

        org_id = _new_org_id()
        try:
            with self._pool.connection() as connection:
                row = connection.execute(
                    "INSERT INTO organizations (org_id, name, slug) "
                    "VALUES (%s, %s, %s) RETURNING org_id, name, slug, created_at",
                    (org_id, name, slug),
                ).fetchone()
        except psycopg.errors.UniqueViolation as exc:
            raise ValueError(f"The organisation slug is taken: {slug}") from exc
        return Organization(*row)

    def get_organization(self, org_id: str) -> Organization | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT org_id, name, slug, created_at FROM organizations "
                "WHERE org_id = %s",
                (org_id,),
            ).fetchone()
        return None if row is None else Organization(*row)

    def add_member(self, org_id: str, subject: str, roles: frozenset[str]) -> None:
        import psycopg

        try:
            with self._pool.connection() as connection:
                connection.execute(
                    """
                    INSERT INTO org_members (org_id, subject, roles)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (org_id, subject) DO UPDATE SET roles = EXCLUDED.roles
                    """,
                    (org_id, subject, sorted(roles)),
                )
        except psycopg.errors.ForeignKeyViolation as exc:
            raise KeyError(f"Unknown organisation: {org_id}") from exc
        except psycopg.errors.UniqueViolation as exc:
            # org_members_one_org_per_subject. ADR 004 defers multi-org
            # membership deliberately; this is that decision surfacing.
            raise ValueError(
                f"The subject already belongs to another organisation: {subject}"
            ) from exc

    def membership(self, subject: str) -> tuple[str, frozenset[str]] | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT org_id, roles FROM org_members WHERE subject = %s",
                (subject,),
            ).fetchone()
        return None if row is None else (row[0], frozenset(row[1]))

    def issue_key(
        self,
        org_id: str,
        *,
        name: str,
        roles: frozenset[str],
        agent_id: str | None = None,
        customer_id: str | None = None,
        expires_at: datetime | None = None,
        environment: str = "live",
    ) -> IssuedApiKey:
        import psycopg

        secret, prefix, digest = generate_api_key(environment)
        key_id = _new_key_id()
        try:
            with self._pool.connection() as connection:
                row = connection.execute(
                    """
                    INSERT INTO api_keys
                        (key_id, org_id, name, prefix, key_hash, roles,
                         agent_id, customer_id, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING created_at
                    """,
                    (
                        key_id, org_id, name, prefix, digest, sorted(roles),
                        agent_id, customer_id, expires_at,
                    ),
                ).fetchone()
        except psycopg.errors.ForeignKeyViolation as exc:
            raise KeyError(f"Unknown organisation: {org_id}") from exc
        record = ApiKeyRecord(
            key_id=key_id,
            org_id=org_id,
            name=name,
            prefix=prefix,
            roles=frozenset(roles),
            agent_id=agent_id,
            customer_id=customer_id,
            created_at=row[0],
            expires_at=expires_at,
        )
        return IssuedApiKey(record=record, secret=secret)

    def authenticate_key(self, secret: str, *, now: datetime) -> Principal:
        with self._pool.connection() as connection:
            rows = connection.execute(
                """
                SELECT key_id, org_id, name, prefix, key_hash, roles, agent_id,
                       customer_id, created_at, last_used_at, expires_at, revoked_at
                FROM api_keys WHERE prefix = %s
                """,
                (key_prefix(secret),),
            ).fetchall()

            presented = hash_api_key(secret)
            for row in rows:
                if not hmac.compare_digest(row[4], presented):
                    continue
                record = ApiKeyRecord(
                    key_id=row[0], org_id=row[1], name=row[2], prefix=row[3],
                    roles=frozenset(row[5]), agent_id=row[6], customer_id=row[7],
                    created_at=row[8], last_used_at=row[9], expires_at=row[10],
                    revoked_at=row[11],
                )
                if not record.is_usable(now):
                    raise ApiKeyError("The API key is revoked or expired.")
                if (
                    record.last_used_at is None
                    or now - record.last_used_at >= _LAST_USED_RESOLUTION
                ):
                    connection.execute(
                        "UPDATE api_keys SET last_used_at = %s WHERE key_id = %s",
                        (now, record.key_id),
                    )
                return principal_for(record)
        raise ApiKeyError("The API key is not recognised.")

    def list_keys(self, org_id: str) -> tuple[ApiKeyRecord, ...]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                """
                SELECT key_id, org_id, name, prefix, roles, agent_id, customer_id,
                       created_at, last_used_at, expires_at, revoked_at
                FROM api_keys WHERE org_id = %s ORDER BY created_at, key_id
                """,
                (org_id,),
            ).fetchall()
        return tuple(
            ApiKeyRecord(
                key_id=row[0], org_id=row[1], name=row[2], prefix=row[3],
                roles=frozenset(row[4]), agent_id=row[5], customer_id=row[6],
                created_at=row[7], last_used_at=row[8], expires_at=row[9],
                revoked_at=row[10],
            )
            for row in rows
        )

    def revoke_key(self, org_id: str, key_id: str) -> bool:
        with self._pool.connection() as connection:
            row = connection.execute(
                """
                UPDATE api_keys SET revoked_at = now()
                 WHERE key_id = %s AND org_id = %s AND revoked_at IS NULL
                RETURNING key_id
                """,
                (key_id, org_id),
            ).fetchone()
        return row is not None
