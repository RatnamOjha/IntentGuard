"""Explicit protected hotel-booking connector service."""

from __future__ import annotations

import hashlib
import json
import os
import time
from time import perf_counter
from dataclasses import asdict, dataclass
from decimal import Decimal
from threading import RLock
from typing import Any, Callable, Protocol

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, Field

from .abuse import (
    AbuseLimits,
    RateLimiter,
    RateLimiterUnavailable,
    RedisSlidingWindowRateLimiter,
    RequestBodyLimitMiddleware,
    SlidingWindowRateLimiter,
)
from .execution_lease import (
    ExecutionLeaseClaims,
    ExecutionLeaseVerifier,
    LeaseVerificationError,
    PostgresLeaseKeyRegistry,
    InMemoryLeaseKeyRegistry,
    LeaseVerificationKey,
)
from .observability import (
    install_observability,
    observation_fields,
    operation_span,
    outbound_trace_headers,
)


class ConnectorError(RuntimeError):
    pass


class ConnectorConflict(ConnectorError):
    pass


class ProviderTimeout(ConnectorError):
    pass


class ProviderFailure(ConnectorError):
    pass


class CircuitOpen(ProviderFailure):
    pass


class CircuitBreaker:
    """Small thread-safe closed/open/half-open provider circuit breaker."""

    def __init__(
        self,
        *,
        failure_threshold: int = 3,
        recovery_seconds: float = 30.0,
        clock: Any = time.monotonic,
    ) -> None:
        if failure_threshold < 1 or recovery_seconds <= 0:
            raise ValueError("Circuit-breaker limits must be positive.")
        self.failure_threshold = failure_threshold
        self.recovery_seconds = recovery_seconds
        self._clock = clock
        self._failures = 0
        self._opened_at: float | None = None
        self._probe_in_flight = False
        self._lock = RLock()

    @property
    def state(self) -> str:
        with self._lock:
            if self._opened_at is None:
                return "closed"
            if self._clock() - self._opened_at >= self.recovery_seconds:
                return "half_open"
            return "open"

    def before_call(self) -> None:
        with self._lock:
            if self._opened_at is None:
                return
            if self._clock() - self._opened_at < self.recovery_seconds:
                raise CircuitOpen("The booking provider circuit is open.")
            if self._probe_in_flight:
                raise CircuitOpen("The booking provider recovery probe is in progress.")
            self._probe_in_flight = True

    def success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self._probe_in_flight = False

    def failure(self) -> None:
        with self._lock:
            self._failures += 1
            self._probe_in_flight = False
            if self._failures >= self.failure_threshold:
                self._opened_at = self._clock()


@dataclass(frozen=True)
class FleetState:
    stopped: bool
    fleet_epoch: int


@dataclass(frozen=True)
class BookingCommand:
    request_id: str
    reservation_id: str
    agent_id: str
    customer_id: str
    action: str
    hotel: str
    amount: Decimal
    currency: str
    refundable: bool
    lease_token: str


@dataclass(frozen=True)
class BookingResponse:
    status: str
    request_id: str
    provider_reference: str | None
    message: str
    idempotent_replay: bool = False


class GovernanceGateway(Protocol):
    def fleet_state(self) -> FleetState: ...
    def commit(self, reservation_id: str, lease_id: str) -> None: ...
    def release(self, reservation_id: str, reason: str) -> None: ...


class HotelProvider(Protocol):
    def book(self, command: BookingCommand) -> str: ...


class ExecutionStore(Protocol):
    def claim(self, request_id: str, fingerprint: str) -> tuple[str, dict[str, Any] | None]: ...
    def complete(self, request_id: str, response: dict[str, Any]) -> None: ...
    def close(self) -> None: ...


class InMemoryExecutionStore:
    def __init__(self) -> None:
        self._records: dict[str, tuple[str, str, dict[str, Any] | None]] = {}
        self._lock = RLock()

    def claim(self, request_id: str, fingerprint: str) -> tuple[str, dict[str, Any] | None]:
        with self._lock:
            current = self._records.get(request_id)
            if current is None:
                self._records[request_id] = (fingerprint, "processing", None)
                return "new", None
            previous_fingerprint, status, response = current
            if previous_fingerprint != fingerprint:
                return "conflict", None
            if status == "complete":
                return "cached", response
            return "processing", None

    def complete(self, request_id: str, response: dict[str, Any]) -> None:
        with self._lock:
            fingerprint, _, _ = self._records[request_id]
            self._records[request_id] = (fingerprint, "complete", response)

    def close(self) -> None:
        return None


class PostgresExecutionStore:
    def __init__(self, conninfo: str) -> None:
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(
            conninfo, min_size=1, max_size=8, open=True,
            kwargs={"autocommit": True},
        )
        self._pool.wait(timeout=10)

    def claim(self, request_id: str, fingerprint: str) -> tuple[str, dict[str, Any] | None]:
        with self._pool.connection() as connection:
            inserted = connection.execute(
                """
                INSERT INTO connector_executions
                    (request_id, request_fingerprint, status)
                VALUES (%s, %s, 'processing')
                ON CONFLICT (request_id) DO NOTHING
                """,
                (request_id, fingerprint),
            ).rowcount
            if inserted == 1:
                return "new", None
            row = connection.execute(
                "SELECT request_fingerprint, status, response_payload "
                "FROM connector_executions WHERE request_id = %s",
                (request_id,),
            ).fetchone()
        if row[0] != fingerprint:
            return "conflict", None
        return ("cached", row[2]) if row[1] == "complete" else ("processing", None)

    def complete(self, request_id: str, response: dict[str, Any]) -> None:
        from psycopg.types.json import Jsonb

        with self._pool.connection() as connection:
            connection.execute(
                """
                UPDATE connector_executions
                SET status = 'complete', response_payload = %s, updated_at = now()
                WHERE request_id = %s
                """,
                (Jsonb(response), request_id),
            )

    def close(self) -> None:
        self._pool.close()


class MockHotelProvider:
    def book(self, command: BookingCommand) -> str:
        return f"HOTEL-{command.request_id[-12:].upper()}"


def _fingerprint(command: BookingCommand, claims: ExecutionLeaseClaims) -> str:
    value = {
        "request_id": command.request_id,
        "reservation_id": command.reservation_id,
        "agent_id": command.agent_id,
        "customer_id": command.customer_id,
        "action": command.action,
        "hotel": command.hotel,
        "amount": format(command.amount, "f"),
        "currency": command.currency,
        "refundable": command.refundable,
        "lease_id": claims.lease_id,
    }
    canonical = json.dumps(value, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ProtectedBookingConnector:
    def __init__(
        self,
        *,
        verifier: ExecutionLeaseVerifier,
        governance: GovernanceGateway,
        execution_store: ExecutionStore,
        provider: HotelProvider | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ) -> None:
        self.verifier = verifier
        self.governance = governance
        self.execution_store = execution_store
        self.provider = provider or MockHotelProvider()
        self.circuit_breaker = circuit_breaker or CircuitBreaker()

    def execute(self, command: BookingCommand) -> BookingResponse:
        claims = self.verifier.verify(command.lease_token)
        mismatches = [
            label
            for label, expected, actual in (
                ("request_id", claims.request_id, command.request_id),
                ("reservation_id", claims.reservation_id, command.reservation_id),
                ("agent_id", claims.agent_id, command.agent_id),
                ("action", claims.action, command.action),
                ("amount", claims.amount, command.amount),
                ("currency", claims.currency, command.currency),
            )
            if expected != actual
        ]
        if mismatches:
            raise ConnectorConflict(
                "The booking differs from its execution lease: " + ", ".join(mismatches)
            )
        fleet = self.governance.fleet_state()
        if fleet.stopped or fleet.fleet_epoch != claims.fleet_epoch:
            raise ConnectorConflict("The execution lease was invalidated by a fleet stop.")

        fingerprint = _fingerprint(command, claims)
        claim, cached = self.execution_store.claim(command.request_id, fingerprint)
        if claim == "conflict":
            raise ConnectorConflict("The request ID was reused with different booking data.")
        if claim == "processing":
            raise ConnectorConflict("The booking request is already being processed.")
        if claim == "cached":
            return BookingResponse(**{**cached, "idempotent_replay": True})

        try:
            self.circuit_breaker.before_call()
        except CircuitOpen as exc:
            self.governance.release(command.reservation_id, "booking_provider_circuit_open")
            response = BookingResponse(
                "failed", command.request_id, None,
                "The booking provider circuit is open; execution failed fast.",
            )
            self.execution_store.complete(command.request_id, asdict(response))
            raise CircuitOpen(response.message) from exc

        try:
            provider_reference = self.provider.book(command)
        except TimeoutError as exc:
            self.circuit_breaker.failure()
            self.governance.release(command.reservation_id, "booking_provider_timeout")
            response = BookingResponse(
                "failed", command.request_id, None, "The booking provider timed out."
            )
            self.execution_store.complete(command.request_id, asdict(response))
            raise ProviderTimeout(response.message) from exc
        except Exception as exc:
            self.circuit_breaker.failure()
            self.governance.release(command.reservation_id, "booking_provider_failure")
            response = BookingResponse(
                "failed", command.request_id, None, "The booking provider failed."
            )
            self.execution_store.complete(command.request_id, asdict(response))
            raise ProviderFailure(response.message) from exc

        self.circuit_breaker.success()

        fleet_after_provider = self.governance.fleet_state()
        if fleet_after_provider.stopped or fleet_after_provider.fleet_epoch != claims.fleet_epoch:
            response = BookingResponse(
                "failed", command.request_id, None,
                "The fleet stopped before the provider result could be committed.",
            )
            self.execution_store.complete(command.request_id, asdict(response))
            raise ConnectorConflict(response.message)
        try:
            self.governance.commit(command.reservation_id, claims.lease_id)
        except (KeyError, ValueError) as exc:
            response = BookingResponse(
                "failed", command.request_id, None,
                "IntentGuard rejected the final reservation commit.",
            )
            self.execution_store.complete(command.request_id, asdict(response))
            raise ConnectorConflict(response.message) from exc

        response = BookingResponse(
            "booked", command.request_id, provider_reference,
            "The provider booking succeeded and reserved budget was committed.",
        )
        self.execution_store.complete(command.request_id, asdict(response))
        return response


class BookingExecute(BaseModel):
    request_id: str
    reservation_id: str
    agent_id: str
    customer_id: str
    action: str = "book_hotel"
    hotel: str
    amount: Decimal = Field(gt=0)
    currency: str = Field(min_length=3, max_length=3)
    refundable: bool
    lease_token: str | None = None


def create_connector_app(
    connector: ProtectedBookingConnector,
    *,
    abuse_limits: AbuseLimits | None = None,
    rate_limiter: RateLimiter | None = None,
) -> FastAPI:
    limits = abuse_limits or AbuseLimits.from_env()
    redis_url = os.getenv("INTENTGUARD_REDIS_URL")
    limiter = rate_limiter or (
        RedisSlidingWindowRateLimiter.from_url(redis_url)
        if redis_url
        else SlidingWindowRateLimiter()
    )
    app = FastAPI(title="IntentGuard Protected Booking Connector", version="1.0.0")
    app.add_middleware(
        RequestBodyLimitMiddleware,
        max_bytes=limits.max_request_body_bytes,
    )
    metrics = install_observability(
        app, service_name="intentguard-booking-connector"
    )
    close_limiter = getattr(limiter, "close", None)
    if callable(close_limiter):
        app.router.add_event_handler("shutdown", close_limiter)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "provider_circuit": connector.circuit_breaker.state}

    @app.post("/v1/bookings")
    def execute_booking(payload: BookingExecute, response: Response) -> dict[str, Any]:
        observation_fields(
            request_id=payload.request_id,
            reservation_id=payload.reservation_id,
            agent_id=payload.agent_id,
            customer_id=payload.customer_id,
        )
        try:
            rate = limiter.consume(
                scope="connector",
                key=payload.agent_id,
                limit=limits.connector_requests,
                window_seconds=limits.window_seconds,
            )
        except RateLimiterUnavailable as exc:
            metrics.abuse_rejections.labels(
                "connector", "limiter_unavailable"
            ).inc()
            raise HTTPException(
                status_code=503,
                detail="The distributed rate limiter is unavailable; the request failed closed.",
                headers={"Retry-After": "1"},
            ) from exc
        response.headers["X-RateLimit-Limit"] = str(limits.connector_requests)
        response.headers["X-RateLimit-Remaining"] = str(rate.remaining)
        if not rate.allowed:
            metrics.abuse_rejections.labels("connector", "rate_limit").inc()
            raise HTTPException(
                status_code=429,
                detail="The connector request rate limit was exceeded.",
                headers={
                    "Retry-After": str(rate.retry_after_seconds),
                    "X-RateLimit-Limit": str(limits.connector_requests),
                    "X-RateLimit-Remaining": "0",
                },
            )
        started_at = perf_counter()
        result = "success"
        if not payload.lease_token:
            metrics.connector_requests.labels("missing_lease").inc()
            metrics.connector_failures.labels("missing_lease").inc()
            metrics.connector_latency.labels("missing_lease").observe(
                perf_counter() - started_at
            )
            raise HTTPException(status_code=401, detail="A signed execution lease is required.")
        command = BookingCommand(**payload.model_dump())
        try:
            with operation_span(
                "intentguard.connector.execute", request_id=payload.request_id
            ):
                return asdict(connector.execute(command))
        except LeaseVerificationError as exc:
            result = "lease_rejected"
            metrics.connector_failures.labels(result).inc()
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        except ProviderTimeout as exc:
            result = "provider_timeout"
            metrics.connector_failures.labels(result).inc()
            raise HTTPException(status_code=504, detail=str(exc)) from exc
        except ProviderFailure as exc:
            result = "provider_failure"
            metrics.connector_failures.labels(result).inc()
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except ConnectorConflict as exc:
            result = "conflict"
            metrics.connector_failures.labels(result).inc()
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        finally:
            observation_fields(connector_result=result)
            metrics.connector_requests.labels(result).inc()
            metrics.connector_latency.labels(result).observe(
                perf_counter() - started_at
            )

    return app


class ClientCredentialsTokenProvider:
    """Fetch and cache a service-account token for connector-to-gateway calls."""

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        *,
        timeout: float = 5.0,
    ) -> None:
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self._token = ""
        self._expires_at = 0.0
        self._lock = RLock()

    def __call__(self) -> str:
        with self._lock:
            if self._token and time.monotonic() < self._expires_at:
                return self._token
            import httpx

            response = httpx.post(
                self.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            document = response.json()
            token = document.get("access_token")
            if not isinstance(token, str) or not token:
                raise RuntimeError("The identity provider returned no access token.")
            lifetime = max(1.0, float(document.get("expires_in", 60)))
            self._token = token
            self._expires_at = time.monotonic() + max(1.0, lifetime - 10.0)
            return token


class HttpGovernanceGateway:
    """Connector-side client for the governance gateway's internal API."""

    def __init__(
        self,
        base_url: str,
        access_token: str | None = None,
        *,
        token_provider: Callable[[], str] | None = None,
        timeout: float = 5.0,
    ) -> None:
        import httpx

        if not access_token and token_provider is None:
            raise ValueError("An access token or token provider is required.")
        self._access_token = access_token
        self._token_provider = token_provider
        self._client = httpx.Client(
            base_url=base_url,
            timeout=timeout,
        )

    def _headers(self) -> dict[str, str]:
        token = (
            self._token_provider()
            if self._token_provider is not None
            else self._access_token
        )
        return {
            **outbound_trace_headers(),
            "Authorization": f"Bearer {token}",
        }

    def fleet_state(self) -> FleetState:
        response = self._client.get(
            "/v1/fleet/status", headers=self._headers()
        )
        response.raise_for_status()
        return FleetState(**response.json())

    def lease_key(self) -> LeaseVerificationKey:
        response = self._client.get(
            "/v1/connectors/lease-key", headers=self._headers()
        )
        response.raise_for_status()
        return LeaseVerificationKey(**response.json())

    def commit(self, reservation_id: str, lease_id: str) -> None:
        response = self._client.post(
            f"/v1/connectors/reservations/{reservation_id}/commit",
            json={"lease_id": lease_id},
            headers=self._headers(),
        )
        response.raise_for_status()

    def release(self, reservation_id: str, reason: str) -> None:
        response = self._client.post(
            f"/v1/connectors/reservations/{reservation_id}/release",
            json={"reason": reason},
            headers=self._headers(),
        )
        response.raise_for_status()

    def close(self) -> None:
        self._client.close()


class EngineGovernanceGateway:
    """In-process gateway adapter used only by deterministic tests and demos."""

    def __init__(self, engine: Any) -> None:
        self.engine = engine

    def fleet_state(self) -> FleetState:
        return FleetState(
            stopped=self.engine.fleet_stopped,
            fleet_epoch=self.engine.fleet_epoch,
        )

    def commit(self, reservation_id: str, lease_id: str) -> None:
        self.engine.commit_reservation(reservation_id, lease_id=lease_id)

    def release(self, reservation_id: str, reason: str) -> None:
        self.engine.release_reservation(reservation_id, reason=reason)


def configured_connector() -> ProtectedBookingConnector:
    database_url = os.getenv("INTENTGUARD_DATABASE_URL")
    audience = os.getenv(
        "INTENTGUARD_LEASE_AUDIENCE", "intentguard-booking-connector"
    )
    gateway_url = os.getenv("INTENTGUARD_API_URL", "http://127.0.0.1:8000")
    access_token = os.getenv("INTENTGUARD_CONNECTOR_ACCESS_TOKEN")
    token_provider = None
    if not access_token:
        token_url = os.getenv("INTENTGUARD_OAUTH_TOKEN_URL")
        client_id = os.getenv("INTENTGUARD_OAUTH_CLIENT_ID")
        client_secret = os.getenv("INTENTGUARD_OAUTH_CLIENT_SECRET")
        if not all((token_url, client_id, client_secret)):
            raise RuntimeError(
                "Set INTENTGUARD_CONNECTOR_ACCESS_TOKEN or the OAuth client "
                "credentials configuration."
            )
        token_provider = ClientCredentialsTokenProvider(
            token_url, client_id, client_secret
        )
    governance = HttpGovernanceGateway(
        gateway_url,
        access_token,
        token_provider=token_provider,
        timeout=float(
            os.getenv("INTENTGUARD_CONNECTOR_GATEWAY_TIMEOUT_SECONDS", "5")
        ),
    )
    if database_url:
        key_registry = PostgresLeaseKeyRegistry(database_url)
        execution_store: ExecutionStore = PostgresExecutionStore(database_url)
    else:
        key_registry = InMemoryLeaseKeyRegistry()
        key_registry.save(governance.lease_key())
        execution_store = InMemoryExecutionStore()
    return ProtectedBookingConnector(
        verifier=ExecutionLeaseVerifier(
            audience=audience, key_registry=key_registry
        ),
        governance=governance,
        execution_store=execution_store,
        circuit_breaker=CircuitBreaker(
            failure_threshold=int(
                os.getenv("INTENTGUARD_CONNECTOR_CIRCUIT_FAILURE_THRESHOLD", "3")
            ),
            recovery_seconds=float(
                os.getenv("INTENTGUARD_CONNECTOR_CIRCUIT_RECOVERY_SECONDS", "30")
            ),
        ),
    )


def run() -> None:
    import uvicorn

    connector = configured_connector()
    uvicorn.run(
        create_connector_app(connector),
        host=os.getenv("INTENTGUARD_CONNECTOR_HOST", "127.0.0.1"),
        port=int(os.getenv("INTENTGUARD_CONNECTOR_PORT", "8100")),
    )


if __name__ == "__main__":
    run()
