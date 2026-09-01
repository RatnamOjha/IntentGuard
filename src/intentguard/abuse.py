"""Bounded, injectable controls for request floods and resource exhaustion."""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import RLock
from typing import Any, Callable
from typing import Protocol
from uuid import uuid4

from starlette.responses import JSONResponse


@dataclass(frozen=True)
class AbuseLimits:
    window_seconds: int = 60
    agent_requests: int = 300
    customer_requests: int = 180
    operator_requests: int = 180
    connector_requests: int = 600
    max_request_body_bytes: int = 1_048_576
    max_outstanding_reservations: int = 20
    max_pending_approvals: int = 500
    max_audit_page_size: int = 200

    @classmethod
    def from_env(cls) -> "AbuseLimits":
        return cls(
            window_seconds=int(os.getenv("INTENTGUARD_RATE_WINDOW_SECONDS", "60")),
            agent_requests=int(os.getenv("INTENTGUARD_AGENT_RATE_LIMIT", "300")),
            customer_requests=int(os.getenv("INTENTGUARD_CUSTOMER_RATE_LIMIT", "180")),
            operator_requests=int(os.getenv("INTENTGUARD_OPERATOR_RATE_LIMIT", "180")),
            connector_requests=int(os.getenv("INTENTGUARD_CONNECTOR_RATE_LIMIT", "600")),
            max_request_body_bytes=int(os.getenv("INTENTGUARD_MAX_REQUEST_BODY_BYTES", "1048576")),
            max_outstanding_reservations=int(os.getenv("INTENTGUARD_MAX_OUTSTANDING_RESERVATIONS", "20")),
            max_pending_approvals=int(os.getenv("INTENTGUARD_MAX_PENDING_APPROVALS", "500")),
            max_audit_page_size=int(os.getenv("INTENTGUARD_MAX_AUDIT_PAGE_SIZE", "200")),
        )

    def rate_for(self, scope: str) -> int:
        return {
            "agent": self.agent_requests,
            "customer": self.customer_requests,
            "operator": self.operator_requests,
            "connector": self.connector_requests,
        }[scope]


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after_seconds: int


class RateLimiter(Protocol):
    def consume(
        self, *, scope: str, key: str, limit: int, window_seconds: int
    ) -> RateLimitResult: ...


class RateLimiterUnavailable(RuntimeError):
    pass


class SlidingWindowRateLimiter:
    """Thread-safe process-local limiter; replaceable by a Redis adapter."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = RLock()

    def consume(
        self, *, scope: str, key: str, limit: int, window_seconds: int
    ) -> RateLimitResult:
        if limit < 1 or window_seconds < 1:
            raise ValueError("Rate limits and windows must be positive.")
        now = self._clock()
        cutoff = now - window_seconds
        bucket_key = (scope, key)
        with self._lock:
            bucket = self._events[bucket_key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, int(window_seconds - (now - bucket[0]) + 0.999))
                return RateLimitResult(False, 0, retry_after)
            bucket.append(now)
            return RateLimitResult(True, max(0, limit - len(bucket)), 0)


class RedisSlidingWindowRateLimiter:
    """Atomic distributed sliding window backed by a Redis sorted set."""

    SCRIPT = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local member = ARGV[3]
local clock = redis.call('TIME')
local now_ms = (tonumber(clock[1]) * 1000) + math.floor(tonumber(clock[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', key, '-inf', now_ms - window_ms)
local count = redis.call('ZCARD', key)
if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retry_ms = window_ms
  if #oldest == 2 then
    retry_ms = math.max(1, tonumber(oldest[2]) + window_ms - now_ms)
  end
  redis.call('PEXPIRE', key, window_ms)
  return {0, 0, math.ceil(retry_ms / 1000)}
end
redis.call('ZADD', key, now_ms, member)
redis.call('PEXPIRE', key, window_ms)
return {1, limit - count - 1, 0}
"""

    def __init__(self, client: Any, *, prefix: str = "intentguard:rate") -> None:
        self._client = client
        self._prefix = prefix
        self._script = client.register_script(self.SCRIPT)

    @classmethod
    def from_url(cls, url: str) -> "RedisSlidingWindowRateLimiter":
        import redis

        client = redis.Redis.from_url(
            url,
            decode_responses=False,
            socket_connect_timeout=1,
            socket_timeout=1,
            health_check_interval=30,
        )
        return cls(client)

    def consume(
        self, *, scope: str, key: str, limit: int, window_seconds: int
    ) -> RateLimitResult:
        if limit < 1 or window_seconds < 1:
            raise ValueError("Rate limits and windows must be positive.")
        redis_key = f"{self._prefix}:{scope}:{key}"
        try:
            allowed, remaining, retry_after = self._script(
                keys=[redis_key],
                args=[limit, window_seconds * 1000, uuid4().hex],
            )
        except Exception as exc:
            raise RateLimiterUnavailable(
                "The distributed rate limiter is unavailable."
            ) from exc
        return RateLimitResult(
            bool(int(allowed)), int(remaining), int(retry_after)
        )

    def close(self) -> None:
        self._client.close()

    def ping(self) -> None:
        """Raise a normalized error when the distributed limiter is unavailable."""

        try:
            self._client.ping()
        except Exception as exc:
            raise RateLimiterUnavailable("The rate-limit store is unavailable.") from exc


class RequestBodyLimitMiddleware:
    """Reject oversized bodies even when Content-Length is absent or false."""

    def __init__(self, app: Any, *, max_bytes: int) -> None:
        if max_bytes < 1:
            raise ValueError("The request body limit must be positive.")
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", ()))
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                if int(declared) > self.max_bytes:
                    await self._reject(scope, receive, send)
                    return
            except ValueError:
                await self._reject(scope, receive, send)
                return

        messages: list[dict[str, Any]] = []
        size = 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > self.max_bytes:
                await self._reject(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        async def replay() -> dict[str, Any]:
            if messages:
                return messages.pop(0)
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(scope: dict[str, Any], receive: Any, send: Any) -> None:
        response = JSONResponse(
            {"detail": "The request body exceeds the configured limit."},
            status_code=413,
        )
        await response(scope, receive, send)
