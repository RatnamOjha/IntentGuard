"""Production-style tracing, metrics, and structured request logging."""

from __future__ import annotations

import json
import logging
import os
import re
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, is_dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from opentelemetry import propagate, trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Status, StatusCode
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from prometheus_client.exposition import CONTENT_TYPE_LATEST


_context: ContextVar[dict[str, Any] | None] = ContextVar(
    "intentguard_observation_context", default=None
)
_provider_configured = False
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
LATENCY_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5)


def _json_default(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, (datetime, Decimal, Enum)):
        return str(value)
    return str(value)


class JsonFormatter(logging.Formatter):
    """One JSON object per line for ingestion by standard log collectors."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created).astimezone().isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
            **(_context.get() or {}),
            **getattr(record, "fields", {}),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=_json_default, separators=(",", ":"))


def structured_logger(name: str = "intentguard") -> logging.Logger:
    logger = logging.getLogger(name)
    if not any(getattr(handler, "intentguard_json", False) for handler in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        handler.intentguard_json = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
    logger.setLevel(os.getenv("INTENTGUARD_LOG_LEVEL", "INFO").upper())
    logger.propagate = False
    return logger


def configure_tracing(service_name: str) -> None:
    """Install one SDK provider and an optional OTLP/HTTP exporter."""

    global _provider_configured
    if _provider_configured:
        return
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": service_name,
                "service.version": "0.2.0",
                "deployment.environment": os.getenv(
                    "INTENTGUARD_ENVIRONMENT", "development"
                ),
            }
        )
    )
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    if not endpoint and os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").rstrip("/") + "/v1/traces"
    if endpoint:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    _provider_configured = True


def observation_fields(**fields: Any) -> None:
    """Attach bounded business identifiers to the current log line and span."""

    context = _context.get()
    if context is None:
        context = {}
        _context.set(context)
    span = trace.get_current_span()
    for key, value in fields.items():
        if value is None:
            continue
        rendered = str(value)
        if key.endswith("_id") and not _SAFE_ID.fullmatch(rendered):
            continue
        context[key] = rendered
        span.set_attribute(f"intentguard.{key}", rendered)


def outbound_trace_headers() -> dict[str, str]:
    """Return W3C trace context for downstream connector/gateway calls."""

    headers: dict[str, str] = {}
    propagate.inject(headers)
    context = _context.get() or {}
    if context.get("correlation_id"):
        headers["x-correlation-id"] = str(context["correlation_id"])
    return headers


@contextmanager
def operation_span(name: str, **attributes: Any):
    """Create a child span for an important application operation."""

    tracer = trace.get_tracer("intentguard.operations")
    with tracer.start_as_current_span(name) as span:
        for key, value in attributes.items():
            if value is not None:
                span.set_attribute(f"intentguard.{key}", str(value))
        yield span


class ObservabilityMetrics:
    """Low-cardinality Prometheus instruments for both services."""

    def __init__(self, service: str) -> None:
        self.service = service
        self.registry = CollectorRegistry(auto_describe=True)
        common = {"registry": self.registry}
        self.http_requests = Counter(
            "intentguard_http_requests_total", "HTTP requests.",
            ("service", "method", "route", "status"), **common,
        )
        self.http_latency = Histogram(
            "intentguard_http_request_duration_seconds", "HTTP request latency.",
            ("service", "method", "route"), buckets=LATENCY_BUCKETS, **common,
        )
        self.authorizations = Counter(
            "intentguard_authorization_requests_total", "Authorization decisions.",
            ("decision",), **common,
        )
        self.policy_latency = Histogram(
            "intentguard_policy_evaluation_duration_seconds", "Policy evaluation latency.",
            buckets=LATENCY_BUCKETS, **common,
        )
        self.budget_failures = Counter(
            "intentguard_budget_reservation_failures_total", "Budget reservation failures.",
            ("reason",), **common,
        )
        self.approval_queue_age = Gauge(
            "intentguard_approval_queue_oldest_age_seconds", "Age of the oldest pending approval.",
            **common,
        )
        self.lease_expirations = Counter(
            "intentguard_lease_expirations_total", "Expired leases rejected at commit.", **common,
        )
        self.connector_requests = Counter(
            "intentguard_connector_requests_total", "Protected connector results.",
            ("result",), **common,
        )
        self.connector_latency = Histogram(
            "intentguard_connector_duration_seconds", "Protected connector latency.",
            ("result",), buckets=LATENCY_BUCKETS, **common,
        )
        self.connector_failures = Counter(
            "intentguard_connector_failures_total", "Protected connector failures.",
            ("reason",), **common,
        )
        self.llm_latency = Histogram(
            "intentguard_llm_duration_seconds", "LLM proposal latency.",
            ("provider", "model", "status"), buckets=LATENCY_BUCKETS, **common,
        )
        self.llm_tokens = Counter(
            "intentguard_llm_tokens_total", "LLM tokens consumed.",
            ("provider", "model", "direction"), **common,
        )
        self.revocation_propagation = Histogram(
            "intentguard_revocation_propagation_seconds", "Revocation application latency.",
            buckets=LATENCY_BUCKETS, **common,
        )
        self.abuse_rejections = Counter(
            "intentguard_abuse_rejections_total", "Requests rejected by abuse controls.",
            ("scope", "reason"), **common,
        )

    def render(self) -> bytes:
        return generate_latest(self.registry)


def install_observability(
    app: FastAPI,
    *,
    service_name: str,
    metrics: ObservabilityMetrics | None = None,
) -> ObservabilityMetrics:
    """Install request spans, correlation headers, metrics, and JSON logs."""

    configure_tracing(service_name)
    instruments = metrics or ObservabilityMetrics(service_name)
    app.state.observability = instruments
    logger = structured_logger(f"intentguard.{service_name}")
    tracer = trace.get_tracer(service_name)

    @app.middleware("http")
    async def observe_request(request: Request, call_next: Any) -> Response:
        correlation = request.headers.get("x-correlation-id", "")
        if not _SAFE_ID.fullmatch(correlation):
            correlation = uuid4().hex
        request_context = propagate.extract(dict(request.headers))
        started = time.perf_counter()
        status_code = 500
        with tracer.start_as_current_span(
            f"{request.method} {request.url.path}", context=request_context
        ) as span:
            span_context = span.get_span_context()
            trace_id = (
                format(span_context.trace_id, "032x")
                if span_context.is_valid
                else uuid4().hex
            )
            token = _context.set(
                {
                    "service": service_name,
                    "correlation_id": correlation,
                    "trace_id": trace_id,
                }
            )
            span.set_attribute("http.request.method", request.method)
            span.set_attribute("url.path", request.url.path)
            try:
                response = await call_next(request)
                status_code = response.status_code
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR))
                raise
            finally:
                elapsed = time.perf_counter() - started
                route = getattr(request.scope.get("route"), "path", request.url.path)
                instruments.http_requests.labels(
                    service_name, request.method, route, str(status_code)
                ).inc()
                instruments.http_latency.labels(
                    service_name, request.method, route
                ).observe(elapsed)
                span.set_attribute("http.response.status_code", status_code)
                span.set_attribute("http.route", route)
                logger.info(
                    "http_request_completed",
                    extra={
                        "fields": {
                            "method": request.method,
                            "route": route,
                            "status": status_code,
                            "latency_ms": round(elapsed * 1000, 3),
                        }
                    },
                )
                _context.reset(token)
            response.headers["x-correlation-id"] = correlation
            response.headers["x-trace-id"] = trace_id
            return response

    @app.get("/metrics", include_in_schema=False)
    def metrics_endpoint() -> Response:
        return Response(instruments.render(), media_type=CONTENT_TYPE_LATEST)

    return instruments
