"""Reproducible policy, latency, throughput, concurrency, and audit evidence."""

from __future__ import annotations

import os
import platform
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from statistics import median
from time import perf_counter, perf_counter_ns, sleep
from typing import Any

from .models import ActionRequest, AgentProfile, Decision, IntentPassport
from .policy_engine import PolicyEngine


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * percentile)))
    return ordered[index]


def _environment() -> dict[str, Any]:
    """Describe the machine the evidence was produced on."""

    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
    }


def _configured_engine(
    *,
    daily_budget: str = "100000",
    active: bool = True,
    agent_max_amount: str = "50000",
    intent_max_amount: str = "20000",
    intent_ttl: timedelta = timedelta(hours=1),
    intent_agent_id: str = "benchmark-agent",
    intent_action: str = "book_hotel",
    intent_attributes: dict[str, Any] | None = None,
) -> tuple[PolicyEngine, datetime]:
    now = datetime.now(timezone.utc)
    engine = PolicyEngine()
    engine.register_agent(
        AgentProfile(
            agent_id="benchmark-agent",
            name="Benchmark Agent",
            allowed_actions=frozenset({"book_hotel"}),
            max_action_amount=Decimal(agent_max_amount),
            daily_budget=Decimal(daily_budget),
            active=active,
        )
    )
    engine.register_intent(
        IntentPassport(
            intent_id="benchmark-intent",
            customer_id="benchmark-customer",
            agent_id=intent_agent_id,
            action=intent_action,
            max_amount=Decimal(intent_max_amount),
            currency="INR",
            expires_at=now + intent_ttl,
            required_attributes=(
                {"refundable": True}
                if intent_attributes is None
                else intent_attributes
            ),
        )
    )
    return engine, now


def create_api_probe_engine() -> PolicyEngine:
    """Create isolated state for browser-to-FastAPI latency probes."""

    engine, _ = _configured_engine(
        daily_budget="1000000",
        intent_ttl=timedelta(days=1),
    )
    return engine


def api_probe_request(request_id: str) -> ActionRequest:
    """Build a valid authorization request for the isolated API probe."""

    return _request(request_id, amount="1")


def _request(
    request_id: str,
    *,
    amount: str = "1000",
    action: str = "book_hotel",
    agent_id: str = "benchmark-agent",
    intent_id: str = "benchmark-intent",
    currency: str = "INR",
    risk_score: int = 20,
    attributes: dict[str, Any] | None = None,
) -> ActionRequest:
    return ActionRequest(
        request_id=request_id,
        agent_id=agent_id,
        action=action,
        amount=Decimal(amount),
        currency=currency,
        intent_id=intent_id,
        risk_score=risk_score,
        attributes=(
            {"refundable": True}
            if attributes is None
            else attributes
        ),
    )


def _decision_case(
    *,
    name: str,
    category: str,
    engine: PolicyEngine,
    now: datetime,
    request: ActionRequest,
    expected_decision: Decision,
    expected_finding: str,
) -> dict[str, Any]:
    result = engine.evaluate(request, now=now)
    finding_codes = [finding.code for finding in result.findings]
    passed = (
        result.decision is expected_decision
        and expected_finding in finding_codes
    )
    return {
        "name": name,
        "category": category,
        "passed": passed,
        "expected": {
            "decision": expected_decision.value,
            "finding": expected_finding,
        },
        "observed": {
            "decision": result.decision.value,
            "findings": finding_codes,
        },
    }


def _control_case(
    *,
    name: str,
    category: str,
    passed: bool,
    expected: str,
    observed: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "category": category,
        "passed": passed,
        "expected": expected,
        "observed": observed,
    }


def _run_acceptance_suite() -> tuple[list[dict[str, Any]], list[PolicyEngine]]:
    """Exercise deterministic policy boundaries and adversarial controls."""

    results: list[dict[str, Any]] = []
    engines: list[PolicyEngine] = []

    def configured(**kwargs: Any) -> tuple[PolicyEngine, datetime]:
        engine, now = _configured_engine(**kwargs)
        engines.append(engine)
        return engine, now

    def decision(
        name: str,
        category: str,
        engine: PolicyEngine,
        now: datetime,
        request: ActionRequest,
        expected_decision: Decision,
        expected_finding: str,
    ) -> None:
        results.append(
            _decision_case(
                name=name,
                category=category,
                engine=engine,
                now=now,
                request=request,
                expected_decision=expected_decision,
                expected_finding=expected_finding,
            )
        )

    base, base_now = configured()
    decision(
        "Compliant request is allowed",
        "permitted boundaries",
        base,
        base_now,
        _request("accept-compliant"),
        Decision.ALLOW,
        "POLICY_SATISFIED",
    )
    decision(
        "Exact customer amount boundary is allowed",
        "permitted boundaries",
        base,
        base_now,
        _request("accept-intent-boundary", amount="20000"),
        Decision.ALLOW,
        "POLICY_SATISFIED",
    )
    decision(
        "Additional non-conflicting context is allowed",
        "permitted boundaries",
        base,
        base_now,
        _request(
            "accept-extra-context",
            attributes={"refundable": True, "channel": "mobile"},
        ),
        Decision.ALLOW,
        "POLICY_SATISFIED",
    )
    decision(
        "Risk immediately below threshold is allowed",
        "risk routing",
        base,
        base_now,
        _request("accept-risk-below", risk_score=69),
        Decision.ALLOW,
        "POLICY_SATISFIED",
    )
    decision(
        "Risk threshold routes to review",
        "risk routing",
        base,
        base_now,
        _request("review-risk-threshold", risk_score=70),
        Decision.REVIEW,
        "HUMAN_APPROVAL_REQUIRED",
    )
    decision(
        "Maximum risk routes to review",
        "risk routing",
        base,
        base_now,
        _request("review-risk-maximum", risk_score=100),
        Decision.REVIEW,
        "HUMAN_APPROVAL_REQUIRED",
    )
    decision(
        "Customer intent amount breach is denied",
        "authenticated intent",
        base,
        base_now,
        _request("deny-intent-amount", amount="20001"),
        Decision.DENY,
        "INTENT_AMOUNT_EXCEEDED",
    )
    decision(
        "Agent action limit breach is denied",
        "permission envelope",
        base,
        base_now,
        _request("deny-agent-limit", amount="50001"),
        Decision.DENY,
        "AGENT_ACTION_LIMIT",
    )
    decision(
        "Unpermitted action is denied",
        "permission envelope",
        base,
        base_now,
        _request("deny-action", action="pay_merchant"),
        Decision.DENY,
        "ACTION_NOT_PERMITTED",
    )
    decision(
        "Wrong currency is denied",
        "authenticated intent",
        base,
        base_now,
        _request("deny-currency", currency="USD"),
        Decision.DENY,
        "INTENT_CURRENCY_MISMATCH",
    )
    decision(
        "Conflicting required attribute is denied",
        "authenticated intent",
        base,
        base_now,
        _request("deny-attribute", attributes={"refundable": False}),
        Decision.DENY,
        "INTENT_ATTRIBUTE_MISMATCH",
    )
    decision(
        "Missing required attribute is denied",
        "authenticated intent",
        base,
        base_now,
        _request("deny-missing-attribute", attributes={}),
        Decision.DENY,
        "INTENT_ATTRIBUTE_MISMATCH",
    )
    decision(
        "Unknown intent is denied",
        "authenticated intent",
        base,
        base_now,
        _request("deny-unknown-intent", intent_id="missing-intent"),
        Decision.DENY,
        "INTENT_UNKNOWN",
    )
    decision(
        "Unknown agent is denied",
        "identity and lifecycle",
        base,
        base_now,
        _request("deny-unknown-agent", agent_id="missing-agent"),
        Decision.DENY,
        "AGENT_UNKNOWN",
    )

    action_mismatch, action_mismatch_now = configured(
        intent_action="book_flight"
    )
    decision(
        "Intent action mismatch is denied",
        "authenticated intent",
        action_mismatch,
        action_mismatch_now,
        _request("deny-intent-action"),
        Decision.DENY,
        "INTENT_ACTION_MISMATCH",
    )

    agent_mismatch, agent_mismatch_now = configured(
        intent_agent_id="other-agent"
    )
    decision(
        "Intent assigned to another agent is denied",
        "authenticated intent",
        agent_mismatch,
        agent_mismatch_now,
        _request("deny-intent-agent"),
        Decision.DENY,
        "INTENT_AGENT_MISMATCH",
    )

    expired, expired_now = configured(intent_ttl=timedelta(seconds=-1))
    decision(
        "Expired intent is denied",
        "authenticated intent",
        expired,
        expired_now,
        _request("deny-expired-intent"),
        Decision.DENY,
        "INTENT_EXPIRED",
    )

    inactive, inactive_now = configured(active=False)
    decision(
        "Inactive agent is denied",
        "identity and lifecycle",
        inactive,
        inactive_now,
        _request("deny-inactive-agent"),
        Decision.DENY,
        "AGENT_INACTIVE",
    )

    revoked, revoked_now = configured()
    revoked.revoke_agent("benchmark-agent")
    decision(
        "Revoked agent is denied",
        "identity and lifecycle",
        revoked,
        revoked_now,
        _request("deny-revoked-agent"),
        Decision.DENY,
        "AGENT_REVOKED",
    )

    stopped, stopped_now = configured()
    stopped.stop_fleet(reason="Acceptance-suite fleet stop")
    decision(
        "Fleet emergency stop fails closed",
        "identity and lifecycle",
        stopped,
        stopped_now,
        _request("deny-fleet-stopped"),
        Decision.DENY,
        "FLEET_STOPPED",
    )

    exhausted, exhausted_now = configured(daily_budget="999")
    decision(
        "Daily budget breach is denied",
        "budget enforcement",
        exhausted,
        exhausted_now,
        _request("deny-daily-budget", amount="1000"),
        Decision.DENY,
        "DAILY_BUDGET_EXCEEDED",
    )

    exact_budget, exact_budget_now = configured(daily_budget="1000")
    decision(
        "Exact remaining budget is allowed",
        "budget enforcement",
        exact_budget,
        exact_budget_now,
        _request("accept-daily-boundary", amount="1000"),
        Decision.ALLOW,
        "POLICY_SATISFIED",
    )

    replay, replay_now = configured()
    replay_request = _request("control-idempotent-replay")
    first = replay.authorize_action(replay_request, now=replay_now)
    second = replay.authorize_action(replay_request, now=replay_now)
    same_lease = (
        first.lease is not None
        and second.lease is not None
        and first.lease.lease_id == second.lease.lease_id
        and first.reservation is not None
        and second.reservation is not None
        and first.reservation.reservation_id == second.reservation.reservation_id
    )
    results.append(
        _control_case(
            name="Identical request replay is idempotent",
            category="replay protection",
            passed=same_lease,
            expected="same lease and reservation",
            observed="same lease and reservation" if same_lease else "new artifact issued",
        )
    )

    conflict_rejected = False
    conflict_observed = "request accepted"
    try:
        replay.authorize_action(
            _request("control-idempotent-replay", amount="1001"),
            now=replay_now,
        )
    except ValueError as exc:
        conflict_rejected = "different action data" in str(exc)
        conflict_observed = str(exc)
    results.append(
        _control_case(
            name="Conflicting request-ID replay is rejected",
            category="replay protection",
            passed=conflict_rejected,
            expected="rejected as conflicting replay",
            observed=conflict_observed,
        )
    )

    stale, stale_now = configured()
    stale_authorization = stale.authorize_action(
        _request("control-stale-lease"),
        now=stale_now,
    )
    stale.stop_fleet(reason="Invalidate the outstanding lease")
    stale_rejected = False
    stale_observed = "lease accepted"
    try:
        stale.commit_reservation(
            stale_authorization.reservation.reservation_id,  # type: ignore[union-attr]
            lease_id=stale_authorization.lease.lease_id,  # type: ignore[union-attr]
            now=stale_now + timedelta(seconds=1),
        )
    except ValueError as exc:
        stale_rejected = "fleet stop" in str(exc)
        stale_observed = str(exc)
    results.append(
        _control_case(
            name="Pre-stop execution lease is rejected",
            category="lease safety",
            passed=stale_rejected,
            expected="rejected after fleet epoch change",
            observed=stale_observed,
        )
    )

    expired_lease, lease_now = configured()
    expiring_authorization = expired_lease.authorize_action(
        _request("control-expired-lease"),
        now=lease_now,
        lease_ttl=timedelta(seconds=1),
    )
    expiry_rejected = False
    expiry_observed = "lease accepted"
    try:
        expired_lease.commit_reservation(
            expiring_authorization.reservation.reservation_id,  # type: ignore[union-attr]
            lease_id=expiring_authorization.lease.lease_id,  # type: ignore[union-attr]
            now=lease_now + timedelta(seconds=2),
        )
    except ValueError as exc:
        expiry_rejected = "expired" in str(exc)
        expiry_observed = str(exc)
    results.append(
        _control_case(
            name="Expired execution lease is rejected",
            category="lease safety",
            passed=expiry_rejected,
            expected="rejected after lease expiry",
            observed=expiry_observed,
        )
    )

    # The agent is untrusted, so its self-reported risk may only raise the
    # effective score. An intent that does not pin refundability leaves that
    # choice to the agent, which is where a risk score has to do real work.
    under_declared, under_declared_now = configured(
        daily_budget="20000",
        intent_max_amount="18000",
        intent_attributes={},
    )
    decision(
        "Under-declared risk still routes to review",
        "risk integrity",
        under_declared,
        under_declared_now,
        _request(
            "control-risk-under-declared",
            amount="18000",
            risk_score=0,
            attributes={"refundable": False},
        ),
        Decision.REVIEW,
        "RISK_SCORE_UNDER_DECLARED",
    )

    monotonic, monotonic_now = configured()
    monotonic_violations: list[str] = []
    for declared in (0, 25, 50, 69, 70, 100):
        assessed = monotonic.evaluate(
            _request(f"control-risk-monotonic-{declared}", risk_score=declared),
            now=monotonic_now,
        )
        risk = assessed.risk
        if risk is None or risk.effective != max(declared, risk.derived):
            monotonic_violations.append(f"declared={declared}")
    results.append(
        _control_case(
            name="Declared risk can raise but never lower the derived score",
            category="risk integrity",
            passed=not monotonic_violations,
            expected="effective == max(declared, derived) for every declaration",
            observed=(
                "monotonic across 0-100"
                if not monotonic_violations
                else f"violated at {', '.join(monotonic_violations)}"
            ),
        )
    )

    # Deliberately corrupted, so it is built outside `configured()` and kept out
    # of the fleet-wide audit verification below.
    truncated, _ = _configured_engine()
    for index in range(3):
        truncated.audit_ledger.append("benchmark.probe", {"index": index})
    truncation_detected = False
    truncation_observed = "truncated chain still verified"
    truncated.audit_ledger._events.pop()
    if not truncated.audit_ledger.verify():
        truncation_detected = True
        truncation_observed = (
            "chain rejected at link "
            f"{truncated.audit_ledger.first_invalid_link()}"
        )
    results.append(
        _control_case(
            name="Audit truncation of the newest events is detected",
            category="audit integrity",
            passed=truncation_detected,
            expected="rejected against the separately held head checkpoint",
            observed=truncation_observed,
        )
    )

    revoked_lease, revoked_lease_now = configured()
    revoked_authorization = revoked_lease.authorize_action(
        _request("control-revoked-lease"),
        now=revoked_lease_now,
    )
    revoked_lease.revoke_agent("benchmark-agent")
    revocation_rejected = False
    revocation_observed = "lease accepted"
    try:
        revoked_lease.commit_reservation(
            revoked_authorization.reservation.reservation_id,  # type: ignore[union-attr]
            lease_id=revoked_authorization.lease.lease_id,  # type: ignore[union-attr]
            now=revoked_lease_now + timedelta(seconds=1),
        )
    except ValueError as exc:
        revocation_rejected = "revoked agent" in str(exc)
        revocation_observed = str(exc)
    results.append(
        _control_case(
            name="Revocation invalidates an outstanding lease",
            category="lease safety",
            passed=revocation_rejected,
            expected="rejected after agent revocation",
            observed=revocation_observed,
        )
    )

    return results, engines


def measure_http_round_trip(
    *,
    requests: int = 500,
    concurrency: int = 16,
    warmup: int = 25,
) -> dict[str, Any]:
    """Measure end-to-end HTTP latency against a real Uvicorn server.

    This is the number a caller actually experiences: TCP, HTTP parsing,
    Pydantic validation, the full authorization path, and JSON serialization,
    under concurrent load. It is not comparable to the in-process engine
    figures, which exclude all of that.

    Requests go to /v1/demo/benchmark/authorize-probe, which runs the complete
    FastAPI authorization path against isolated state so the measurement cannot
    disturb demo or operator data.
    """

    try:
        import httpx
        import uvicorn
    except ImportError:
        return {
            "scope": "http_round_trip_authorize",
            "measured": False,
            "reason": "Install the api and dev extras to measure HTTP latency.",
        }

    # Imported here: intentguard.api imports this module, so a module-level
    # import would be circular.
    from .api import create_app

    server = uvicorn.Server(
        uvicorn.Config(
            create_app(),
            host="127.0.0.1",
            port=0,
            log_level="error",
            access_log=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = perf_counter() + 30
    while not server.started and perf_counter() < deadline:
        sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=10)
        raise RuntimeError("The benchmark server did not start within 30s.")

    try:
        port = server.servers[0].sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}/v1/demo/benchmark/authorize-probe"

        def probe_batch(labels: list[str]) -> list[float]:
            samples: list[float] = []
            with httpx.Client(timeout=30.0) as client:
                for label in labels:
                    started = perf_counter_ns()
                    response = client.post(url, json={"request_id": label})
                    samples.append((perf_counter_ns() - started) / 1_000_000)
                    response.raise_for_status()
                    if response.json()["decision"] != "allow":
                        raise RuntimeError(
                            "The HTTP probe did not receive an allow decision."
                        )
            return samples

        probe_batch([f"warmup-{index}" for index in range(warmup)])

        # Round-robin so every worker stays busy for the whole window.
        batches: list[list[str]] = [[] for _ in range(concurrency)]
        for index in range(requests):
            batches[index % concurrency].append(f"measured-{index}")

        started_at = perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            collected = list(executor.map(probe_batch, batches))
        elapsed = perf_counter() - started_at
    finally:
        server.should_exit = True
        thread.join(timeout=10)

    samples = [sample for batch in collected for sample in batch]
    return {
        "scope": "http_round_trip_authorize",
        "measured": True,
        "requests": len(samples),
        "concurrency": concurrency,
        "elapsed_seconds": round(elapsed, 6),
        "requests_per_second": round(len(samples) / elapsed, 1),
        "p50": round(median(samples), 4),
        "p95": round(_percentile(samples, 0.95), 4),
        "p99": round(_percentile(samples, 0.99), 4),
        "max": round(max(samples), 4),
    }


def run_benchmark(
    iterations: int = 1000,
    *,
    include_http: bool = False,
    http_requests: int = 500,
    http_concurrency: int = 16,
) -> dict[str, Any]:
    """Run acceptance controls plus engine, race, and audit measurements."""

    acceptance_results, acceptance_engines = _run_acceptance_suite()
    passed = sum(result["passed"] for result in acceptance_results)
    failed_results = [
        result for result in acceptance_results if not result["passed"]
    ]
    categories = sorted(
        {result["category"] for result in acceptance_results}
    )

    engine, now = _configured_engine()
    engine_latency_ms: list[float] = []
    for index in range(iterations):
        started = perf_counter_ns()
        engine.evaluate(_request(f"latency-{index}"), now=now)
        engine_latency_ms.append((perf_counter_ns() - started) / 1_000_000)

    # Throughput is measured over a separate, uninstrumented loop across
    # pre-built requests so the figure excludes per-iteration timing calls and
    # request construction.
    throughput_engine, throughput_now = _configured_engine()
    throughput_requests = [
        _request(f"throughput-{index}") for index in range(iterations)
    ]
    throughput_started = perf_counter()
    for throughput_request in throughput_requests:
        throughput_engine.evaluate(throughput_request, now=throughput_now)
    throughput_elapsed = perf_counter() - throughput_started

    race_engine, race_now = _configured_engine(daily_budget="10000")
    race_requests = [
        _request(f"race-{index}", amount="2000") for index in range(20)
    ]
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(
            executor.map(
                lambda request: race_engine.authorize_action(
                    request,
                    now=race_now,
                ),
                race_requests,
            )
        )
    allowed = [
        result for result in results if result.decision.decision is Decision.ALLOW
    ]
    reserved_total = sum(
        (
            result.reservation.amount
            for result in allowed
            if result.reservation is not None
        ),
        Decimal("0"),
    )

    return {
        "iterations": iterations,
        "environment": _environment(),
        "acceptance": {
            "total": len(acceptance_results),
            "passed": passed,
            "failed": len(failed_results),
            "category_count": len(categories),
            "categories": categories,
            "failures": failed_results,
            "results": acceptance_results,
        },
        "engine_latency_ms": {
            "scope": "in_process_policy_engine",
            "p50": round(median(engine_latency_ms), 4),
            "p95": round(_percentile(engine_latency_ms, 0.95), 4),
            "p99": round(_percentile(engine_latency_ms, 0.99), 4),
        },
        "http_round_trip_ms": (
            measure_http_round_trip(
                requests=http_requests, concurrency=http_concurrency
            )
            if include_http
            # The /v1/demo/benchmark endpoint calls this from inside a running
            # server; it must not start another one to answer a request.
            else {
                "scope": "http_round_trip_authorize",
                "measured": False,
                "reason": "Run intentguard.benchmark as a script to measure HTTP latency.",
            }
        ),
        "engine_throughput": {
            "scope": "in_process_policy_engine_single_thread",
            "iterations": iterations,
            "elapsed_seconds": round(throughput_elapsed, 6),
            "decisions_per_second": round(iterations / throughput_elapsed, 1),
        },
        "concurrency": {
            "requests": len(race_requests),
            "allowed": len(allowed),
            "budget": "10000",
            "reserved_total": str(reserved_total),
            "overspend_violations": int(reserved_total > Decimal("10000")),
        },
        "audit_chain_verified": (
            engine.audit_ledger.verify()
            and throughput_engine.audit_ledger.verify()
            and race_engine.audit_ledger.verify()
            and all(
                acceptance_engine.audit_ledger.verify()
                for acceptance_engine in acceptance_engines
            )
        ),
    }


def main() -> None:
    import json

    print(json.dumps(run_benchmark(include_http=True), indent=2))


if __name__ == "__main__":
    main()
