"""Reproducible policy accuracy, latency, and concurrency evidence."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from statistics import median
from time import perf_counter_ns
from typing import Any

from .models import ActionRequest, AgentProfile, Decision, IntentPassport
from .policy_engine import PolicyEngine


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * percentile)))
    return ordered[index]


def _configured_engine(*, daily_budget: str = "100000") -> tuple[
    PolicyEngine, datetime
]:
    now = datetime.now(timezone.utc)
    engine = PolicyEngine()
    engine.register_agent(
        AgentProfile(
            agent_id="benchmark-agent",
            name="Benchmark Agent",
            allowed_actions=frozenset({"book_hotel"}),
            max_action_amount=Decimal("50000"),
            daily_budget=Decimal(daily_budget),
        )
    )
    engine.register_intent(
        IntentPassport(
            intent_id="benchmark-intent",
            customer_id="benchmark-customer",
            agent_id="benchmark-agent",
            action="book_hotel",
            max_amount=Decimal("20000"),
            currency="INR",
            expires_at=now + timedelta(hours=1),
            required_attributes={"refundable": True},
        )
    )
    return engine, now


def _request(
    request_id: str,
    *,
    amount: str = "1000",
    action: str = "book_hotel",
    risk_score: int = 20,
    refundable: bool = True,
) -> ActionRequest:
    return ActionRequest(
        request_id=request_id,
        agent_id="benchmark-agent",
        action=action,
        amount=Decimal(amount),
        currency="INR",
        intent_id="benchmark-intent",
        risk_score=risk_score,
        attributes={"refundable": refundable},
    )


def run_benchmark(iterations: int = 1000) -> dict[str, Any]:
    """Run deterministic labeled scenarios plus an atomic overspend race."""

    engine, now = _configured_engine()
    labeled = (
        (_request("label-allow"), Decision.ALLOW),
        (_request("label-amount", amount="25000"), Decision.DENY),
        (_request("label-action", action="pay_merchant"), Decision.DENY),
        (_request("label-intent", refundable=False), Decision.DENY),
        (_request("label-review", risk_score=85), Decision.REVIEW),
    )
    correct = sum(
        engine.evaluate(request, now=now).decision is expected
        for request, expected in labeled
    )

    latency_ms: list[float] = []
    for index in range(iterations):
        started = perf_counter_ns()
        engine.evaluate(_request(f"latency-{index}"), now=now)
        latency_ms.append((perf_counter_ns() - started) / 1_000_000)

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
        "labeled_scenarios": len(labeled),
        "accuracy_percent": round(correct / len(labeled) * 100, 2),
        "latency_ms": {
            "p50": round(median(latency_ms), 4),
            "p95": round(_percentile(latency_ms, 0.95), 4),
            "p99": round(_percentile(latency_ms, 0.99), 4),
        },
        "concurrency": {
            "requests": len(race_requests),
            "allowed": len(allowed),
            "budget": "10000",
            "reserved_total": str(reserved_total),
            "overspend_violations": int(reserved_total > Decimal("10000")),
        },
        "audit_chain_verified": (
            engine.audit_ledger.verify() and race_engine.audit_ledger.verify()
        ),
    }


def main() -> None:
    import json

    print(json.dumps(run_benchmark(), indent=2))


if __name__ == "__main__":
    main()
