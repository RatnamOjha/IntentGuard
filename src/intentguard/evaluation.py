"""Unified, reproducible correctness, security, reliability, and performance evidence."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import platform
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from statistics import median
from time import perf_counter, perf_counter_ns
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .benchmark import run_benchmark
from .booking_connector import (
    BookingCommand,
    EngineGovernanceGateway,
    InMemoryExecutionStore,
    ProtectedBookingConnector,
)
from .execution_lease import (
    ExecutionLeaseSigner,
    ExecutionLeaseVerifier,
    InMemoryLeaseKeyRegistry,
)
from .llm_eval import evaluate_cases
from .models import ActionRequest, AgentProfile, Decision, IntentPassport
from .policy_engine import PolicyEngine

ROOT = Path(__file__).parents[2]
DEFAULT_MANIFEST = ROOT / "evaluations" / "suite.json"
DEFAULT_LLM_CASES = ROOT / "evaluations" / "llm_cases.json"


def percentile(values: list[float], fraction: float) -> float:
    """Return a nearest-rank percentile, including a safe empty result."""

    if not values:
        return 0.0
    ordered = sorted(values)
    index = round((len(ordered) - 1) * fraction)
    return ordered[max(0, min(len(ordered) - 1, index))]


class _Result(unittest.TestResult):
    def __init__(self) -> None:
        super().__init__()
        self.failure_text = ""

    def addFailure(self, test: unittest.TestCase, err: Any) -> None:
        super().addFailure(test, err)
        self.failure_text = self._exc_info_to_string(err, test)

    def addError(self, test: unittest.TestCase, err: Any) -> None:
        super().addError(test, err)
        self.failure_text = self._exc_info_to_string(err, test)


def run_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Execute each named unittest independently and retain auditable timing."""

    # ``intentguard-evaluate`` is a console script, so Python starts with the
    # virtual environment's bin directory on its import path rather than the
    # repository root that contains the manifest's ``tests.*`` modules.
    root = str(ROOT)
    remove_root_after_run = root not in sys.path
    if remove_root_after_run:
        sys.path.insert(0, root)

    loader = unittest.TestLoader()
    rows: list[dict[str, Any]] = []
    try:
        for scenario in manifest["scenarios"]:
            suite = loader.loadTestsFromName(scenario["test"])
            capture = io.StringIO()
            result = _Result()
            started = perf_counter_ns()
            with (
                contextlib.redirect_stdout(capture),
                contextlib.redirect_stderr(capture),
            ):
                suite.run(result)
            duration_ms = (perf_counter_ns() - started) / 1_000_000
            if result.skipped:
                status, detail = "skipped", result.skipped[0][1]
            elif result.failures or result.errors or result.unexpectedSuccesses:
                status, detail = "failed", result.failure_text or capture.getvalue()
            elif result.testsRun != 1:
                status, detail = (
                    "failed",
                    f"Expected one test, loaded {result.testsRun}.",
                )
            else:
                status, detail = "passed", ""
            rows.append(
                {
                    **scenario,
                    "status": status,
                    "passed": status == "passed",
                    "duration_ms": round(duration_ms, 3),
                    "detail": detail.strip()[-4000:],
                }
            )
    finally:
        if remove_root_after_run:
            sys.path.remove(root)
    return rows


def _configured_engine(*, signed_leases: bool = False) -> tuple[PolicyEngine, datetime, InMemoryLeaseKeyRegistry | None]:
    now = datetime.now(timezone.utc)
    keys = InMemoryLeaseKeyRegistry() if signed_leases else None
    signer = (
        ExecutionLeaseSigner(
            Ed25519PrivateKey.generate(),
            issuer="evaluation-gateway",
            audience="evaluation-connector",
            key_registry=keys,
        )
        if keys is not None
        else None
    )
    engine = PolicyEngine(lease_signer=signer, review_risk_threshold=70)
    engine.register_agent(
        AgentProfile(
            "evaluation-agent",
            "Evaluation Agent",
            frozenset({"book_hotel"}),
            Decimal(1000000),
            Decimal(1000000),
        )
    )
    engine.register_intent(
        IntentPassport(
            "evaluation-intent",
            "evaluation-customer",
            "evaluation-agent",
            "book_hotel",
            Decimal(1000000),
            "INR",
            now + timedelta(hours=1),
            {"refundable": True},
        )
    )
    return engine, now, keys


def _request(index: int, *, risk_score: int = 1) -> ActionRequest:
    return ActionRequest(
        request_id=f"evaluation-{index}",
        agent_id="evaluation-agent",
        customer_id="evaluation-customer",
        action="book_hotel",
        amount=Decimal(1),
        currency="INR",
        intent_id="evaluation-intent",
        risk_score=risk_score,
        attributes={"refundable": True},
    )


def _latency_summary(scope: str, samples: list[float]) -> dict[str, Any]:
    return {
        "scope": scope,
        "requests": len(samples),
        "p50": round(median(samples), 4),
        "p95": round(percentile(samples, 0.95), 4),
        "p99": round(percentile(samples, 0.99), 4),
        "max": round(max(samples), 4),
    }


def measure_concurrent_authorization(requests: int, workers: int) -> dict[str, Any]:
    engine, now, _ = _configured_engine()

    def evaluate(index: int) -> float:
        started = perf_counter_ns()
        decision = engine.evaluate(_request(index), now=now)
        if decision.decision is not Decision.ALLOW:
            raise RuntimeError("A performance probe was unexpectedly denied.")
        return (perf_counter_ns() - started) / 1_000_000

    started = perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        samples = list(executor.map(evaluate, range(requests)))
    elapsed = perf_counter() - started
    return {
        **_latency_summary("concurrent_in_process_authorization", samples),
        "concurrency": workers,
        "elapsed_seconds": round(elapsed, 6),
        "decisions_per_second": round(requests / elapsed, 1),
    }


def measure_connector(iterations: int) -> dict[str, Any]:
    engine, now, keys = _configured_engine(signed_leases=True)
    assert keys is not None
    connector = ProtectedBookingConnector(
        verifier=ExecutionLeaseVerifier(
            audience="evaluation-connector", key_registry=keys
        ),
        governance=EngineGovernanceGateway(engine),
        execution_store=InMemoryExecutionStore(),
    )
    samples: list[float] = []
    for index in range(iterations):
        request = _request(index)
        authorization = engine.authorize_action(request, now=now)
        assert authorization.lease is not None
        assert authorization.reservation is not None
        command = BookingCommand(
            request.request_id,
            authorization.reservation.reservation_id,
            request.agent_id,
            request.customer_id or "",
            request.action,
            "Evaluation Hotel",
            request.amount,
            request.currency,
            True,
            authorization.lease.token,
        )
        started = perf_counter_ns()
        connector.execute(command)
        samples.append((perf_counter_ns() - started) / 1_000_000)
    return _latency_summary("signed_lease_verify_provider_commit", samples)


def measure_approval_queue(iterations: int) -> dict[str, Any]:
    engine, now, _ = _configured_engine()
    samples: list[float] = []
    for index in range(iterations):
        started = perf_counter_ns()
        result = engine.authorize_action(_request(index, risk_score=100), now=now)
        samples.append((perf_counter_ns() - started) / 1_000_000)
        if result.decision.decision is not Decision.REVIEW:
            raise RuntimeError("An approval-queue probe was not routed to review.")
    listed_started = perf_counter_ns()
    approvals = engine.list_approvals()
    listing_ms = (perf_counter_ns() - listed_started) / 1_000_000
    return {
        **_latency_summary("review_routing_and_queue_insert", samples),
        "queue_depth": len(approvals),
        "full_queue_listing_ms": round(listing_ms, 4),
    }


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    passed = sum(row["status"] == "passed" for row in rows)
    failed = sum(row["status"] == "failed" for row in rows)
    skipped = sum(row["status"] == "skipped" for row in rows)
    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "pass_rate": round(passed / max(1, total - skipped), 4),
    }


def run_evaluation(
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
    llm_cases_path: Path = DEFAULT_LLM_CASES,
    benchmark_iterations: int = 1000,
    concurrent_requests: int = 500,
    concurrency: int = 16,
    connector_iterations: int = 100,
    approval_iterations: int = 200,
) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    scenario_rows = run_manifest(manifest)
    benchmark = run_benchmark(iterations=benchmark_iterations)
    llm_cases = json.loads(llm_cases_path.read_text(encoding="utf-8"))
    llm = evaluate_cases(llm_cases)
    categories = {
        category: _summary([row for row in scenario_rows if row["category"] == category])
        for category in ("correctness", "security", "reliability")
    }
    no_failures = all(row["status"] != "failed" for row in scenario_rows)
    no_failures = no_failures and benchmark["acceptance"]["failed"] == 0
    no_failures = no_failures and llm["passed"] == llm["scenarios"]
    no_failures = no_failures and benchmark["concurrency"]["overspend_violations"] == 0
    has_skips = any(row["status"] == "skipped" for row in scenario_rows)
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": (
            "failed"
            if not no_failures
            else "passed_with_skips"
            if has_skips
            else "passed"
        ),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
        },
        "summary": {
            "manifest": _summary(scenario_rows),
            "categories": categories,
            "acceptance_controls": benchmark["acceptance"]["total"],
            "llm_scenarios": llm["scenarios"],
            "max_budget_overspend": str(
                max(
                    Decimal(0),
                    Decimal(benchmark["concurrency"]["reserved_total"])
                    - Decimal(benchmark["concurrency"]["budget"]),
                )
            ),
        },
        "scenarios": scenario_rows,
        "acceptance": benchmark["acceptance"],
        "llm_security": llm,
        "performance": {
            "policy_engine_latency_ms": {
                **benchmark["engine_latency_ms"],
                "requests": benchmark_iterations,
            },
            "single_thread_throughput": benchmark["engine_throughput"],
            "concurrent_authorization": measure_concurrent_authorization(
                concurrent_requests, concurrency
            ),
            "protected_connector_latency_ms": measure_connector(connector_iterations),
            "approval_queue_latency_ms": measure_approval_queue(approval_iterations),
            "database_contention": {
                "measured": False,
                "reason": (
                    "Run the PostgreSQL integration race suite against a dedicated database; "
                    "the evaluation runner never load-tests a configured production database."
                ),
                "contract_test": "tests.test_budget_ledger.PostgresBudgetLedgerTest",
            },
            "budget_race": benchmark["concurrency"],
        },
        "audit_chain_verified": benchmark["audit_chain_verified"],
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    perf = report["performance"]
    lines = [
        "# IntentGuard evaluation evidence",
        "",
        f"Generated: `{report['generated_at']}`  ",
        f"Overall status: **{report['status'].upper()}**",
        "",
        "## Scenario results",
        "",
        "| Category | Passed | Failed | Skipped |",
        "| --- | ---: | ---: | ---: |",
    ]
    for category, values in summary["categories"].items():
        lines.append(
            f"| {category.title()} | {values['passed']} | {values['failed']} | {values['skipped']} |"
        )
    lines.extend(
        [
            "",
            f"Deterministic acceptance controls: **{summary['acceptance_controls']}**  ",
            f"LLM containment scenarios: **{summary['llm_scenarios']}**  ",
            f"Maximum observed budget overspend: **{summary['max_budget_overspend']}**",
            "",
            "## Performance",
            "",
            "| Scope | Requests | p50 ms | p95 ms | p99 ms |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for key in (
        "policy_engine_latency_ms",
        "concurrent_authorization",
        "protected_connector_latency_ms",
        "approval_queue_latency_ms",
    ):
        values = perf[key]
        lines.append(
            f"| {values['scope']} | {values.get('requests', report.get('iterations', '-'))} | "
            f"{values['p50']} | {values['p95']} | {values['p99']} |"
        )
    lines.extend(
        [
            "",
            f"Single-thread throughput: **{perf['single_thread_throughput']['decisions_per_second']} decisions/s**  ",
            f"Concurrent throughput: **{perf['concurrent_authorization']['decisions_per_second']} decisions/s**  ",
            f"Audit chain verified: **{str(report['audit_chain_verified']).lower()}**",
            "",
            "Database contention is intentionally measured by the isolated PostgreSQL integration race suite, not against an arbitrary configured database.",
            "",
        ]
    )
    exceptions = [row for row in report["scenarios"] if row["status"] != "passed"]
    if exceptions:
        lines.extend(["## Exceptions", ""])
        for row in exceptions:
            lines.append(f"- `{row['id']}`: {row['status']} — {row['detail']}")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_LLM_CASES)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--concurrent-requests", type=int, default=500)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--connector-iterations", type=int, default=100)
    parser.add_argument("--approval-iterations", type=int, default=200)
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--output-markdown", type=Path)
    args = parser.parse_args()
    report = run_evaluation(
        manifest_path=args.manifest,
        llm_cases_path=args.dataset,
        benchmark_iterations=args.iterations,
        concurrent_requests=args.concurrent_requests,
        concurrency=args.concurrency,
        connector_iterations=args.connector_iterations,
        approval_iterations=args.approval_iterations,
    )
    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.output_markdown:
        args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
        args.output_markdown.write_text(render_markdown(report), encoding="utf-8")
    print(render_markdown(report))
    if report["status"] == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
