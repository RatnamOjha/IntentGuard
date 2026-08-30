from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

try:
    from fastapi.testclient import TestClient
except ImportError:
    TestClient = None

from intentguard import PolicyEngine
from intentguard.evaluation import percentile, render_markdown, run_manifest


class EvaluationHarnessTest(unittest.TestCase):
    def test_percentiles_are_deterministic_and_empty_safe(self) -> None:
        self.assertEqual(0.0, percentile([], 0.95))
        self.assertEqual(3, percentile([4, 1, 3, 2], 0.50))
        self.assertEqual(4, percentile([4, 1, 3, 2], 0.99))

    def test_manifest_runner_records_pass_fail_and_skip(self) -> None:
        manifest = {
            "scenarios": [
                {
                    "id": "pass",
                    "category": "correctness",
                    "requirement": "harness",
                    "test": "tests.test_evaluation._Fixture.test_pass",
                },
                {
                    "id": "skip",
                    "category": "reliability",
                    "requirement": "harness",
                    "test": "tests.test_evaluation._Fixture.test_skip",
                },
            ]
        }
        rows = run_manifest(manifest)
        self.assertEqual(["passed", "skipped"], [row["status"] for row in rows])
        self.assertTrue(all(row["duration_ms"] >= 0 for row in rows))

    def test_markdown_contains_required_evidence(self) -> None:
        report = {
            "generated_at": "2026-08-30T00:00:00+00:00",
            "status": "passed",
            "summary": {
                "categories": {
                    name: {"passed": 1, "failed": 0, "skipped": 0}
                    for name in ("correctness", "security", "reliability")
                },
                "acceptance_controls": 31,
                "llm_scenarios": 12,
                "max_budget_overspend": "0",
            },
            "performance": {
                "policy_engine_latency_ms": {"scope": "policy", "p50": 1, "p95": 2, "p99": 3},
                "concurrent_authorization": {"scope": "concurrent", "requests": 2, "p50": 1, "p95": 2, "p99": 3, "decisions_per_second": 10},
                "protected_connector_latency_ms": {"scope": "connector", "requests": 2, "p50": 1, "p95": 2, "p99": 3},
                "approval_queue_latency_ms": {"scope": "approval", "requests": 2, "p50": 1, "p95": 2, "p99": 3},
                "single_thread_throughput": {"decisions_per_second": 20},
            },
            "audit_chain_verified": True,
            "scenarios": [],
        }
        rendered = render_markdown(report)
        self.assertIn("Maximum observed budget overspend: **0**", rendered)
        self.assertIn("connector", rendered)
        self.assertIn("approval", rendered)


@unittest.skipIf(TestClient is None, "FastAPI test dependencies are unavailable")
class EvaluationReliabilityTest(unittest.TestCase):
    def test_readiness_fails_closed_when_database_is_unavailable(self) -> None:
        from intentguard.api import create_app

        with patch.dict(
            os.environ,
            {"INTENTGUARD_DATABASE_URL": "postgresql://unavailable/evaluation"},
            clear=False,
        ), patch("psycopg.connect", side_effect=OSError("database unavailable")):
            response = TestClient(create_app(PolicyEngine())).get("/health/ready")

        self.assertEqual(503, response.status_code)
        self.assertEqual(["database"], response.json()["detail"]["unavailable"])


class _Fixture(unittest.TestCase):
    def test_pass(self) -> None:
        self.assertTrue(True)

    @unittest.skip("deliberate fixture skip")
    def test_skip(self) -> None:
        self.fail("unreachable")


if __name__ == "__main__":
    unittest.main()
