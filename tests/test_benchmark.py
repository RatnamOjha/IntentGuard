from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from intentguard.benchmark import (  # noqa: E402
    measure_http_round_trip,
    run_benchmark,
)

try:
    import httpx  # noqa: F401
    import uvicorn  # noqa: F401

    HTTP_EXTRAS = True
except ImportError:  # Allows domain-only runs before extras are installed.
    HTTP_EXTRAS = False


class BenchmarkTest(unittest.TestCase):
    def test_benchmark_is_reproducible_and_safe(self) -> None:
        evidence = run_benchmark(iterations=50)

        self.assertEqual(31, evidence["acceptance"]["total"])
        self.assertEqual(31, evidence["acceptance"]["passed"])
        self.assertEqual(0, evidence["acceptance"]["failed"])
        self.assertEqual([], evidence["acceptance"]["failures"])
        self.assertGreaterEqual(evidence["acceptance"]["category_count"], 10)
        self.assertEqual(0, evidence["concurrency"]["overspend_violations"])
        self.assertEqual(
            evidence["concurrency"]["budget"],
            evidence["concurrency"]["reserved_total"],
        )
        self.assertTrue(evidence["audit_chain_verified"])
        self.assertEqual(
            "in_process_policy_engine",
            evidence["engine_latency_ms"]["scope"],
        )
        self.assertGreaterEqual(evidence["engine_latency_ms"]["p99"], 0)
        self.assertGreaterEqual(
            evidence["engine_latency_ms"]["p99"],
            evidence["engine_latency_ms"]["p50"],
        )

        throughput = evidence["engine_throughput"]
        self.assertEqual(
            "in_process_policy_engine_single_thread", throughput["scope"]
        )
        self.assertEqual(50, throughput["iterations"])
        self.assertGreater(throughput["elapsed_seconds"], 0)
        self.assertGreater(throughput["decisions_per_second"], 0)

        # A benchmark run inside a server must not start another server.
        self.assertFalse(evidence["http_round_trip_ms"]["measured"])

        environment = evidence["environment"]
        for key in (
            "python_version",
            "python_implementation",
            "platform",
            "machine",
            "cpu_count",
        ):
            self.assertIn(key, environment)


@unittest.skipUnless(HTTP_EXTRAS, "Install the api and dev extras for HTTP timing")
class HttpRoundTripBenchmarkTest(unittest.TestCase):
    def test_measures_real_http_latency_under_concurrency(self) -> None:
        measured = measure_http_round_trip(
            requests=24, concurrency=4, warmup=4
        )

        self.assertTrue(measured["measured"])
        self.assertEqual("http_round_trip_authorize", measured["scope"])
        self.assertEqual(24, measured["requests"])
        self.assertEqual(4, measured["concurrency"])
        self.assertGreater(measured["requests_per_second"], 0)
        # Ordering must hold, and a real round trip is far slower than the
        # in-process engine, so the two figures cannot be confused.
        self.assertLessEqual(measured["p50"], measured["p95"])
        self.assertLessEqual(measured["p95"], measured["p99"])
        self.assertLessEqual(measured["p99"], measured["max"])
        self.assertGreater(measured["p50"], 0)


if __name__ == "__main__":
    unittest.main()
