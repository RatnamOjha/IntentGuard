from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from intentguard.benchmark import run_benchmark  # noqa: E402


class BenchmarkTest(unittest.TestCase):
    def test_benchmark_is_reproducible_and_safe(self) -> None:
        evidence = run_benchmark(iterations=50)

        self.assertEqual(100.0, evidence["accuracy_percent"])
        self.assertEqual(0, evidence["concurrency"]["overspend_violations"])
        self.assertEqual(
            evidence["concurrency"]["budget"],
            evidence["concurrency"]["reserved_total"],
        )
        self.assertTrue(evidence["audit_chain_verified"])
        self.assertGreaterEqual(evidence["latency_ms"]["p99"], 0)


if __name__ == "__main__":
    unittest.main()
