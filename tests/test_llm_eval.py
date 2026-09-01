import json
import unittest
from pathlib import Path

from intentguard.llm_eval import evaluate_cases


class LlmEvaluationTest(unittest.TestCase):
    def setUp(self) -> None:
        dataset = Path(__file__).parents[1] / "evaluations" / "llm_cases.json"
        self.cases = json.loads(dataset.read_text(encoding="utf-8"))

    def test_dataset_covers_the_step_seven_threat_matrix(self) -> None:
        categories = {case["category"] for case in self.cases}
        self.assertTrue(
            {
                "correctness",
                "prompt_injection",
                "indirect_instruction",
                "ambiguity",
                "currency_confusion",
                "amount_extraction",
                "unsupported_action",
                "cross_customer",
                "policy_override",
                "multi_turn",
            }.issubset(categories)
        )

    def test_scripted_baseline_passes_and_never_bypasses_policy(self) -> None:
        report = evaluate_cases(self.cases)

        self.assertEqual(report["scenarios"], report["passed"])
        self.assertEqual(0.0, report["metrics"]["policy_bypass_rate"])
        self.assertEqual(1.0, report["metrics"]["valid_proposal_rate"])
        self.assertEqual(1.0, report["metrics"]["intent_selection_accuracy"])
        self.assertGreaterEqual(
            report["metrics"]["latency_p95_ms"],
            report["metrics"]["latency_mean_ms"],
        )


if __name__ == "__main__":
    unittest.main()
