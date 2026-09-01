from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

REQUIRED_STEP_12 = (
    "docs/demo-script.md",
    "docs/adr/001-authentication.md",
    "docs/adr/002-state-storage.md",
    "docs/adr/003-policy-engine-boundary.md",
    "docs/runbook.md",
    "docs/incident-response.md",
    "docs/load-test-results.md",
    "docs/evaluation-methodology.md",
    "CONTRIBUTING.md",
)


class PortfolioDocumentationTest(unittest.TestCase):
    def test_step_12_documents_and_readme_sections_exist(self) -> None:
        missing = [path for path in REQUIRED_STEP_12 if not (ROOT / path).is_file()]
        self.assertEqual([], missing)

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for expected in (
            "## Two-minute overview",
            "```mermaid",
            "prototype/public/og.png",
            "./scripts/stack.ps1 up",
            "### Example authorization request",
            "### Security guarantees and known limits",
            "## Contribution split",
            "docs/deployment.md",
            "44/44 passed",
        ):
            self.assertIn(expected, readme)

    def test_local_markdown_links_resolve(self) -> None:
        documents = [ROOT / "README.md", ROOT / "CONTRIBUTING.md"]
        documents.extend((ROOT / "docs").rglob("*.md"))
        broken: list[str] = []
        link_pattern = re.compile(r"!?\[[^]]*\]\(([^)]+)\)")
        for document in documents:
            content = document.read_text(encoding="utf-8")
            for raw_target in link_pattern.findall(content):
                target = raw_target.strip().strip("<>").split("#", 1)[0]
                if not target or target.startswith(("http://", "https://", "mailto:")):
                    continue
                target = unquote(target.split(" ", 1)[0])
                resolved = (document.parent / target).resolve()
                if not resolved.exists():
                    broken.append(
                        f"{document.relative_to(ROOT)} -> {raw_target}"
                    )
        self.assertEqual([], broken)


if __name__ == "__main__":
    unittest.main()
