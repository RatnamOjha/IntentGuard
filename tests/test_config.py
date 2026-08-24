"""Tests for `.env` loading.

The rules that matter are precedence and blast radius: an exported variable
must beat the file, a blank placeholder must not mask a real value, and
importing the library must never read from disk.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from intentguard.config import (  # noqa: E402
    find_env_file,
    load_env_file,
    parse_env_file,
)


class ParseEnvFileTest(unittest.TestCase):
    def test_parses_pairs_and_ignores_noise(self) -> None:
        parsed = parse_env_file(
            "\n".join(
                (
                    "# a comment",
                    "",
                    "XAI_API_KEY=xai-abc",
                    "export GROQ_API_KEY=gsk_def",
                    'QUOTED="quoted value"',
                    "SINGLE='single'",
                    "SPACED = padded ",
                    "no_equals_sign",
                )
            )
        )

        self.assertEqual(
            {
                "XAI_API_KEY": "xai-abc",
                "GROQ_API_KEY": "gsk_def",
                "QUOTED": "quoted value",
                "SINGLE": "single",
                "SPACED": "padded",
            },
            parsed,
        )

    def test_a_value_containing_equals_is_kept_whole(self) -> None:
        self.assertEqual(
            {"URL": "https://example.com/?a=1&b=2"},
            parse_env_file("URL=https://example.com/?a=1&b=2"),
        )


class LoadEnvFileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / ".env"

    def test_applies_values_that_are_not_already_set(self) -> None:
        self.path.write_text("INTENTGUARD_TEST_KEY=from-file\n")

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("INTENTGUARD_TEST_KEY", None)
            applied = load_env_file(self.path)

            self.assertEqual({"INTENTGUARD_TEST_KEY": "from-file"}, applied)
            self.assertEqual("from-file", os.environ["INTENTGUARD_TEST_KEY"])

    def test_an_exported_variable_beats_the_file(self) -> None:
        self.path.write_text("INTENTGUARD_TEST_KEY=from-file\n")

        with patch.dict(
            os.environ, {"INTENTGUARD_TEST_KEY": "from-shell"}, clear=False
        ):
            applied = load_env_file(self.path)

            self.assertEqual({}, applied)
            self.assertEqual("from-shell", os.environ["INTENTGUARD_TEST_KEY"])

    def test_override_reverses_that_when_asked(self) -> None:
        self.path.write_text("INTENTGUARD_TEST_KEY=from-file\n")

        with patch.dict(
            os.environ, {"INTENTGUARD_TEST_KEY": "from-shell"}, clear=False
        ):
            load_env_file(self.path, override=True)

            self.assertEqual("from-file", os.environ["INTENTGUARD_TEST_KEY"])

    def test_a_blank_placeholder_never_masks_a_real_value(self) -> None:
        """.env.example ships blank keys; applying them would break the shell."""

        self.path.write_text("INTENTGUARD_TEST_KEY=\n")

        with patch.dict(
            os.environ, {"INTENTGUARD_TEST_KEY": "from-shell"}, clear=False
        ):
            load_env_file(self.path, override=True)

            self.assertEqual("from-shell", os.environ["INTENTGUARD_TEST_KEY"])

    def test_a_missing_file_is_not_an_error(self) -> None:
        self.assertEqual({}, load_env_file(self.path / "absent"))

    def test_find_walks_upwards_from_a_subdirectory(self) -> None:
        self.path.write_text("INTENTGUARD_TEST_KEY=x\n")
        nested = Path(self.directory.name) / "a" / "b"
        nested.mkdir(parents=True)

        self.assertEqual(self.path.resolve(), find_env_file(nested))


class ImportPurityTest(unittest.TestCase):
    def test_importing_the_package_does_not_read_any_env_file(self) -> None:
        """Loading is opt-in at entry points, never a side effect of import."""

        import intentguard

        with patch("intentguard.config.load_env_file") as loader:
            import importlib

            importlib.reload(intentguard)
            loader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
