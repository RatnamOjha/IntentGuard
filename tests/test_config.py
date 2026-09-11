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


class PolicyEngineResolutionTest(unittest.TestCase):
    """Choosing an evaluator must be a decision, never a path lookup.

    The built-in evaluator is deliberately not equivalent to Rego, and it is
    the more permissive of the two. Before this resolver existed, a missed
    binary lookup silently substituted it -- so dev, demo and CI enforced a
    weaker policy than the container did, and nothing said so.
    """

    def resolve(
        self, mode: str | None, opa: str | None, database_url: str | None
    ) -> str | None:
        from intentguard.api import resolve_policy_engine

        environment = {} if mode is None else {"INTENTGUARD_POLICY_ENGINE": mode}
        with patch.dict(os.environ, environment, clear=False):
            if mode is None:
                os.environ.pop("INTENTGUARD_POLICY_ENGINE", None)
            return resolve_policy_engine(opa, database_url=database_url)

    def test_auto_prefers_rego_when_the_binary_is_there(self) -> None:
        self.assertEqual("/opa", self.resolve(None, "/opa", None))

    def test_auto_falls_back_only_where_a_fallback_is_obviously_safe(self) -> None:
        """No database means a scratch demo, where zero-dependency boot wins."""

        self.assertIsNone(self.resolve(None, None, None))

    def test_auto_refuses_to_downgrade_once_a_database_is_configured(self) -> None:
        """The regression this whole change exists to prevent."""

        from intentguard.api import PolicyEngineMisconfigured

        with self.assertRaises(PolicyEngineMisconfigured) as caught:
            self.resolve(None, None, "postgresql:///intentguard")
        self.assertIn("must not be", str(caught.exception))

    def test_builtin_is_honoured_when_asked_for_explicitly(self) -> None:
        """Downgrading is allowed. Doing it by accident is not."""

        self.assertIsNone(self.resolve("builtin", "/opa", "postgresql:///x"))

    def test_opa_mode_refuses_to_start_without_a_binary(self) -> None:
        from intentguard.api import PolicyEngineMisconfigured

        with self.assertRaises(PolicyEngineMisconfigured):
            self.resolve("opa", None, None)

    def test_an_unknown_mode_is_refused_rather_than_guessed(self) -> None:
        from intentguard.api import PolicyEngineMisconfigured

        with self.assertRaises(PolicyEngineMisconfigured):
            self.resolve("sqlite", "/opa", None)
