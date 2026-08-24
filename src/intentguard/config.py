"""Loading local configuration from a `.env` file.

Deliberately stdlib-only. The domain core has no dependencies and this keeps it
that way, rather than pulling in a settings library to read `KEY=value` lines.

Two rules matter:

* An environment variable that is already set always wins. A `.env` file is a
  convenience for local runs, not an override of what the operator exported or
  what a deployment injected.
* Nothing here is loaded implicitly by the library. Entry points opt in, so
  importing :mod:`intentguard` never reaches into the filesystem.
"""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_ENV_FILENAME = ".env"


def parse_env_file(text: str) -> dict[str, str]:
    """Parse `KEY=value` lines, ignoring comments, blanks, and `export`."""

    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, raw = stripped.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        if not key:
            continue
        value = raw.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def find_env_file(start: Path | None = None) -> Path | None:
    """Walk upwards for a `.env`, so the CWD does not have to be the repo root."""

    current = (start or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        candidate = directory / DEFAULT_ENV_FILENAME
        if candidate.is_file():
            return candidate
    return None


def load_env_file(path: Path | None = None, *, override: bool = False) -> dict[str, str]:
    """Apply a `.env` file to the process environment.

    Returns only the variables actually applied, so a caller can report what it
    picked up. Existing environment variables are left alone unless ``override``
    is set: the shell should beat a file on disk.
    """

    resolved = path or find_env_file()
    if resolved is None or not resolved.is_file():
        return {}

    applied: dict[str, str] = {}
    for key, value in parse_env_file(resolved.read_text()).items():
        if not value:
            # A blank entry is a placeholder, as in .env.example. Applying it
            # would mask a real value from the surrounding environment.
            continue
        if not override and os.environ.get(key):
            continue
        os.environ[key] = value
        applied[key] = value
    return applied
