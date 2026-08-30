"""Versioned OPA/Rego policy evaluation and control-plane storage."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Protocol
from uuid import uuid4

from .models import Decision, PolicyFinding


class PolicyEvaluationError(RuntimeError):
    pass


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    findings: tuple[PolicyFinding, ...]
    policy_version: str


class PolicyEvaluator(Protocol):
    def evaluate(self, policy_input: dict[str, Any]) -> PolicyDecision: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class PolicyVersion:
    version_id: str
    source: str
    status: str
    created_at: datetime
    created_by: str
    description: str
    based_on: str | None = None


class PolicyRepository(Protocol):
    def list(self) -> tuple[PolicyVersion, ...]: ...
    def get(self, version_id: str) -> PolicyVersion | None: ...
    def active(self) -> PolicyVersion | None: ...
    def save(self, version: PolicyVersion) -> None: ...
    def activate(self, version_id: str) -> PolicyVersion: ...
    def close(self) -> None: ...


class InMemoryPolicyRepository:
    def __init__(self, initial: PolicyVersion | None = None) -> None:
        self._versions = {} if initial is None else {initial.version_id: initial}
        self._lock = RLock()

    def list(self) -> tuple[PolicyVersion, ...]:
        with self._lock:
            return tuple(sorted(self._versions.values(), key=lambda item: item.created_at, reverse=True))

    def get(self, version_id: str) -> PolicyVersion | None:
        with self._lock:
            return self._versions.get(version_id)

    def active(self) -> PolicyVersion | None:
        with self._lock:
            return next((item for item in self._versions.values() if item.status == "published"), None)

    def save(self, version: PolicyVersion) -> None:
        with self._lock:
            if version.version_id in self._versions:
                raise ValueError(f"Policy version already exists: {version.version_id}")
            self._versions[version.version_id] = version

    def activate(self, version_id: str) -> PolicyVersion:
        with self._lock:
            if version_id not in self._versions:
                raise KeyError(f"Unknown policy version: {version_id}")
            self._versions = {
                key: replace(item, status="published" if key == version_id else ("retired" if item.status == "published" else item.status))
                for key, item in self._versions.items()
            }
            return self._versions[version_id]

    def close(self) -> None:
        return None


class PostgresPolicyRepository:
    def __init__(self, conninfo: str) -> None:
        from psycopg_pool import ConnectionPool
        self._pool = ConnectionPool(conninfo, min_size=1, max_size=8, open=True, kwargs={"autocommit": True})
        self._pool.wait(timeout=10)

    @staticmethod
    def _row(row: tuple[Any, ...] | None) -> PolicyVersion | None:
        return None if row is None else PolicyVersion(*row)

    def list(self) -> tuple[PolicyVersion, ...]:
        with self._pool.connection() as connection:
            rows = connection.execute("SELECT version_id, source, status, created_at, created_by, description, based_on FROM policy_versions ORDER BY created_at DESC").fetchall()
        return tuple(PolicyVersion(*row) for row in rows)

    def get(self, version_id: str) -> PolicyVersion | None:
        with self._pool.connection() as connection:
            row = connection.execute("SELECT version_id, source, status, created_at, created_by, description, based_on FROM policy_versions WHERE version_id=%s", (version_id,)).fetchone()
        return self._row(row)

    def active(self) -> PolicyVersion | None:
        with self._pool.connection() as connection:
            row = connection.execute("SELECT version_id, source, status, created_at, created_by, description, based_on FROM policy_versions WHERE status='published'").fetchone()
        return self._row(row)

    def save(self, version: PolicyVersion) -> None:
        with self._pool.connection() as connection:
            connection.execute("INSERT INTO policy_versions (version_id, source, status, created_at, created_by, description, based_on) VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (version_id) DO NOTHING", (version.version_id, version.source, version.status, version.created_at, version.created_by, version.description, version.based_on))

    def activate(self, version_id: str) -> PolicyVersion:
        with self._pool.connection() as connection:
            with connection.transaction():
                row = connection.execute("SELECT 1 FROM policy_versions WHERE version_id=%s FOR UPDATE", (version_id,)).fetchone()
                if row is None:
                    raise KeyError(f"Unknown policy version: {version_id}")
                connection.execute("UPDATE policy_versions SET status='retired' WHERE status='published'")
                connection.execute("UPDATE policy_versions SET status='published', published_at=now() WHERE version_id=%s", (version_id,))
        return self.get(version_id)  # type: ignore[return-value]

    def close(self) -> None:
        self._pool.close()


class OpaCliPolicyEvaluator:
    """Executes real Rego through the official OPA CLI and fails closed."""

    QUERY = "data.intentguard.authorization.decision"

    def __init__(self, executable: str, repository: PolicyRepository, *, timeout: float = 5.0) -> None:
        self.executable = executable
        self.repository = repository
        self.timeout = timeout

    def _policy_file(self, source: str) -> str:
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".rego", encoding="utf-8", delete=False)
        try:
            handle.write(source)
            return handle.name
        finally:
            handle.close()

    def validate(self, source: str) -> dict[str, Any]:
        path = self._policy_file(source)
        try:
            try:
                result = subprocess.run([self.executable, "check", "--strict", path], capture_output=True, text=True, timeout=self.timeout)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise PolicyEvaluationError("OPA policy validation is unavailable.") from exc
        finally:
            Path(path).unlink(missing_ok=True)
        return {"valid": result.returncode == 0, "errors": [] if result.returncode == 0 else [line for line in result.stderr.splitlines() if line]}

    def evaluate_source(self, source: str, policy_input: dict[str, Any], *, version: str = "dry-run") -> PolicyDecision:
        path = self._policy_file(source)
        try:
            try:
                result = subprocess.run(
                    [self.executable, "eval", "--format=json", "--fail", "--strict-builtin-errors", "--data", path, "--stdin-input", self.QUERY],
                    input=json.dumps(policy_input), capture_output=True, text=True, timeout=self.timeout,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise PolicyEvaluationError("OPA policy evaluation is unavailable.") from exc
        finally:
            Path(path).unlink(missing_ok=True)
        if result.returncode != 0:
            raise PolicyEvaluationError(result.stderr.strip() or "OPA policy evaluation failed.")
        try:
            value = json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
            return PolicyDecision(
                decision=Decision(value["decision"]),
                findings=tuple(PolicyFinding(**item) for item in value["findings"]),
                policy_version=version,
            )
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PolicyEvaluationError("OPA returned an invalid decision document.") from exc

    def evaluate(self, policy_input: dict[str, Any]) -> PolicyDecision:
        active = self.repository.active()
        if active is None:
            raise PolicyEvaluationError("No published policy is available.")
        return self.evaluate_source(active.source, policy_input, version=active.version_id)

    def close(self) -> None:
        self.repository.close()


class PolicyService:
    def __init__(self, evaluator: OpaCliPolicyEvaluator) -> None:
        self.evaluator = evaluator
        self.repository = evaluator.repository

    def create_draft(self, source: str, *, created_by: str, description: str) -> PolicyVersion:
        validation = self.evaluator.validate(source)
        if not validation["valid"]:
            raise ValueError("Invalid Rego policy: " + "; ".join(validation["errors"]))
        active = self.repository.active()
        version = PolicyVersion(f"rego-{uuid4().hex[:12]}", source, "draft", datetime.now(timezone.utc), created_by, description, active.version_id if active else None)
        self.repository.save(version)
        return version

    def publish(self, version_id: str) -> PolicyVersion:
        version = self.repository.get(version_id)
        if version is None:
            raise KeyError(f"Unknown policy version: {version_id}")
        validation = self.evaluator.validate(version.source)
        if not validation["valid"]:
            raise ValueError("Invalid Rego policy: " + "; ".join(validation["errors"]))
        return self.repository.activate(version_id)

    def rollback(self, version_id: str) -> PolicyVersion:
        version = self.repository.get(version_id)
        if version is None or version.status not in {"retired", "published"}:
            raise ValueError("Rollback requires a previously published policy version.")
        return self.repository.activate(version_id)

    def compare(self, left_id: str, right_id: str, cases: list[dict[str, Any]]) -> dict[str, Any]:
        left, right = self.repository.get(left_id), self.repository.get(right_id)
        if left is None or right is None:
            raise KeyError("Both policy versions must exist.")
        rows = []
        for index, policy_input in enumerate(cases):
            a = self.evaluator.evaluate_source(left.source, policy_input, version=left_id)
            b = self.evaluator.evaluate_source(right.source, policy_input, version=right_id)
            rows.append({"case": index, "left": a.decision.value, "right": b.decision.value, "changed": a.decision != b.decision})
        return {"left": left_id, "right": right_id, "cases": rows, "changed": sum(1 for row in rows if row["changed"])}


def default_policy_source() -> str:
    return (Path(__file__).parents[2] / "policies" / "authorization.rego").read_text(encoding="utf-8")


def initial_policy(source: str | None = None) -> PolicyVersion:
    return PolicyVersion("rego-1", source or default_policy_source(), "published", datetime(2026, 8, 28, tzinfo=timezone.utc), "system", "Initial travel authorization policy")


def find_opa_executable() -> str | None:
    import shutil
    configured = os.getenv("INTENTGUARD_OPA_EXECUTABLE")
    candidates = [configured, shutil.which("opa"), str(Path(__file__).parents[2] / ".tools" / "opa.exe")]
    return next((item for item in candidates if item and Path(item).is_file()), None)
