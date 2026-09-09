"""Measure how PolicyEngine's per-request state load scales with history.

Every governed operation calls PostgresStateRepository.load(), which reads six
tables with no WHERE and no LIMIT. authorization_records and
authorization_leases gain one row per request and are never pruned, so this
measures the cost of that design against accumulated history.

Seeds by duplicating genuine payloads produced by a real authorize call, so
row widths are realistic rather than invented.
"""

from __future__ import annotations

import os
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import psycopg

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
)

from intentguard.audit import PostgresAuditLedger
from intentguard.budget import PostgresBudgetLedger
from intentguard.models import ActionRequest, AgentProfile, IntentPassport
from intentguard.persistence import PostgresStateRepository
from intentguard.policy_engine import PolicyEngine

URL = os.environ["INTENTGUARD_DATABASE_URL"]
STEPS = [0, 500, 2_000, 5_000, 10_000, 20_000]
REPEATS = 5


def median_ms(fn, repeats=REPEATS):
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples)


def rows(table):
    with psycopg.connect(URL) as c:
        return c.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def grow_to(target):
    """Duplicate the seed record/lease rows until each table holds `target`."""
    with psycopg.connect(URL, autocommit=True) as c:
        for table, cols, key in (
            ("authorization_records", "request_payload, result_payload", "request_id"),
            ("authorization_leases", "payload", "lease_id"),
        ):
            current = c.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            missing = target - current
            if missing <= 0:
                continue
            # generate_series duplicates the seed row's real payload under
            # fresh ids, in one statement rather than a Python insert loop.
            c.execute(
                f"""
                INSERT INTO {table} ({key}, {cols})
                SELECT %s || g::text, {cols}
                FROM {table}
                CROSS JOIN generate_series(1, %s) AS g
                WHERE {key} = (SELECT min({key}) FROM {table})
                """,
                (f"pad-{target}-", missing),
            )


def build_engine():
    return PolicyEngine(
        budget_ledger=PostgresBudgetLedger(URL),
        state_repository=PostgresStateRepository(URL),
        audit_ledger=PostgresAuditLedger(URL),
    )


def main():
    engine = build_engine()
    now = datetime.now(timezone.utc)

    engine.register_agent(
        AgentProfile(
            agent_id="curve-agent",
            name="Curve",
            allowed_actions=frozenset({"refund"}),
            max_action_amount=Decimal("500"),
            daily_budget=Decimal("100000000"),
        )
    )
    engine.register_intent(
        IntentPassport(
            intent_id="curve-intent",
            customer_id="curve-customer",
            agent_id="curve-agent",
            action="refund",
            max_amount=Decimal("500"),
            currency="GBP",
            expires_at=now + timedelta(days=365),
        )
    )

    counter = {"n": 0}

    def authorize_once():
        counter["n"] += 1
        engine.authorize_action(
            ActionRequest(
                request_id=f"curve-req-{counter['n']}-{time.time_ns()}",
                agent_id="curve-agent",
                customer_id="curve-customer",
                intent_id="curve-intent",
                action="refund",
                risk_score=0,
                amount=Decimal("1"),
                currency="GBP",
            )
        )

    authorize_once()  # produce genuine payloads to duplicate

    repo = PostgresStateRepository(URL)
    audit = PostgresAuditLedger(URL)

    print(
        f"{'rows/table':>11} {'load() ms':>11} {'authorize ms':>13} "
        f"{'audit events':>13} {'audit/status ms':>16}",
        flush=True,
    )
    print("-" * 68, flush=True)

    for target in STEPS:
        grow_to(target)
        engine_at_n = build_engine()

        def authorize_at_n():
            counter["n"] += 1
            engine_at_n.authorize_action(
                ActionRequest(
                    request_id=f"curve-req-{counter['n']}-{time.time_ns()}",
                    agent_id="curve-agent",
                    customer_id="curve-customer",
                    intent_id="curve-intent",
                    action="refund",
                    risk_score=0,
                    amount=Decimal("1"),
                    currency="GBP",
                )
            )

        load_ms = median_ms(lambda: repo.load(default_policy_version="2026.07"))
        auth_ms = median_ms(authorize_at_n)

        # /v1/audit/status reads the full list once for `events` and again
        # inside verify() -> first_invalid_link().
        def audit_status():
            events = audit.events
            audit.verify()
            return events

        status_ms = median_ms(audit_status, repeats=3)
        engine_at_n.close()

        print(
            f"{rows('authorization_records'):>11,} {load_ms:>11.1f} "
            f"{auth_ms:>13.1f} {rows('audit_events'):>13,} "
            f"{status_ms:>16.1f}",
            flush=True,
        )

    repo.close()
    audit.close()
    engine.close()


if __name__ == "__main__":
    main()
