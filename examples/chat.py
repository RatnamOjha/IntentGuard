"""Talk to the governed agent from a terminal.

Runs against an in-process policy engine, so it needs no server. Set
XAI_API_KEY to talk to Grok; without it a deterministic scripted planner is
used and everything still works.

    PYTHONPATH=src .venv/bin/python examples/chat.py

Pipe input to run it non-interactively:

    echo "book a refundable flight for 16000" | PYTHONPATH=src .venv/bin/python examples/chat.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from intentguard import (
    AgentProfile,
    GovernedAgent,
    IntentPassport,
    PolicyEngine,
    build_planner,
)

CUSTOMER = "card-member-001"
AGENT = "travel-agent-01"

GREEN, RED, YELLOW, DIM, BOLD, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"
)
COLOURS = {"allow": GREEN, "deny": RED, "review": YELLOW}


def build_engine() -> PolicyEngine:
    engine = PolicyEngine()
    now = datetime.now(timezone.utc)
    engine.register_agent(
        AgentProfile(
            agent_id=AGENT,
            name="Travel Concierge",
            allowed_actions=frozenset({"book_flight", "book_hotel"}),
            max_action_amount=Decimal("25000"),
            daily_budget=Decimal("40000"),
        )
    )
    engine.register_intent(
        IntentPassport(
            intent_id="intent-flight",
            customer_id=CUSTOMER,
            agent_id=AGENT,
            action="book_flight",
            max_amount=Decimal("18000"),
            currency="INR",
            expires_at=now + timedelta(hours=2),
            required_attributes={"refundable": True},
        )
    )
    engine.register_intent(
        IntentPassport(
            intent_id="intent-hotel",
            customer_id=CUSTOMER,
            agent_id=AGENT,
            action="book_hotel",
            max_amount=Decimal("12000"),
            currency="INR",
            expires_at=now + timedelta(hours=2),
        )
    )
    # Another customer, served by the same agent. It must stay invisible.
    engine.register_intent(
        IntentPassport(
            intent_id="intent-someone-else",
            customer_id="a-different-customer",
            agent_id=AGENT,
            action="book_flight",
            max_amount=Decimal("90000"),
            currency="INR",
            expires_at=now + timedelta(hours=2),
        )
    )
    return engine


def show_intents(agent: GovernedAgent) -> None:
    print(f"\n{BOLD}What this customer has authorized{RESET}")
    for intent in agent.intents_for(customer_id=CUSTOMER, agent_id=AGENT):
        constraints = (
            f"  requires {intent.required_attributes}"
            if intent.required_attributes
            else ""
        )
        print(
            f"  {intent.action:<12} up to {intent.max_amount} "
            f"{intent.currency}{constraints}"
        )
    print(
        f"{DIM}  The agent's own limits: 25000 per action, 40000 per day.{RESET}"
    )


def show_turn(turn) -> None:  # noqa: ANN001
    if turn.error is not None:
        print(f"  {RED}{BOLD}[agent unavailable]{RESET} {turn.error}")
        print(f"  {DIM}Nothing was proposed, so nothing was authorized.{RESET}")
        return
    if turn.decision is None:
        print(f"  {DIM}[no action]{RESET} {turn.reply}")
        return

    decision = turn.decision.value
    colour = COLOURS[decision]
    print(f"  {colour}{BOLD}[{decision.upper()}]{RESET} {turn.reply}")

    assert turn.result is not None
    codes = [finding.code for finding in turn.result.decision.findings]
    risk = turn.result.decision.risk
    if risk is not None:
        # Only worth calling out when under-declaring would have skipped review.
        note = (
            " (under-declared; review forced anyway)"
            if "RISK_SCORE_UNDER_DECLARED" in codes
            else ""
        )
        print(
            f"  {DIM}risk: declared {risk.declared}, gateway derived "
            f"{risk.derived}, effective {risk.effective}{note}{RESET}"
        )
        if risk.signals:
            print(f"  {DIM}signals: {', '.join(risk.signals)}{RESET}")
    print(f"  {DIM}findings: {', '.join(codes)}{RESET}")


SUGGESTIONS = (
    "book a refundable flight for 16000",
    "book a non-refundable flight for 9000",
    "book a flight for 25000",
    "book a hotel for 11000",
)


def main() -> None:
    engine = build_engine()
    agent = GovernedAgent(engine, planner=build_planner())

    print(f"{BOLD}IntentGuard governed agent{RESET}")
    print(f"planner: {agent.planner.name}", end="")
    if agent.planner.name == "scripted":
        print(
            f"  {DIM}(set XAI_API_KEY for Grok, or GROQ_API_KEY for Groq){RESET}"
        )
    else:
        print()
    show_intents(agent)
    print(f"\n{BOLD}Try{RESET}")
    for suggestion in SUGGESTIONS:
        print(f"  {suggestion}")
    print(f"\n{DIM}/intents  /audit  /quit{RESET}\n")

    interactive = sys.stdin.isatty()
    while True:
        if interactive:
            try:
                message = input(f"{BOLD}you >{RESET} ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
        else:
            line = sys.stdin.readline()
            if not line:
                break
            message = line.strip()
            if not message:
                continue
            print(f"{BOLD}you >{RESET} {message}")

        if not message:
            continue
        if message in {"/quit", "/exit"}:
            break
        if message == "/intents":
            show_intents(agent)
            continue
        if message == "/audit":
            ledger = engine.audit_ledger
            print(
                f"  {DIM}{len(ledger.events)} events, chain verified: "
                f"{ledger.verify()}{RESET}"
            )
            continue

        turn = agent.send(message, customer_id=CUSTOMER, agent_id=AGENT)
        show_turn(turn)
        print()

    ledger = engine.audit_ledger
    print(
        f"{DIM}{len(ledger.events)} audit events, chain verified: "
        f"{ledger.verify()}{RESET}"
    )


if __name__ == "__main__":
    main()
