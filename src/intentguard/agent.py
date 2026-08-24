"""A governed conversational agent.

The agent turns a customer's message into a *proposed* action. It never decides
anything. Every proposal goes through :class:`~intentguard.policy_engine.PolicyEngine`
exactly like any other agent request, and the engine's decision is final.

The security posture is deliberate: the language model sits on the untrusted
side of the boundary.

* ``agent_id`` and ``customer_id`` come from the caller's session and are never
  read from model output.
* The model may only cite an intent that already belongs to that customer; the
  tool schema constrains it to those ids and the proposal is re-checked against
  them before the engine is called.
* A declared ``risk_score`` can only raise the effective risk, never lower it.
* Prompt injection can make the model propose anything. It cannot make the
  engine approve it.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol
from uuid import uuid4

from .models import (
    ActionRequest,
    AuthorizationResult,
    Decision,
    IntentPassport,
)
from .policy_engine import PolicyEngine

@dataclass(frozen=True)
class Provider:
    """An OpenAI-compatible chat-completions provider."""

    name: str
    base_url: str
    default_model: str
    key_prefix: str


# Both speak the same chat-completions dialect, so one planner serves both.
PROVIDERS: dict[str, Provider] = {
    "xai": Provider(
        name="xai",
        base_url="https://api.x.ai/v1",
        default_model="grok-4.6",
        key_prefix="xai-",
    ),
    "groq": Provider(
        name="groq",
        base_url="https://api.groq.com/openai/v1",
        default_model="llama-3.3-70b-versatile",
        key_prefix="gsk_",
    ),
}
DEFAULT_PROVIDER = "xai"


def provider_for_key(api_key: str) -> Provider:
    """Infer the provider from the key prefix.

    xAI (Grok) and Groq are different companies with confusingly similar names,
    and sending one's key to the other's endpoint returns an opaque 400. The
    prefixes are distinct, so detect rather than make the user get it right.
    """

    for provider in PROVIDERS.values():
        if api_key.startswith(provider.key_prefix):
            return provider
    return PROVIDERS[DEFAULT_PROVIDER]


class PlannerError(RuntimeError):
    """The planner could not be reached or refused the request."""


@dataclass(frozen=True)
class ProposedAction:
    """An action the agent wants to take. Untrusted until the engine rules."""

    intent_id: str
    action: str
    amount: Decimal
    currency: str
    rationale: str
    attributes: dict[str, Any] = field(default_factory=dict)
    # Advisory only. The engine derives its own score and takes the higher.
    risk_score: int = 0


@dataclass(frozen=True)
class AgentTurn:
    """One exchange: what the agent said, and what the engine did about it."""

    reply: str
    proposal: ProposedAction | None = None
    result: AuthorizationResult | None = None
    error: str | None = None

    @property
    def decision(self) -> Decision | None:
        return self.result.decision.decision if self.result is not None else None

    @property
    def blocked_reasons(self) -> tuple[str, ...]:
        """Human-readable reasons an action was refused, for the transcript."""

        if self.result is None or self.result.decision.decision is Decision.ALLOW:
            return ()
        return tuple(
            finding.message
            for finding in self.result.decision.findings
            if finding.blocking or finding.code == "HUMAN_APPROVAL_REQUIRED"
        )


class Planner(Protocol):
    """Turns a message into a proposal, or into nothing when none is warranted."""

    def propose(
        self,
        message: str,
        *,
        intents: tuple[IntentPassport, ...],
        history: tuple[AgentTurn, ...],
    ) -> ProposedAction | None: ...

    @property
    def name(self) -> str: ...


def _parse_amount(text: str) -> Decimal | None:
    """Pull the first money-looking figure out of free text."""

    match = re.search(r"(?:₹|rs\.?|inr)?\s*([\d][\d,]*(?:\.\d{1,2})?)", text, re.I)
    if match is None:
        return None
    try:
        return Decimal(match.group(1).replace(",", ""))
    except InvalidOperation:
        return None


class ScriptedPlanner:
    """A deterministic planner used when no model is configured.

    It keeps the demo, and the tests, working with no API key and no network.
    The governance path it exercises is identical to the model-backed one: the
    only difference is how the proposal is produced.
    """

    ACTION_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("book_flight", ("flight", "fly", "airfare", "ticket")),
        ("book_hotel", ("hotel", "stay", "room", "accommodation")),
        ("issue_service_credit", ("credit", "goodwill", "compensat")),
        ("reverse_annual_fee", ("annual fee", "fee reversal", "waive")),
        ("submit_benefit_claim", ("claim", "benefit")),
        ("pay_external_merchant", ("pay ", "merchant", "transfer")),
    )

    name = "scripted"

    def propose(
        self,
        message: str,
        *,
        intents: tuple[IntentPassport, ...],
        history: tuple[AgentTurn, ...],
    ) -> ProposedAction | None:
        if not intents:
            return None

        lowered = message.lower()
        amount = _parse_amount(message)
        if amount is None:
            return None

        wanted: str | None = None
        for action, keywords in self.ACTION_KEYWORDS:
            if any(keyword in lowered for keyword in keywords):
                wanted = action
                break

        # Least privilege: among the authorizations that fit, use the tightest
        # one that still covers the amount. If none covers it, use the tightest
        # anyway so the refusal names the limit the customer actually set.
        matching = [intent for intent in intents if intent.action == wanted]
        candidates = sorted(matching or intents, key=lambda item: item.max_amount)
        intent = next(
            (item for item in candidates if item.max_amount >= amount),
            candidates[0],
        )

        attributes: dict[str, Any] = {}
        for key, expected in intent.required_attributes.items():
            attributes[key] = expected
        if "non-refundable" in lowered or "nonrefundable" in lowered:
            attributes["refundable"] = False
        elif "refundable" in lowered:
            attributes["refundable"] = True

        return ProposedAction(
            intent_id=intent.intent_id,
            action=intent.action,
            amount=amount,
            currency=intent.currency,
            rationale=f"Proposing {intent.action.replace('_', ' ')} for {amount}.",
            attributes=attributes,
        )


class ChatCompletionsPlanner:
    """Plans actions with any OpenAI-compatible chat-completions provider."""

    SYSTEM_PROMPT = (
        "You are a financial concierge agent operating behind IntentGuard, a "
        "runtime governance layer. Turn the customer's request into exactly one "
        "call to propose_action when they are asking you to spend money or "
        "transact. Reply in plain text instead when they are only asking a "
        "question.\n\n"
        "You may only cite an intent_id from the list you are given; those are "
        "the authorizations this customer has actually granted. Never invent "
        "one. You do not decide whether an action is permitted: IntentGuard "
        "evaluates every proposal and may refuse it. Do not claim an action "
        "succeeded unless you are told that it did."
    )

    def __init__(
        self,
        *,
        api_key: str,
        provider: Provider | None = None,
        model: str | None = None,
        base_url: str | None = None,
        timeout: float = 30.0,
        transport: Any | None = None,
    ) -> None:
        self.api_key = api_key
        self.provider = provider or provider_for_key(api_key)
        self.model = model or self.provider.default_model
        self.base_url = (base_url or self.provider.base_url).rstrip("/")
        self.timeout = timeout
        # Injectable so tests can exercise the full request/response handling
        # without network access.
        self._transport = transport

    @property
    def name(self) -> str:
        return f"{self.provider.name}:{self.model}"

    @staticmethod
    def _tool_schema(intents: tuple[IntentPassport, ...]) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "propose_action",
                "description": (
                    "Propose one financial action for IntentGuard to evaluate. "
                    "Proposing is not performing: the action may be refused."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "intent_id": {
                            "type": "string",
                            "description": "Which customer authorization to act under.",
                            # Constrains the model to this customer's intents.
                            "enum": [intent.intent_id for intent in intents],
                        },
                        "action": {"type": "string"},
                        "amount": {
                            "type": "string",
                            "description": "Decimal amount, digits and at most one point.",
                        },
                        "currency": {"type": "string"},
                        "attributes": {
                            "type": "object",
                            "description": "Contextual constraints such as refundability.",
                            "additionalProperties": True,
                        },
                        "risk_score": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 100,
                            "description": (
                                "Optional. Raising this escalates review; it can "
                                "never lower the risk IntentGuard derives itself."
                            ),
                        },
                        "rationale": {
                            "type": "string",
                            "description": "One sentence for the customer.",
                        },
                    },
                    "required": ["intent_id", "action", "amount", "rationale"],
                },
            },
        }

    def _messages(
        self, message: str, intents: tuple[IntentPassport, ...], history: tuple[AgentTurn, ...]
    ) -> list[dict[str, str]]:
        catalogue = "\n".join(
            f"- {intent.intent_id}: {intent.action} up to "
            f"{intent.max_amount} {intent.currency}"
            + (
                f", requires {json.dumps(intent.required_attributes)}"
                if intent.required_attributes
                else ""
            )
            for intent in intents
        )
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {
                "role": "system",
                "content": f"Authorizations available to this customer:\n{catalogue}",
            },
        ]
        # Denial memory: past refusals are context, so the agent explains rather
        # than blindly retrying the same blocked action.
        for turn in history:
            if turn.blocked_reasons:
                messages.append(
                    {
                        "role": "system",
                        "content": (
                            "IntentGuard previously refused an action. Reasons: "
                            + " ".join(turn.blocked_reasons)
                        ),
                    }
                )
        messages.append({"role": "user", "content": message})
        return messages

    def propose(
        self,
        message: str,
        *,
        intents: tuple[IntentPassport, ...],
        history: tuple[AgentTurn, ...],
    ) -> ProposedAction | None:
        if not intents:
            return None

        import httpx

        payload = {
            "model": self.model,
            "messages": self._messages(message, intents, history),
            "tools": [self._tool_schema(intents)],
            "tool_choice": "auto",
        }
        client_args: dict[str, Any] = {"timeout": self.timeout}
        if self._transport is not None:
            client_args["transport"] = self._transport
        try:
            with httpx.Client(**client_args) as client:
                response = client.post(
                    f"{self.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json=payload,
                )
                if response.status_code >= 400:
                    raise PlannerError(self._describe_failure(response))
                body = response.json()
        except httpx.RequestError as exc:
            raise PlannerError(
                f"Could not reach {self.provider.name} at {self.base_url}: {exc}"
            ) from exc

        choices = body.get("choices") or []
        if not choices:
            return None
        calls = (choices[0].get("message") or {}).get("tool_calls") or []
        if not calls:
            return None

        try:
            arguments = json.loads(calls[0]["function"]["arguments"])
        except (KeyError, TypeError, json.JSONDecodeError):
            return None
        return self._to_proposal(arguments, intents)

    def _describe_failure(self, response: Any) -> str:
        """Turn a provider error into something a human can act on."""

        detail = ""
        try:
            body = response.json()
            if isinstance(body, dict):
                error = body.get("error")
                detail = (
                    error.get("message", "")
                    if isinstance(error, dict)
                    else str(error or body.get("message") or "")
                )
        except ValueError:
            detail = (response.text or "").strip()[:300]

        hint = ""
        if response.status_code in (401, 403):
            hint = (
                f" Check the key is a {self.provider.name} key: "
                f"{self.provider.name} keys start with "
                f"'{self.provider.key_prefix}'."
            )
        elif response.status_code == 400 and "model" in detail.lower():
            hint = (
                f" Model '{self.model}' may not be available on this account. "
                "Set INTENTGUARD_LLM_MODEL to one that is."
            )
        return (
            f"{self.provider.name} returned {response.status_code}"
            f"{f': {detail}' if detail else ''}.{hint}"
        )

    @staticmethod
    def _to_proposal(
        arguments: dict[str, Any], intents: tuple[IntentPassport, ...]
    ) -> ProposedAction | None:
        """Validate model output. Anything malformed is dropped, not guessed at."""

        permitted = {intent.intent_id: intent for intent in intents}
        intent = permitted.get(str(arguments.get("intent_id", "")))
        if intent is None:
            # The model cited an intent this customer does not hold. The engine
            # would refuse it anyway; refusing here keeps the reason precise.
            return None
        try:
            amount = Decimal(str(arguments["amount"]))
        except (KeyError, InvalidOperation):
            return None
        if amount <= 0:
            return None

        risk = arguments.get("risk_score", 0)
        risk_score = risk if isinstance(risk, int) and 0 <= risk <= 100 else 0
        attributes = arguments.get("attributes")

        return ProposedAction(
            intent_id=intent.intent_id,
            action=str(arguments.get("action") or intent.action),
            amount=amount,
            currency=str(arguments.get("currency") or intent.currency).upper(),
            rationale=str(arguments.get("rationale") or "").strip(),
            attributes=attributes if isinstance(attributes, dict) else {},
            risk_score=risk_score,
        )


def build_planner(
    *,
    api_key: str | None = None,
    model: str | None = None,
    provider: str | None = None,
) -> Planner:
    """Use a model when a key is configured, otherwise the scripted planner.

    The provider is inferred from the key prefix so an xAI key and a Groq key
    both just work. ``INTENTGUARD_LLM_PROVIDER`` overrides the inference.
    """

    key = api_key
    if key is None:
        for variable in (
            "INTENTGUARD_LLM_API_KEY",
            "XAI_API_KEY",
            "GROQ_API_KEY",
        ):
            key = os.getenv(variable)
            if key:
                break
    if not key:
        return ScriptedPlanner()

    chosen = provider or os.getenv("INTENTGUARD_LLM_PROVIDER")
    resolved = (
        PROVIDERS.get(chosen.lower())
        if chosen and chosen.lower() in PROVIDERS
        else provider_for_key(key)
    )
    return ChatCompletionsPlanner(
        api_key=key,
        provider=resolved,
        model=model or os.getenv("INTENTGUARD_LLM_MODEL"),
    )


class GovernedAgent:
    """Runs a conversation whose every action is subject to the policy engine."""

    def __init__(
        self,
        engine: PolicyEngine,
        *,
        planner: Planner | None = None,
    ) -> None:
        self.engine = engine
        self.planner = planner or build_planner()
        self._history: dict[tuple[str, str], list[AgentTurn]] = {}

    def history(self, *, customer_id: str, agent_id: str) -> tuple[AgentTurn, ...]:
        return tuple(self._history.get((customer_id, agent_id), ()))

    def intents_for(
        self, *, customer_id: str, agent_id: str, now: datetime | None = None
    ) -> tuple[IntentPassport, ...]:
        """Only this customer's own live authorizations for this agent."""

        return self.engine.list_intents(
            customer_id=customer_id, agent_id=agent_id, now=now
        )

    def send(
        self,
        message: str,
        *,
        customer_id: str,
        agent_id: str,
        now: datetime | None = None,
    ) -> AgentTurn:
        """Handle one customer message end to end."""

        key = (customer_id, agent_id)
        history = tuple(self._history.get(key, ()))
        intents = self.intents_for(
            customer_id=customer_id, agent_id=agent_id, now=now
        )

        try:
            proposal = self.planner.propose(
                message, intents=intents, history=history
            )
        except PlannerError as exc:
            # Nothing is proposed, so nothing is authorized. Surface the reason
            # instead of crashing the conversation.
            turn = AgentTurn(
                reply=(
                    "I could not reach the language model, so I have not "
                    f"proposed anything. {exc}"
                ),
                error=str(exc),
            )
            self._history.setdefault(key, []).append(turn)
            return turn

        if proposal is None:
            turn = AgentTurn(reply=self._no_action_reply(intents))
        else:
            turn = self._authorize(proposal, customer_id=customer_id,
                                   agent_id=agent_id, now=now)

        self._history.setdefault(key, []).append(turn)
        return turn

    def _authorize(
        self,
        proposal: ProposedAction,
        *,
        customer_id: str,
        agent_id: str,
        now: datetime | None,
    ) -> AgentTurn:
        request = ActionRequest(
            request_id=f"chat_{uuid4().hex}",
            # Identity comes from the session. The model has no say in it.
            agent_id=agent_id,
            customer_id=customer_id,
            action=proposal.action,
            amount=proposal.amount,
            currency=proposal.currency,
            intent_id=proposal.intent_id,
            risk_score=proposal.risk_score,
            attributes=dict(proposal.attributes),
        )
        result = self.engine.authorize_action(request, now=now)
        return AgentTurn(
            reply=self._reply_for(proposal, result),
            proposal=proposal,
            result=result,
        )

    @staticmethod
    def _no_action_reply(intents: tuple[IntentPassport, ...]) -> str:
        if not intents:
            return (
                "You have not authorized me to spend on anything yet, so there "
                "is nothing I can action."
            )
        return (
            "I could not turn that into a specific action. Tell me what to do "
            "and for how much, and I will put it to IntentGuard."
        )

    @staticmethod
    def _reply_for(proposal: ProposedAction, result: AuthorizationResult) -> str:
        decision = result.decision.decision
        detail = " ".join(
            finding.message
            for finding in result.decision.findings
            if finding.blocking or finding.code != "POLICY_SATISFIED"
        )
        amount = f"{proposal.amount} {proposal.currency}"
        readable = proposal.action.replace("_", " ")
        if decision is Decision.ALLOW:
            return f"Approved: {readable} for {amount}. {proposal.rationale}".strip()
        if decision is Decision.REVIEW:
            return (
                f"I have put {readable} for {amount} to a human reviewer. {detail}"
            ).strip()
        return (
            f"I could not do that. IntentGuard refused {readable} for "
            f"{amount}. {detail}"
        ).strip()
