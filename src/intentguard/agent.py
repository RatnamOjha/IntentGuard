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

The provider layer supports xAI, Groq, and OpenAI's Responses API. Without a
key the agent falls back to a deterministic scripted planner so the demo and
the tests run offline.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .models import (
    ActionRequest,
    AuthorizationResult,
    Decision,
    IntentPassport,
)
from .policy_engine import PolicyEngine

@dataclass(frozen=True)
class Provider:
    """Configuration for one model API dialect."""

    name: str
    base_url: str
    default_model: str
    key_prefix: str
    api_style: str = "chat_completions"


# xAI and Groq expose the chat-completions dialect. OpenAI uses the Responses
# dialect. The planner keeps these transport details behind one proposal-only
# contract.
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
        default_model="openai/gpt-oss-120b",
        key_prefix="gsk_",
    ),
    "openai": Provider(
        name="openai",
        base_url="https://api.openai.com/v1",
        default_model="gpt-5",
        key_prefix="sk-",
        api_style="responses",
    ),
}
DEFAULT_PROVIDER = "xai"


def redact_sensitive(value: Any) -> Any:
    """Redact common secrets and direct identifiers before telemetry storage."""

    sensitive_keys = {
        "api_key", "authorization", "card_number", "cvv", "email",
        "passport_number", "token", "access_token", "secret",
    }
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key.lower() in sensitive_keys else redact_sensitive(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive(item) for item in value)
    if isinstance(value, str):
        text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[REDACTED_EMAIL]", value)
        text = re.sub(r"\b(?:\d[ -]*?){12,19}\b", "[REDACTED_NUMBER]", text)
        return re.sub(r"\b(?:sk-|xai-|gsk_)[A-Za-z0-9_-]+", "[REDACTED_TOKEN]", text)
    return value


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
class PlannerTrace:
    """Safe operational metadata; raw customer text is intentionally absent."""

    trace_id: str
    provider: str
    model: str
    prompt_version: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    estimated_cost_usd: Decimal
    latency_ms: float
    attempts: int
    status: str
    request_fingerprint: str
    error: str | None = None


class ProposalPayload(BaseModel):
    """Strictly validated shape accepted from an untrusted model."""

    model_config = ConfigDict(extra="forbid")

    intent_id: str = Field(min_length=1, max_length=200)
    action: str | None = Field(default=None, min_length=1, max_length=100)
    amount: Decimal = Field(gt=0, max_digits=20, decimal_places=2)
    currency: str | None = Field(default=None, pattern=r"^[A-Za-z]{3}$")
    attributes: dict[str, Any] = Field(default_factory=dict)
    risk_score: int = Field(default=0, ge=0, le=100)
    rationale: str = Field(min_length=1, max_length=500)

    @field_validator("amount")
    @classmethod
    def finite_amount(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("amount must be finite")
        return value


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
    trace: PlannerTrace | None = None

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

    @property
    def last_trace(self) -> PlannerTrace | None: ...


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

    def __init__(self) -> None:
        self._last_trace: PlannerTrace | None = None
        self._trace_id: str | None = None

    def set_trace_id(self, trace_id: str) -> None:
        self._trace_id = trace_id

    @property
    def last_trace(self) -> PlannerTrace | None:
        return self._last_trace

    def propose(
        self,
        message: str,
        *,
        intents: tuple[IntentPassport, ...],
        history: tuple[AgentTurn, ...],
    ) -> ProposedAction | None:
        started = time.perf_counter()
        fingerprint = hashlib.sha256(message.encode("utf-8")).hexdigest()[:16]
        if not intents:
            self._trace(started, fingerprint, "no_action")
            return None

        lowered = message.lower()
        if re.search(r"(?:\busd\b|\beur\b|\bgbp\b|[$â‚¬Â£])", lowered):
            self._trace(started, fingerprint, "no_action")
            return None
        amount = _parse_amount(message)
        if amount is None:
            self._trace(started, fingerprint, "no_action")
            return None

        wanted: str | None = None
        for action, keywords in self.ACTION_KEYWORDS:
            if any(keyword in lowered for keyword in keywords):
                wanted = action
                break

        if wanted is None:
            self._trace(started, fingerprint, "no_action")
            return None

        # Least privilege: among the authorizations that fit, use the tightest
        # one that still covers the amount. If none covers it, use the tightest
        # anyway so the refusal names the limit the customer actually set.
        matching = [intent for intent in intents if intent.action == wanted]
        if not matching:
            self._trace(started, fingerprint, "no_action")
            return None
        candidates = sorted(matching, key=lambda item: item.max_amount)
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

        proposal = ProposedAction(
            intent_id=intent.intent_id,
            action=intent.action,
            amount=amount,
            currency=intent.currency,
            rationale=f"Proposing {intent.action.replace('_', ' ')} for {amount}.",
            attributes=attributes,
        )
        self._trace(started, fingerprint, "proposal")
        return proposal

    def _trace(self, started: float, fingerprint: str, status: str) -> None:
        self._last_trace = PlannerTrace(
            trace_id=self._trace_id or uuid4().hex,
            provider="deterministic",
            model="scripted-v2",
            prompt_version="scripted-rules-v2",
            input_tokens=0,
            output_tokens=0,
            total_tokens=0,
            estimated_cost_usd=Decimal("0"),
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
            attempts=1,
            status=status,
            request_fingerprint=fingerprint,
        )


class ChatCompletionsPlanner:
    """Plans actions with any OpenAI-compatible chat-completions provider."""

    PROMPT_VERSION = "financial-proposal-v2"
    RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})

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
        max_retries: int = 2,
        retry_backoff: float = 0.05,
        sleeper: Any = time.sleep,
        max_tool_calls: int = 1,
    ) -> None:
        self.api_key = api_key
        self.provider = provider or provider_for_key(api_key)
        self.model = model or self.provider.default_model
        self.base_url = (base_url or self.provider.base_url).rstrip("/")
        self.timeout = timeout
        # Injectable so tests can exercise the full request/response handling
        # without network access.
        self._transport = transport
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        self._sleeper = sleeper
        self.max_tool_calls = max_tool_calls
        self._last_trace: PlannerTrace | None = None
        self._trace_id: str | None = None

    def set_trace_id(self, trace_id: str) -> None:
        self._trace_id = trace_id

    @property
    def last_trace(self) -> PlannerTrace | None:
        return self._last_trace

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
                    "required": [
                        "intent_id",
                        "action",
                        "amount",
                        "currency",
                        "attributes",
                        "risk_score",
                        "rationale",
                    ],
                    "additionalProperties": False,
                },
                "strict": True,
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

        trace_id = self._trace_id or uuid4().hex
        fingerprint = hashlib.sha256(message.encode("utf-8")).hexdigest()[:16]
        payload, endpoint = self._request(message, intents, history, trace_id)
        client_args: dict[str, Any] = {"timeout": self.timeout}
        if self._transport is not None:
            client_args["transport"] = self._transport
        started = time.perf_counter()
        last_error: Exception | None = None
        body: dict[str, Any] | None = None
        attempts = 0
        with httpx.Client(**client_args) as client:
            for attempt in range(self.max_retries + 1):
                attempts = attempt + 1
                try:
                    response = client.post(
                        f"{self.base_url}{endpoint}",
                        headers={"Authorization": f"Bearer {self.api_key}"},
                        json=payload,
                    )
                    if response.status_code in self.RETRYABLE_STATUS and attempt < self.max_retries:
                        self._sleeper(self.retry_backoff * (2**attempt))
                        continue
                    if response.status_code >= 400:
                        raise PlannerError(self._describe_failure(response))
                    try:
                        body = response.json()
                    except ValueError as exc:
                        raise PlannerError("The model provider returned malformed JSON.") from exc
                    break
                except httpx.RequestError as exc:
                    last_error = exc
                    if attempt < self.max_retries:
                        self._sleeper(self.retry_backoff * (2**attempt))
                        continue
                    error = PlannerError(
                        f"Could not reach {self.provider.name} at {self.base_url}: {exc}"
                    )
                    self._set_trace(trace_id, fingerprint, started, attempts, "error", {}, str(error))
                    raise error from exc
                except PlannerError as exc:
                    last_error = exc
                    self._set_trace(trace_id, fingerprint, started, attempts, "error", {}, str(exc))
                    raise
        if body is None:
            error = PlannerError(str(last_error or "The model provider returned no response."))
            self._set_trace(trace_id, fingerprint, started, attempts, "error", {}, str(error))
            raise error

        calls = self._calls(body)
        if not calls:
            self._set_trace(trace_id, fingerprint, started, attempts, "no_action", body)
            return None
        if len(calls) > self.max_tool_calls:
            error = PlannerError("The model exceeded the one-proposal tool-call limit.")
            self._set_trace(trace_id, fingerprint, started, attempts, "rejected", body, str(error))
            raise error
        call = calls[0]
        if call.get("name") != "propose_action":
            error = PlannerError("The model requested a tool that is not allowlisted.")
            self._set_trace(trace_id, fingerprint, started, attempts, "rejected", body, str(error))
            raise error
        try:
            arguments = json.loads(call["arguments"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            error = PlannerError("The model produced malformed proposal arguments.")
            self._set_trace(trace_id, fingerprint, started, attempts, "rejected", body, str(error))
            raise error from exc
        try:
            proposal = self._to_proposal(arguments, intents)
        except PlannerError as exc:
            self._set_trace(trace_id, fingerprint, started, attempts, "rejected", body, str(exc))
            raise
        self._set_trace(
            trace_id,
            fingerprint,
            started,
            attempts,
            "proposal" if proposal is not None else "rejected",
            body,
        )
        return proposal

    def _request(
        self,
        message: str,
        intents: tuple[IntentPassport, ...],
        history: tuple[AgentTurn, ...],
        trace_id: str,
    ) -> tuple[dict[str, Any], str]:
        schema = self._tool_schema(intents)
        if self.provider.api_style == "responses":
            function = schema["function"]
            return (
                {
                    "model": self.model,
                    "input": [
                        {
                            "role": "developer" if item["role"] == "system" else item["role"],
                            "content": item["content"],
                        }
                        for item in self._messages(message, intents, history)
                    ],
                    "tools": [{"type": "function", **function}],
                    "tool_choice": "auto",
                    "parallel_tool_calls": False,
                    "max_output_tokens": 500,
                    "store": False,
                    "metadata": {"trace_id": trace_id, "prompt_version": self.PROMPT_VERSION},
                },
                "/responses",
            )
        return (
            {
                "model": self.model,
                "messages": self._messages(message, intents, history),
                "tools": [schema],
                "tool_choice": "auto",
                "parallel_tool_calls": False,
            },
            "/chat/completions",
        )

    def _calls(self, body: dict[str, Any]) -> list[dict[str, str]]:
        if self.provider.api_style == "responses":
            return [
                {"name": str(item.get("name", "")), "arguments": item.get("arguments", "")}
                for item in body.get("output", [])
                if item.get("type") == "function_call"
            ]
        choices = body.get("choices") or []
        if not choices:
            return []
        calls = (choices[0].get("message") or {}).get("tool_calls") or []
        return [
            {
                "name": str((call.get("function") or {}).get("name", "")),
                "arguments": (call.get("function") or {}).get("arguments", ""),
            }
            for call in calls
        ]

    def _set_trace(
        self,
        trace_id: str,
        fingerprint: str,
        started: float,
        attempts: int,
        status: str,
        body: dict[str, Any],
        error: str | None = None,
    ) -> None:
        usage = body.get("usage") or {}
        input_tokens = int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0)
        output_tokens = int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0)
        total_tokens = int(usage.get("total_tokens", input_tokens + output_tokens) or 0)
        try:
            input_rate = Decimal(os.getenv("INTENTGUARD_LLM_INPUT_COST_PER_MILLION", "0"))
            output_rate = Decimal(os.getenv("INTENTGUARD_LLM_OUTPUT_COST_PER_MILLION", "0"))
        except InvalidOperation:
            input_rate = Decimal("0")
            output_rate = Decimal("0")
        estimated = (Decimal(input_tokens) * input_rate + Decimal(output_tokens) * output_rate) / Decimal(1_000_000)
        self._last_trace = PlannerTrace(
            trace_id=trace_id,
            provider=self.provider.name,
            model=self.model,
            prompt_version=self.PROMPT_VERSION,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            estimated_cost_usd=estimated,
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
            attempts=attempts,
            status=status,
            request_fingerprint=fingerprint,
            error=redact_sensitive(error),
        )

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
        detail = str(redact_sensitive(detail))

        hint = ""
        if response.status_code in (401, 403):
            hint = (
                f" Check the key is a {self.provider.name} key: "
                f"{self.provider.name} keys start with "
                f"'{self.provider.key_prefix}'."
            )
        elif "model" in detail.lower():
            # Providers disagree on the status for an unavailable model: xAI
            # returns 400, Groq returns 404. Key off the message instead.
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
            payload = ProposalPayload.model_validate(arguments)
        except ValidationError as exc:
            raise PlannerError("The model proposal failed structured validation.") from exc

        return ProposedAction(
            intent_id=intent.intent_id,
            action=payload.action or intent.action,
            amount=payload.amount,
            currency=(payload.currency or intent.currency).upper(),
            rationale=payload.rationale.strip(),
            attributes=payload.attributes,
            risk_score=payload.risk_score,
        )


def build_planner(
    *,
    api_key: str | None = None,
    model: str | None = None,
    provider: str | None = None,
) -> Planner:
    """Use a model when a key is configured, otherwise the scripted planner.

    The provider is inferred from OpenAI, xAI, and Groq key prefixes.
    ``INTENTGUARD_LLM_PROVIDER`` overrides the inference.
    """

    key = api_key
    if key is None:
        for variable in (
            "INTENTGUARD_LLM_API_KEY",
            "OPENAI_API_KEY",
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
        timeout=float(os.getenv("INTENTGUARD_LLM_TIMEOUT_SECONDS", "30")),
        max_retries=int(os.getenv("INTENTGUARD_LLM_MAX_RETRIES", "2")),
        max_tool_calls=int(os.getenv("INTENTGUARD_LLM_MAX_TOOL_CALLS", "1")),
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
        self._trace_ids: dict[tuple[str, str], str] = {}

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
        submitted_by: str | None = None,
    ) -> AgentTurn:
        """Handle one customer message end to end."""

        key = (customer_id, agent_id)
        trace_id = self._trace_ids.setdefault(key, uuid4().hex)
        history = tuple(self._history.get(key, ()))
        intents = self.intents_for(
            customer_id=customer_id, agent_id=agent_id, now=now
        )

        set_trace_id = getattr(self.planner, "set_trace_id", None)
        if callable(set_trace_id):
            set_trace_id(trace_id)
        try:
            proposal = self.planner.propose(
                message, intents=intents, history=history
            )
        except PlannerError as exc:
            # Nothing is proposed, so nothing is authorized. Surface the reason
            # instead of crashing the conversation.
            trace = getattr(self.planner, "last_trace", None)
            turn = AgentTurn(
                reply=(
                    "I could not reach the language model, so I have not "
                    f"proposed anything. {exc}"
                ),
                error=str(exc),
                trace=trace,
            )
            self._audit_planner_trace(trace)
            self._history.setdefault(key, []).append(turn)
            return turn

        trace = getattr(self.planner, "last_trace", None)
        if proposal is None:
            turn = AgentTurn(reply=self._no_action_reply(intents), trace=trace)
        else:
            turn = self._authorize(
                proposal,
                customer_id=customer_id,
                agent_id=agent_id,
                now=now,
                submitted_by=submitted_by,
            )
            turn = AgentTurn(
                reply=turn.reply,
                proposal=turn.proposal,
                result=turn.result,
                error=turn.error,
                trace=trace,
            )

        self._audit_planner_trace(trace)

        self._history.setdefault(key, []).append(turn)
        return turn

    def _audit_planner_trace(self, trace: PlannerTrace | None) -> None:
        if trace is None:
            return
        self.engine.audit_ledger.append(
            "llm.proposal.completed",
            {
                "trace_id": trace.trace_id,
                "provider": trace.provider,
                "model": trace.model,
                "prompt_version": trace.prompt_version,
                "input_tokens": trace.input_tokens,
                "output_tokens": trace.output_tokens,
                "total_tokens": trace.total_tokens,
                "estimated_cost_usd": trace.estimated_cost_usd,
                "latency_ms": trace.latency_ms,
                "attempts": trace.attempts,
                "status": trace.status,
                "request_fingerprint": trace.request_fingerprint,
                "error": trace.error,
            },
        )

    def _authorize(
        self,
        proposal: ProposedAction,
        *,
        customer_id: str,
        agent_id: str,
        now: datetime | None,
        submitted_by: str | None,
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
            submitted_by=submitted_by,
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
