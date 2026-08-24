"""FastAPI enforcement gateway for IntentGuard."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from time import perf_counter
from typing import Any

from fastapi import FastAPI, HTTPException, status
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .agent import GovernedAgent, build_planner
from .benchmark import api_probe_request, create_api_probe_engine, run_benchmark
from .config import load_env_file
from .models import ActionRequest, AgentProfile, IntentPassport
from .policy_engine import PolicyEngine


DEFAULT_CORS_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
)


def configured_cors_origins() -> tuple[str, ...]:
    """Read a comma-separated origin allowlist, falling back to local UIs."""

    configured = os.getenv("INTENTGUARD_CORS_ORIGINS")
    if configured is None:
        return DEFAULT_CORS_ORIGINS
    return tuple(origin.strip() for origin in configured.split(",") if origin.strip())


class AgentCreate(BaseModel):
    agent_id: str
    name: str
    allowed_actions: set[str]
    max_action_amount: Decimal = Field(ge=0)
    daily_budget: Decimal = Field(ge=0)
    active: bool = True


class IntentCreate(BaseModel):
    intent_id: str
    customer_id: str
    agent_id: str
    action: str
    max_amount: Decimal = Field(ge=0)
    currency: str = Field(min_length=3, max_length=3)
    expires_at: datetime
    required_attributes: dict[str, Any] = Field(default_factory=dict)


class AgentPolicyUpdate(BaseModel):
    allowed_actions: set[str] = Field(min_length=1)
    max_action_amount: Decimal = Field(ge=0)
    daily_budget: Decimal = Field(ge=0)
    active: bool = True
    operator: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=500)


class ActionAuthorize(BaseModel):
    request_id: str
    agent_id: str
    action: str
    amount: Decimal = Field(gt=0)
    currency: str = Field(min_length=3, max_length=3)
    intent_id: str
    risk_score: int = Field(ge=0, le=100)
    attributes: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime | None = None


class ReservationCommit(BaseModel):
    lease_id: str


class ReservationRelease(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


class FleetStop(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


class ApprovalResolution(BaseModel):
    reviewer: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=500)


class BenchmarkProbe(BaseModel):
    request_id: str = Field(min_length=1, max_length=128)


class AgentMessage(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    agent_id: str = Field(min_length=1, max_length=100)
    # TODO(auth): this must come from a verified Firebase ID token, not the
    # request body. Until it does, a caller can claim to be any customer, which
    # is the "self-asserted customer identity" entry in docs/threat-model.md.
    customer_id: str = Field(min_length=1, max_length=100)


def seed_demo_engine(engine: PolicyEngine) -> None:
    """Populate a deterministic three-agent sandbox for the operator console."""

    agents = (
        AgentProfile(
            agent_id="agt_travel_01",
            name="Atlas",
            allowed_actions=frozenset({"book_flight", "book_hotel"}),
            max_action_amount=Decimal("50000"),
            daily_budget=Decimal("100000"),
        ),
        AgentProfile(
            agent_id="agt_service_02",
            name="Nova",
            allowed_actions=frozenset(
                {"issue_service_credit", "replace_card", "reverse_annual_fee"}
            ),
            max_action_amount=Decimal("70000"),
            daily_budget=Decimal("75000"),
        ),
        AgentProfile(
            agent_id="agt_benefits_03",
            name="Orbit",
            allowed_actions=frozenset(
                {"activate_benefit", "submit_benefit_claim"}
            ),
            max_action_amount=Decimal("40000"),
            daily_budget=Decimal("50000"),
        ),
    )
    for agent in agents:
        engine.register_agent(agent)

    expires_at = datetime.now(timezone.utc) + timedelta(days=1)
    intents = (
        IntentPassport(
            intent_id="intent_seed_atlas",
            customer_id="demo-customer",
            agent_id="agt_travel_01",
            action="book_hotel",
            max_amount=Decimal("50000"),
            currency="INR",
            expires_at=expires_at,
        ),
        IntentPassport(
            intent_id="intent_seed_nova",
            customer_id="demo-customer",
            agent_id="agt_service_02",
            action="issue_service_credit",
            max_amount=Decimal("70000"),
            currency="INR",
            expires_at=expires_at,
        ),
        IntentPassport(
            intent_id="intent_seed_orbit",
            customer_id="demo-customer",
            agent_id="agt_benefits_03",
            action="submit_benefit_claim",
            max_amount=Decimal("40000"),
            currency="INR",
            expires_at=expires_at,
        ),
        IntentPassport(
            intent_id="intent_travel_booking",
            customer_id="demo-customer",
            agent_id="agt_travel_01",
            action="book_hotel",
            max_amount=Decimal("18000"),
            currency="INR",
            expires_at=expires_at,
            required_attributes={"city": "BOM", "refundable": True},
        ),
        IntentPassport(
            intent_id="intent_service_credit",
            customer_id="demo-customer",
            agent_id="agt_service_02",
            action="issue_service_credit",
            max_amount=Decimal("25000"),
            currency="INR",
            expires_at=expires_at,
        ),
        IntentPassport(
            intent_id="intent_external_payment",
            customer_id="demo-customer",
            agent_id="agt_benefits_03",
            action="pay_external_merchant",
            max_amount=Decimal("35000"),
            currency="INR",
            expires_at=expires_at,
        ),
        IntentPassport(
            intent_id="intent_fee_reversal",
            customer_id="demo-customer",
            agent_id="agt_service_02",
            action="reverse_annual_fee",
            max_amount=Decimal("10000"),
            currency="INR",
            expires_at=expires_at,
        ),
    )
    for intent in intents:
        engine.register_intent(intent)

    seed_actions = (
        ActionRequest(
            request_id="seed_atlas_spend",
            agent_id="agt_travel_01",
            action="book_hotel",
            amount=Decimal("48320"),
            currency="INR",
            intent_id="intent_seed_atlas",
            risk_score=10,
        ),
        ActionRequest(
            request_id="seed_nova_spend",
            agent_id="agt_service_02",
            action="issue_service_credit",
            amount=Decimal("69200"),
            currency="INR",
            intent_id="intent_seed_nova",
            risk_score=10,
        ),
        ActionRequest(
            request_id="seed_orbit_spend",
            agent_id="agt_benefits_03",
            action="submit_benefit_claim",
            amount=Decimal("18600"),
            currency="INR",
            intent_id="intent_seed_orbit",
            risk_score=10,
        ),
    )
    for action in seed_actions:
        decision = engine.evaluate(action)
        engine.record_execution(action, decision)


def create_app(
    engine: PolicyEngine | None = None,
    *,
    allowed_origins: tuple[str, ...] | list[str] | None = None,
) -> FastAPI:
    """Create an application with an injectable engine for tests and deployment."""

    app = FastAPI(
        title="IntentGuard Governance Gateway",
        version="0.2.0",
        description=(
            "Runtime authorization, budget reservation, revocation, and audit "
            "APIs for autonomous financial agents."
        ),
    )
    cors_origins = (
        tuple(allowed_origins)
        if allowed_origins is not None
        else configured_cors_origins()
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.engine = engine or PolicyEngine()
    app.state.benchmark_probe_engine = create_api_probe_engine()
    app.state.demo_bootstrapped = False
    app.state.agent = GovernedAgent(app.state.engine, planner=build_planner())

    def governance_engine() -> PolicyEngine:
        return app.state.engine

    @app.get("/health", tags=["operations"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/fleet/status", tags=["fleet"])
    def fleet_status() -> dict[str, Any]:
        current = governance_engine()
        return {
            "stopped": current.fleet_stopped,
            "fleet_epoch": current.fleet_epoch,
        }

    @app.get("/v1/agents", tags=["agents"])
    def list_agents() -> list[dict[str, Any]]:
        return jsonable_encoder(governance_engine().list_agent_states())

    @app.post(
        "/v1/agents",
        status_code=status.HTTP_201_CREATED,
        tags=["agents"],
    )
    def register_agent(payload: AgentCreate) -> dict[str, Any]:
        agent = AgentProfile(
            agent_id=payload.agent_id,
            name=payload.name,
            allowed_actions=frozenset(payload.allowed_actions),
            max_action_amount=payload.max_action_amount,
            daily_budget=payload.daily_budget,
            active=payload.active,
        )
        governance_engine().register_agent(agent)
        return jsonable_encoder(agent)

    @app.put("/v1/agents/{agent_id}/policy", tags=["agents", "policies"])
    def update_agent_policy(
        agent_id: str, payload: AgentPolicyUpdate
    ) -> dict[str, Any]:
        try:
            governance_engine().update_agent_policy(
                agent_id,
                allowed_actions=frozenset(payload.allowed_actions),
                max_action_amount=payload.max_action_amount,
                daily_budget=payload.daily_budget,
                active=payload.active,
                operator=payload.operator,
                reason=payload.reason,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        state = next(
            item
            for item in governance_engine().list_agent_states()
            if item["agent_id"] == agent_id
        )
        return jsonable_encoder(
            {
                "agent": state,
                "policy_version": governance_engine().policy_version,
            }
        )

    @app.post(
        "/v1/intents",
        status_code=status.HTTP_201_CREATED,
        tags=["intents"],
    )
    def register_intent(payload: IntentCreate) -> dict[str, Any]:
        expires_at = payload.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        intent = IntentPassport(
            intent_id=payload.intent_id,
            customer_id=payload.customer_id,
            agent_id=payload.agent_id,
            action=payload.action,
            max_amount=payload.max_amount,
            currency=payload.currency.upper(),
            expires_at=expires_at,
            required_attributes=payload.required_attributes,
        )
        governance_engine().register_intent(intent)
        return jsonable_encoder(intent)

    @app.post("/v1/actions/authorize", tags=["enforcement"])
    def authorize_action(payload: ActionAuthorize) -> dict[str, Any]:
        occurred_at = payload.occurred_at or datetime.now(timezone.utc)
        if occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(tzinfo=timezone.utc)
        request = ActionRequest(
            request_id=payload.request_id,
            agent_id=payload.agent_id,
            action=payload.action,
            amount=payload.amount,
            currency=payload.currency.upper(),
            intent_id=payload.intent_id,
            risk_score=payload.risk_score,
            attributes=payload.attributes,
            occurred_at=occurred_at,
        )
        started_at = perf_counter()
        try:
            result = governance_engine().authorize_action(request)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        latency_ms = round((perf_counter() - started_at) * 1000, 3)
        governance_engine().audit_ledger.append(
            "gateway.authorization.completed",
            {
                "request_id": request.request_id,
                "agent_id": request.agent_id,
                "action": request.action,
                "amount": request.amount,
                "currency": request.currency,
                "decision": result.decision.decision.value,
                "finding_codes": [
                    finding.code for finding in result.decision.findings
                ],
                "latency_ms": latency_ms,
            },
        )
        return jsonable_encoder(result)

    @app.post(
        "/v1/reservations/{reservation_id}/commit",
        tags=["enforcement"],
    )
    def commit_reservation(
        reservation_id: str, payload: ReservationCommit
    ) -> dict[str, Any]:
        try:
            reservation = governance_engine().commit_reservation(
                reservation_id,
                lease_id=payload.lease_id,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            reservation = governance_engine().get_reservation(reservation_id)
            governance_engine().audit_ledger.append(
                "connector.execution.rejected",
                {
                    "reservation_id": reservation_id,
                    "request_id": (
                        reservation.request_id if reservation is not None else None
                    ),
                    "agent_id": (
                        reservation.agent_id if reservation is not None else None
                    ),
                    "reason": str(exc),
                },
            )
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        governance_engine().audit_ledger.append(
            "connector.execution.succeeded",
            {
                "reservation_id": reservation.reservation_id,
                "request_id": reservation.request_id,
                "agent_id": reservation.agent_id,
                "amount": reservation.amount,
                "currency": reservation.currency,
            },
        )
        return jsonable_encoder(reservation)

    @app.post(
        "/v1/reservations/{reservation_id}/release",
        tags=["enforcement"],
    )
    def release_reservation(
        reservation_id: str, payload: ReservationRelease
    ) -> dict[str, Any]:
        try:
            reservation = governance_engine().release_reservation(
                reservation_id,
                reason=payload.reason,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return jsonable_encoder(reservation)

    @app.post(
        "/v1/agents/{agent_id}/revoke",
        status_code=status.HTTP_204_NO_CONTENT,
        tags=["agents"],
    )
    def revoke_agent(agent_id: str) -> None:
        governance_engine().revoke_agent(agent_id)

    @app.post(
        "/v1/agents/{agent_id}/restore",
        status_code=status.HTTP_204_NO_CONTENT,
        tags=["agents"],
    )
    def restore_agent(agent_id: str) -> None:
        try:
            governance_engine().restore_agent(agent_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post(
        "/v1/fleet/stop",
        status_code=status.HTTP_204_NO_CONTENT,
        tags=["fleet"],
    )
    def stop_fleet(payload: FleetStop) -> None:
        governance_engine().stop_fleet(reason=payload.reason)

    @app.post(
        "/v1/fleet/resume",
        status_code=status.HTTP_204_NO_CONTENT,
        tags=["fleet"],
    )
    def resume_fleet() -> None:
        governance_engine().resume_fleet()

    @app.get("/v1/approvals", tags=["approvals"])
    def list_approvals() -> list[dict[str, Any]]:
        return jsonable_encoder(governance_engine().list_approvals())

    @app.post(
        "/v1/approvals/{request_id}/approve",
        tags=["approvals"],
    )
    def approve_action(
        request_id: str, payload: ApprovalResolution
    ) -> dict[str, Any]:
        try:
            result = governance_engine().approve_action(
                request_id,
                reviewer=payload.reviewer,
                reason=payload.reason,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return jsonable_encoder(result)

    @app.post(
        "/v1/approvals/{request_id}/reject",
        tags=["approvals"],
    )
    def reject_action(
        request_id: str, payload: ApprovalResolution
    ) -> dict[str, Any]:
        try:
            approval = governance_engine().reject_action(
                request_id,
                reviewer=payload.reviewer,
                reason=payload.reason,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return jsonable_encoder(approval)

    @app.get("/v1/audit/events", tags=["audit"])
    def audit_events() -> list[dict[str, Any]]:
        return jsonable_encoder(governance_engine().audit_ledger.as_dicts())

    @app.get("/v1/audit/status", tags=["audit"])
    def audit_status() -> dict[str, Any]:
        ledger = governance_engine().audit_ledger
        events = ledger.events
        checkpoint = ledger.checkpoint
        return {
            "verified": ledger.verify(),
            "event_count": len(events),
            "head_hash": events[-1].event_hash if events else ledger.GENESIS_HASH,
            # Held outside the chain so truncation of the newest events, which
            # the chain alone cannot see, is detectable.
            "expected_event_count": checkpoint.event_count,
            "expected_head_hash": checkpoint.head_hash,
            "first_invalid_link": ledger.first_invalid_link(),
        }

    @app.get("/v1/agent/intents", tags=["agent"])
    def agent_intents(customer_id: str, agent_id: str) -> list[dict[str, Any]]:
        """The authorizations this customer has granted this agent."""

        return jsonable_encoder(
            governance_engine().list_intents(
                customer_id=customer_id, agent_id=agent_id
            )
        )

    @app.post("/v1/agent/message", tags=["agent"])
    def agent_message(payload: AgentMessage) -> dict[str, Any]:
        """Send one customer message to the governed agent.

        The agent proposes; the policy engine decides. Identity is taken from
        the request rather than from anything the model returns.
        """

        conversation: GovernedAgent = app.state.agent
        turn = conversation.send(
            payload.message,
            customer_id=payload.customer_id,
            agent_id=payload.agent_id,
        )
        return jsonable_encoder(
            {
                "reply": turn.reply,
                "planner": conversation.planner.name,
                "decision": (
                    turn.decision.value if turn.decision is not None else None
                ),
                "blocked_reasons": list(turn.blocked_reasons),
                "proposal": turn.proposal,
                "authorization": turn.result,
            }
        )

    @app.post("/v1/demo/bootstrap", tags=["demo"])
    def bootstrap_demo() -> dict[str, Any]:
        if not app.state.demo_bootstrapped:
            seed_demo_engine(governance_engine())
            app.state.demo_bootstrapped = True
        return {
            "agents": jsonable_encoder(governance_engine().list_agent_states()),
            "fleet": {
                "stopped": governance_engine().fleet_stopped,
                "fleet_epoch": governance_engine().fleet_epoch,
            },
            "approvals": jsonable_encoder(governance_engine().list_approvals()),
            "audit_verified": governance_engine().audit_ledger.verify(),
        }

    @app.post("/v1/demo/reset", tags=["demo"])
    def reset_demo() -> dict[str, Any]:
        app.state.engine = PolicyEngine()
        app.state.demo_bootstrapped = False
        app.state.agent = GovernedAgent(
            app.state.engine, planner=build_planner()
        )
        return bootstrap_demo()

    @app.get("/v1/demo/benchmark", tags=["demo", "operations"])
    def demo_benchmark() -> dict[str, Any]:
        return jsonable_encoder(run_benchmark())

    @app.post(
        "/v1/demo/benchmark/authorize-probe",
        tags=["demo", "operations"],
    )
    def demo_authorization_probe(payload: BenchmarkProbe) -> dict[str, Any]:
        """Exercise the full FastAPI authorization path using isolated state."""

        started_at = perf_counter()
        result = app.state.benchmark_probe_engine.authorize_action(
            api_probe_request(payload.request_id)
        )
        server_processing_ms = round((perf_counter() - started_at) * 1000, 4)
        return {
            "decision": result.decision.decision.value,
            "server_processing_ms": server_processing_ms,
        }

    return app


app = create_app()


def run() -> None:
    """Run the development API via the installed console script."""

    import uvicorn

    # Entry points opt into .env; importing the library never touches the disk.
    loaded = load_env_file()
    if loaded:
        print(f"Loaded {', '.join(sorted(loaded))} from .env")

    uvicorn.run("intentguard.api:app", host="127.0.0.1", port=8000, reload=True)
