"""FastAPI enforcement gateway for IntentGuard."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from fastapi import FastAPI, HTTPException, status
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .models import ActionRequest, AgentProfile, IntentPassport
from .policy_engine import PolicyEngine


DEFAULT_CORS_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
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
        try:
            result = governance_engine().authorize_action(request)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
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
            raise HTTPException(status_code=409, detail=str(exc)) from exc
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

    @app.get("/v1/audit/events", tags=["audit"])
    def audit_events() -> list[dict[str, Any]]:
        return jsonable_encoder(governance_engine().audit_ledger.as_dicts())

    return app


app = create_app()


def run() -> None:
    """Run the development API via the installed console script."""

    import uvicorn

    uvicorn.run("intentguard.api:app", host="127.0.0.1", port=8000, reload=True)
