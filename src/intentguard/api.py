"""FastAPI enforcement gateway for IntentGuard."""

from __future__ import annotations

import base64
from binascii import Error as BinasciiError
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from threading import Lock
from time import perf_counter
from typing import Any, Callable

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from .agent import GovernedAgent, build_planner
from .abuse import (
    AbuseLimits,
    RateLimiter,
    RateLimiterUnavailable,
    RedisSlidingWindowRateLimiter,
    RequestBodyLimitMiddleware,
    SlidingWindowRateLimiter,
)
from .auth import (
    AuthenticationError,
    AuthorizationError,
    JwksAuthenticator,
    Principal,
)
from .benchmark import api_probe_request, create_api_probe_engine, run_benchmark
from .audit import AuditRetentionPolicy, PostgresAuditLedger
from .budget import PostgresBudgetLedger
from .config import load_env_file
from .intent import (
    InMemoryIntentKeyRegistry,
    InMemoryNonceStore,
    IntentReplayError,
    IntentSigningKey,
    IntentVerificationError,
    IntentVerifier,
    PostgresIntentKeyRegistry,
    PostgresNonceStore,
    validate_public_key,
)
from .execution_lease import (
    ExecutionLeaseSigner,
    InMemoryLeaseKeyRegistry,
    PostgresLeaseKeyRegistry,
    decode_lease_private_key,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .evidence import (
    EvidenceValidationError,
    InMemoryEvidenceStore,
    may_read as may_read_evidence,
)
from .models import (
    ActionRequest,
    AgentProfile,
    ClaimReason,
    EvidenceArtifact,
    EvidenceKind,
    IntentPassport,
    RefundClaim,
)
from .observability import install_observability, observation_fields, operation_span
from .policy_engine import PolicyEngine
from .persistence import PostgresStateRepository
from .policy import (
    InMemoryPolicyRepository,
    OpaCliPolicyEvaluator,
    PolicyEvaluationError,
    PolicyService,
    PostgresPolicyRepository,
    find_opa_executable,
    initial_policy,
)
from .tenancy import (
    DEFAULT_ORG_ID,
    ApiKeyError,
    PostgresTenancyStore,
    TenancyStore,
    looks_like_api_key,
)


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


POLICY_ENGINE_MODES = ("auto", "opa", "builtin")


class PolicyEngineMisconfigured(RuntimeError):
    """The requested policy engine cannot be provided as asked."""


def resolve_policy_engine(
    opa_executable: str | None, *, database_url: str | None
) -> str | None:
    """Decide which evaluator to run, and refuse to downgrade by accident.

    The built-in evaluator is not equivalent to Rego and is not meant to be:
    once policies are customer-editable Rego, no Python reimplementation can
    be. What it must never be is *more permissive*, and until this function
    existed the choice between them was made by a path lookup. A missing
    binary silently swapped the strict evaluator for the loose one, in the
    environment least likely to notice.

    ``INTENTGUARD_POLICY_ENGINE``:

    * ``opa`` -- require Rego. Refuse to start without it.
    * ``builtin`` -- run the built-in evaluator, deliberately.
    * ``auto`` (default) -- prefer Rego; fall back only where a fallback is
      obviously safe. A configured database means this is not a scratch demo,
      so ``auto`` refuses rather than downgrading. Say ``builtin`` to accept.
    """

    setting = os.getenv("INTENTGUARD_POLICY_ENGINE", "auto").strip().lower()
    if setting not in POLICY_ENGINE_MODES:
        raise PolicyEngineMisconfigured(
            f"INTENTGUARD_POLICY_ENGINE={setting!r} is not one of "
            f"{', '.join(POLICY_ENGINE_MODES)}."
        )
    if setting == "builtin":
        return None
    if setting == "opa":
        if not opa_executable:
            raise PolicyEngineMisconfigured(
                "INTENTGUARD_POLICY_ENGINE=opa, but no OPA binary was found. "
                "Install it with scripts/install-opa.sh, put it on PATH, or "
                "point INTENTGUARD_OPA_EXECUTABLE at it."
            )
        return opa_executable
    if opa_executable:
        return opa_executable
    if database_url:
        raise PolicyEngineMisconfigured(
            "No OPA binary was found, but INTENTGUARD_DATABASE_URL is set, so "
            "this looks like a deployment rather than a demo. The built-in "
            "evaluator is not equivalent to the Rego policy and must not be "
            "substituted silently. Install OPA, or set "
            "INTENTGUARD_POLICY_ENGINE=builtin to accept it deliberately."
        )
    return None


def configured_engine(limits: AbuseLimits | None = None) -> PolicyEngine:
    """Use PostgreSQL for every durable backend when a database URL is set."""

    database_url = os.getenv("INTENTGUARD_DATABASE_URL")
    resolved_limits = limits or AbuseLimits.from_env()
    audience = os.getenv("INTENTGUARD_INTENT_AUDIENCE", "intentguard-api")
    configured_issuers = os.getenv("INTENTGUARD_INTENT_ISSUERS")
    allowed_issuers = (
        frozenset(
            item.strip()
            for item in configured_issuers.split(",")
            if item.strip()
        )
        if configured_issuers
        else None
    )
    encoded_lease_key = os.getenv("INTENTGUARD_LEASE_PRIVATE_KEY")
    lease_private_key = (
        decode_lease_private_key(encoded_lease_key)
        if encoded_lease_key
        else Ed25519PrivateKey.generate()
    )
    lease_issuer = os.getenv("INTENTGUARD_LEASE_ISSUER", "intentguard-gateway")
    lease_audience = os.getenv(
        "INTENTGUARD_LEASE_AUDIENCE", "intentguard-booking-connector"
    )
    opa_executable = resolve_policy_engine(
        find_opa_executable(), database_url=database_url
    )
    policy_evaluator = None
    if opa_executable:
        policy_repository = (
            PostgresPolicyRepository(database_url)
            if database_url
            else InMemoryPolicyRepository(initial_policy())
        )
        if policy_repository.active() is None:
            policy_repository.save(initial_policy())
        policy_evaluator = OpaCliPolicyEvaluator(
            opa_executable, policy_repository
        )
    if not database_url:
        lease_registry = InMemoryLeaseKeyRegistry()
        return PolicyEngine(
            intent_verifier=IntentVerifier(
                audience=audience,
                key_registry=InMemoryIntentKeyRegistry(),
                nonce_store=InMemoryNonceStore(),
                allowed_issuers=allowed_issuers,
            ),
            lease_signer=ExecutionLeaseSigner(
                lease_private_key,
                issuer=lease_issuer,
                audience=lease_audience,
                key_registry=lease_registry,
            ),
            policy_evaluator=policy_evaluator,
            max_outstanding_reservations=resolved_limits.max_outstanding_reservations,
            max_pending_approvals=resolved_limits.max_pending_approvals,
        )
    lease_registry = PostgresLeaseKeyRegistry(database_url)
    return PolicyEngine(
        budget_ledger=PostgresBudgetLedger(database_url),
        state_repository=PostgresStateRepository(database_url),
        audit_ledger=PostgresAuditLedger(database_url),
        intent_verifier=IntentVerifier(
            audience=audience,
            key_registry=PostgresIntentKeyRegistry(database_url),
            nonce_store=PostgresNonceStore(database_url),
            allowed_issuers=allowed_issuers,
        ),
        lease_signer=ExecutionLeaseSigner(
            lease_private_key,
            issuer=lease_issuer,
            audience=lease_audience,
            key_registry=lease_registry,
        ),
        policy_evaluator=policy_evaluator,
        max_outstanding_reservations=resolved_limits.max_outstanding_reservations,
        max_pending_approvals=resolved_limits.max_pending_approvals,
    )


def configured_tenancy_store() -> TenancyStore | None:
    """Share the database the rest of the gateway already uses, or run untenanted.

    No database means no organisations to tell apart, so a principal is the
    default organisation and every caller authenticates with a token, exactly
    as before. This is the local demo and the test suite.

    A database means organisations are real, and membership becomes required:
    see ``resolve_org`` for why an unmapped subject is refused rather than
    defaulted.
    """

    database_url = os.getenv("INTENTGUARD_DATABASE_URL")
    return PostgresTenancyStore(database_url) if database_url else None


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
    issuer: str = ""
    audience: str = ""
    issued_at: datetime | None = None
    not_before: datetime | None = None
    nonce: str = ""
    key_id: str = ""
    signature: str = ""


class IntentKeyCreate(BaseModel):
    key_id: str = Field(min_length=1, max_length=128)
    issuer: str = Field(min_length=1, max_length=500)
    public_key: str = Field(min_length=40, max_length=100)
    valid_from: datetime | None = None
    expires_at: datetime | None = None


class IntentKeyRevoke(BaseModel):
    issuer: str = Field(min_length=1, max_length=500)


class AgentPolicyUpdate(BaseModel):
    allowed_actions: set[str] = Field(min_length=1)
    max_action_amount: Decimal = Field(ge=0)
    daily_budget: Decimal = Field(ge=0)
    active: bool = True
    reason: str = Field(min_length=1, max_length=500)


class EvidenceUpload(BaseModel):
    """An evidence image, base64 encoded. See upload_evidence for why."""

    model_config = ConfigDict(extra="forbid")

    kind: EvidenceKind
    #: Base64 of the raw bytes. The cap is generous for the 5 MiB limit the
    #: store enforces on the decoded content, and exists so an oversized body
    #: is rejected before it is decoded rather than after.
    content_base64: str = Field(min_length=4, max_length=8 * 1024 * 1024)


class EvidenceArtifactPayload(BaseModel):
    """A citation, not an upload. The gateway never fetches the reference."""

    model_config = ConfigDict(extra="forbid")

    kind: EvidenceKind
    reference: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:/-]+$"
    )


class ClaimPayload(BaseModel):
    """The complaint behind a proposed action, as the agent describes it.

    Closed enums rather than free text: a reason that reached policy as an
    arbitrary string would be attacker-controlled input steering a decision,
    and `extra="forbid"` means a misspelled field is a 422 rather than a
    silently ignored constraint.
    """

    model_config = ConfigDict(extra="forbid")

    reason: ClaimReason
    order_value: Decimal = Field(gt=0)
    days_since_delivery: int = Field(ge=0, le=3650)
    #: The merchant's order or transaction id. Constrained rather than free
    #: text: it is shown to an operator and written to the audit trail, and
    #: an identifier has no business containing markup or newlines.
    order_reference: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$"
    )
    #: Evidence is *derived* from these, never accepted directly. A claim
    #: cannot assert that a photo exists without naming a reference that an
    #: investigator could take back to the order system and check.
    artifacts: list[EvidenceArtifactPayload] = Field(
        default_factory=list, max_length=16
    )
    #: The customer's words. Capped, and quarantined everywhere downstream --
    #: see RefundClaim.complaint.
    complaint: str | None = Field(default=None, max_length=2000)

    @property
    def derived_evidence(self) -> frozenset[str]:
        return frozenset(artifact.kind.value for artifact in self.artifacts)


class ActionAuthorize(BaseModel):
    request_id: str
    agent_id: str
    action: str
    amount: Decimal = Field(gt=0)
    currency: str = Field(min_length=3, max_length=3)
    intent_id: str
    risk_score: int = Field(ge=0, le=100)
    attributes: dict[str, Any] = Field(default_factory=dict)
    customer_id: str | None = Field(default=None, min_length=1, max_length=100)
    occurred_at: datetime | None = None
    claim: ClaimPayload | None = None


class ReservationCommit(BaseModel):
    lease_id: str


class ReservationRelease(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


class FleetStop(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


class ApprovalResolution(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


class BenchmarkProbe(BaseModel):
    request_id: str = Field(min_length=1, max_length=128)


class AgentMessage(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    agent_id: str = Field(min_length=1, max_length=100)
    customer_id: str = Field(min_length=1, max_length=100)


class PolicySource(BaseModel):
    source: str = Field(min_length=20)


class PolicyDraftCreate(PolicySource):
    description: str = Field(min_length=1, max_length=500)


class PolicyDryRun(PolicySource):
    input: dict[str, Any]


class PolicyCompare(BaseModel):
    left_version: str
    right_version: str
    cases: list[dict[str, Any]] = Field(min_length=1, max_length=100)


def seed_demo_engine(engine: PolicyEngine) -> None:
    """Populate a deterministic refund sandbox for the operator console.

    The story the console tells: a company runs AI support agents that can
    issue refunds. Ada handles routine tickets, Bo handles escalations, and
    Cy adjusts billing but is not allowed to move money at all. Every limit
    below is the kind a support lead would actually set.
    """

    agents = (
        AgentProfile(
            agent_id="agt_refund_01",
            name="Ada",
            allowed_actions=frozenset({"refund_order", "issue_goodwill_credit"}),
            # Tier-one refunds: small, frequent, no human in the loop.
            max_action_amount=Decimal("500"),
            daily_budget=Decimal("20000"),
        ),
        AgentProfile(
            agent_id="agt_refund_02",
            name="Bo",
            allowed_actions=frozenset(
                {"refund_order", "issue_goodwill_credit", "refund_shipping"}
            ),
            # Escalations: larger single refunds, still capped for the day.
            max_action_amount=Decimal("5000"),
            daily_budget=Decimal("50000"),
        ),
        AgentProfile(
            agent_id="agt_billing_03",
            name="Cy",
            # Deliberately cannot refund. Cy exists to show that "what an agent
            # may do" is enforced, not merely documented in a prompt.
            allowed_actions=frozenset({"cancel_subscription", "apply_discount"}),
            max_action_amount=Decimal("2500"),
            daily_budget=Decimal("15000"),
        ),
    )
    for agent in agents:
        engine.register_agent(agent)

    expires_at = datetime.now(timezone.utc) + timedelta(days=1)
    intents = (
        IntentPassport(
            intent_id="intent_refund_routine",
            customer_id="demo-customer",
            agent_id="agt_refund_01",
            action="refund_order",
            max_amount=Decimal("500"),
            currency="INR",
            expires_at=expires_at,
        ),
        IntentPassport(
            intent_id="intent_refund_escalated",
            customer_id="demo-customer",
            agent_id="agt_refund_02",
            action="refund_order",
            max_amount=Decimal("5000"),
            currency="INR",
            expires_at=expires_at,
        ),
        IntentPassport(
            intent_id="intent_goodwill_credit",
            customer_id="demo-customer",
            agent_id="agt_refund_02",
            action="issue_goodwill_credit",
            max_amount=Decimal("5000"),
            currency="INR",
            expires_at=expires_at,
        ),
        IntentPassport(
            intent_id="intent_billing_change",
            customer_id="demo-customer",
            agent_id="agt_billing_03",
            action="cancel_subscription",
            max_amount=Decimal("2500"),
            currency="INR",
            expires_at=expires_at,
        ),
    )
    for intent in intents:
        engine.register_intent(intent, verify=False)

    # A little committed spend, so the console does not open on empty charts.
    seed_actions = (
        ActionRequest(
            request_id="seed_refund_ada",
            agent_id="agt_refund_01",
            action="refund_order",
            amount=Decimal("240"),
            currency="INR",
            intent_id="intent_refund_routine",
            risk_score=8,
        ),
        ActionRequest(
            request_id="seed_refund_bo",
            agent_id="agt_refund_02",
            action="refund_order",
            amount=Decimal("1800"),
            currency="INR",
            intent_id="intent_refund_escalated",
            risk_score=12,
        ),
        ActionRequest(
            request_id="seed_billing_cy",
            agent_id="agt_billing_03",
            action="cancel_subscription",
            amount=Decimal("600"),
            currency="INR",
            intent_id="intent_billing_change",
            risk_score=10,
        ),
    )
    for action in seed_actions:
        authorization = engine.authorize_action(action)
        if authorization.decision.decision.value == "review":
            authorization = engine.approve_action(
                action.request_id,
                reviewer="demo-bootstrap-reviewer",
                reason="Approved deterministic dashboard seed exposure",
            )
        if authorization.reservation is not None and authorization.lease is not None:
            engine.commit_reservation(
                authorization.reservation.reservation_id,
                lease_id=authorization.lease.lease_id,
            )


def create_app(
    engine: PolicyEngine | None = None,
    *,
    allowed_origins: tuple[str, ...] | list[str] | None = None,
    authenticator: JwksAuthenticator | None = None,
    abuse_limits: AbuseLimits | None = None,
    rate_limiter: RateLimiter | None = None,
    tenancy: TenancyStore | None = None,
) -> FastAPI:
    """Create an application with an injectable engine for tests and deployment."""

    limits = abuse_limits or AbuseLimits.from_env()
    redis_url = os.getenv("INTENTGUARD_REDIS_URL")
    limiter = rate_limiter or (
        RedisSlidingWindowRateLimiter.from_url(redis_url)
        if redis_url
        else SlidingWindowRateLimiter()
    )
    retention = AuditRetentionPolicy.from_env()
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
    app.add_middleware(
        RequestBodyLimitMiddleware,
        max_bytes=limits.max_request_body_bytes,
    )
    metrics = install_observability(
        app, service_name="intentguard-governance-gateway"
    )
    app.state.engine = engine or configured_engine(limits)
    app.state.abuse_limits = limits
    app.state.rate_limiter = limiter
    app.state.audit_retention = retention

    def oldest_approval_age() -> float:
        pending = [
            item
            for item in app.state.engine.list_approvals()
            if item.status.value == "pending"
        ]
        if not pending:
            return 0.0
        return max(
            0.0,
            (
                datetime.now(timezone.utc)
                - min(item.created_at for item in pending)
            ).total_seconds(),
        )

    metrics.approval_queue_age.set_function(oldest_approval_age)
    app.router.add_event_handler("shutdown", app.state.engine.close)
    close_limiter = getattr(limiter, "close", None)
    if callable(close_limiter):
        app.router.add_event_handler("shutdown", close_limiter)
    app.state.benchmark_probe_engine = create_api_probe_engine()
    app.state.demo_bootstrapped = False
    app.state.agent = GovernedAgent(app.state.engine, planner=build_planner())
    app.state.authenticator = authenticator or JwksAuthenticator.from_env()
    app.state.tenancy = tenancy
    # Whether organisations exist at all, which is a different question from
    # whether the store has been built yet. Everything downstream must ask this
    # one: treating "not built yet" as "no organisations" would default a
    # caller into the default organisation while a database sits there holding
    # somebody else's.
    #
    # Tenancy follows the engine, and that is not a convenience. ADR 004
    # enforces tenancy at the repository boundary, and the repositories belong
    # to the engine -- so a caller who injected an engine has taken over the
    # construction this gateway would otherwise scope, and must inject the
    # store alongside it. A deployment injects neither and gets both from the
    # environment, so the production path cannot lose tenancy by accident.
    app.state.tenancy_configured = tenancy is not None or (
        engine is None and bool(os.getenv("INTENTGUARD_DATABASE_URL"))
    )
    app.state.tenancy_lock = Lock()

    def close_tenancy() -> None:
        if app.state.tenancy is not None:
            app.state.tenancy.close()

    app.router.add_event_handler("shutdown", close_tenancy)
    # Process-local and bounded. Evidence exists so an operator can look at it;
    # nothing in policy reads an image and no decision depends on one.
    app.state.evidence_store = InMemoryEvidenceStore()
    app.state.policy_service = (
        PolicyService(app.state.engine.policy_evaluator)
        if isinstance(app.state.engine.policy_evaluator, OpaCliPolicyEvaluator)
        else None
    )
    bearer_scheme = HTTPBearer(auto_error=False)

    @app.get("/health/live", tags=["health"], include_in_schema=False)
    def liveness() -> dict[str, str]:
        """Process-level health check used by containers and load balancers."""

        return {"status": "ok"}

    @app.get("/health/ready", tags=["health"], include_in_schema=False)
    def readiness() -> dict[str, Any]:
        """Confirm the initialized runtime can serve governance requests."""

        engine = governance_engine()
        database_url = os.getenv("INTENTGUARD_DATABASE_URL")
        failures: list[str] = []
        if database_url:
            try:
                import psycopg

                with psycopg.connect(database_url, connect_timeout=2) as connection:
                    connection.execute("SELECT 1")
            except Exception:
                failures.append("database")
        ping_limiter = getattr(limiter, "ping", None)
        if callable(ping_limiter):
            try:
                ping_limiter()
            except RateLimiterUnavailable:
                failures.append("rate_limiter")
        if failures:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"status": "not_ready", "unavailable": failures},
            )
        return {
            "status": "ready",
            "database": "postgres" if database_url else "memory",
            "rate_limiter": "redis" if os.getenv("INTENTGUARD_REDIS_URL") else "memory",
            "policy": "opa" if engine.policy_evaluator is not None else "builtin",
            # The mode that was asked for, beside the engine actually running.
            # These agreeing is the point: "builtin" can no longer happen by
            # accident, only by configuration or on the no-database dev path.
            "policy_engine_mode": os.getenv(
                "INTENTGUARD_POLICY_ENGINE", "auto"
            ).strip().lower(),
        }

    def governance_engine() -> PolicyEngine:
        return app.state.engine

    def tenancy_store() -> TenancyStore | None:
        """Open the store on first use rather than at boot.

        An unreachable database must still let the gateway start and report
        itself unready -- that is what ``/health/ready`` exists for -- instead
        of killing the process on a blip. So the pool is opened by the first
        request that needs it, and a failure to open it is a 503. It is never
        a downgrade to single tenancy: a gateway that quietly forgot its
        organisations would serve one tenant's data to another.
        """

        if not app.state.tenancy_configured:
            return None
        with app.state.tenancy_lock:
            if app.state.tenancy is None:
                try:
                    app.state.tenancy = configured_tenancy_store()
                except Exception as exc:
                    raise HTTPException(
                        status_code=503,
                        detail="The organisation store is unavailable.",
                    ) from exc
            return app.state.tenancy

    def api_key_principal(secret: str) -> Principal:
        """Verify a presented API key. A key carries its own organisation."""

        store = tenancy_store()
        if store is None:
            # Reached only when a credential already looks like a key. Falling
            # through to the JWT verifier would report a malformed token,
            # which sends the caller looking in the wrong place.
            raise ApiKeyError(
                "API key authentication is not configured on this deployment."
            )
        return store.authenticate_key(secret, now=datetime.now(timezone.utc))

    def resolve_org(principal: Principal) -> Principal:
        """Attach the organisation a verified token subject acts for.

        Membership is the authority, not the token. ADR 001 chose Keycloak for
        operator SSO and ADR 004 kept organisation identity in our own
        database, so the identity provider says *who* a caller is and
        ``org_members`` says which organisation they act for and what they may
        do there. A realm role on its own therefore grants nothing here.

        An unmapped subject is refused rather than defaulted. Defaulting is the
        shape this codebase has already paid for twice -- a silent permissive
        fallback nobody revisits -- and here it would hand a stranger another
        tenant's data on the day repositories start scoping by organisation.

        With no store configured there are no organisations to confuse, so the
        principal is the default organisation and nothing changes.
        """

        store = tenancy_store()
        if store is None:
            return replace(principal, org_id=DEFAULT_ORG_ID)
        membership = store.membership(principal.subject)
        if membership is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="The authenticated subject belongs to no organisation.",
            )
        org_id, roles = membership
        return replace(principal, org_id=org_id, roles=roles)

    def authenticated_principal(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ) -> Principal:
        """Resolve either credential kind to the same Principal.

        Handlers cannot tell an operator's token from an agent's key, which is
        the point: authority comes from roles and bound identity, never from
        how the caller authenticated.
        """

        presented = credentials.credentials.strip() if credentials is not None else ""
        try:
            if looks_like_api_key(presented):
                principal = api_key_principal(presented)
            else:
                authorization = (
                    f"{credentials.scheme} {credentials.credentials}"
                    if credentials is not None
                    else None
                )
                principal = resolve_org(
                    app.state.authenticator.authenticate(authorization)
                )
        except AuthenticationError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        observation_fields(
            subject_id=principal.subject,
            agent_id=principal.agent_id,
            customer_id=principal.customer_id,
            org_id=principal.org_id,
        )
        return principal

    def roles(*permitted: str) -> Callable[..., Principal]:
        allowed = frozenset(permitted)
        if allowed == {"agent"}:
            rate_scope = "agent"
        elif allowed == {"customer"}:
            rate_scope = "customer"
        elif allowed == {"connector"}:
            rate_scope = "connector"
        else:
            rate_scope = "operator"

        def dependency(
            request: Request,
            response: Response,
            principal: Principal = Depends(authenticated_principal),
        ) -> Principal:
            try:
                verified = app.state.authenticator.require_roles(principal, allowed)
            except AuthorizationError as exc:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
                ) from exc
            identity = (
                verified.agent_id
                if rate_scope == "agent"
                else verified.customer_id
                if rate_scope == "customer"
                else verified.subject
            ) or verified.subject
            rate_limit = limits.rate_for(rate_scope)
            try:
                rate = limiter.consume(
                    scope=rate_scope,
                    key=identity,
                    limit=rate_limit,
                    window_seconds=limits.window_seconds,
                )
            except RateLimiterUnavailable as exc:
                metrics.abuse_rejections.labels(
                    rate_scope, "limiter_unavailable"
                ).inc()
                raise HTTPException(
                    status_code=503,
                    detail="The distributed rate limiter is unavailable; the request failed closed.",
                    headers={"Retry-After": "1"},
                ) from exc
            response.headers["X-RateLimit-Limit"] = str(rate_limit)
            response.headers["X-RateLimit-Remaining"] = str(rate.remaining)
            if not rate.allowed:
                metrics.abuse_rejections.labels(rate_scope, "rate_limit").inc()
                governance_engine().audit_ledger.append(
                    "abuse.rate_limited",
                    {
                        "scope": rate_scope,
                        "subject": verified.subject,
                        "path": request.url.path,
                        "retry_after_seconds": rate.retry_after_seconds,
                    },
                )
                raise HTTPException(
                    status_code=429,
                    detail="The request rate limit was exceeded.",
                    headers={
                        "Retry-After": str(rate.retry_after_seconds),
                        "X-RateLimit-Limit": str(rate_limit),
                        "X-RateLimit-Remaining": "0",
                    },
                )
            return verified

        return dependency

    customer_principal = roles("customer")
    agent_principal = roles("agent")
    operator_principal = roles("operator")
    reviewer_principal = roles("reviewer")
    operations_reader = roles("operator", "reviewer")
    fleet_reader = roles("operator", "reviewer", "connector")
    connector_principal = roles("connector")
    admin_principal = roles("admin")
    evidence_reader = roles("operator", "reviewer", "agent", "customer", "admin")
    evidence_writer = roles("customer", "admin")

    def policy_service() -> PolicyService:
        service = app.state.policy_service
        if service is None:
            raise HTTPException(
                status_code=503,
                detail="OPA policy-as-code is not configured.",
            )
        return service

    def signed_intent_verifier() -> IntentVerifier:
        verifier = governance_engine().intent_verifier
        if verifier is None:
            raise HTTPException(
                status_code=503,
                detail="Signed intent verification is not configured.",
            )
        return verifier

    def require_claim(principal: Principal, name: str) -> str:
        value = getattr(principal, name)
        if value is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"The token must contain a verified {name} claim.",
            )
        return value

    def require_match(actual: str, expected: str, label: str) -> None:
        if actual != expected:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"The token cannot act as the requested {label}.",
            )

    @app.get("/health", tags=["operations"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/fleet/status", tags=["fleet"])
    def fleet_status(
        principal: Principal = Depends(fleet_reader),
    ) -> dict[str, Any]:
        current = governance_engine()
        return {
            "stopped": current.fleet_stopped,
            "fleet_epoch": current.fleet_epoch,
        }

    @app.get("/v1/agents", tags=["agents"])
    def list_agents(
        principal: Principal = Depends(operations_reader),
    ) -> list[dict[str, Any]]:
        return jsonable_encoder(governance_engine().list_agent_states())

    @app.post(
        "/v1/agents",
        status_code=status.HTTP_201_CREATED,
        tags=["agents"],
    )
    def register_agent(
        payload: AgentCreate,
        principal: Principal = Depends(operator_principal),
    ) -> dict[str, Any]:
        agent = AgentProfile(
            agent_id=payload.agent_id,
            name=payload.name,
            allowed_actions=frozenset(payload.allowed_actions),
            max_action_amount=payload.max_action_amount,
            daily_budget=payload.daily_budget,
            active=payload.active,
        )
        governance_engine().register_agent(agent)
        governance_engine().audit_ledger.append(
            "gateway.agent.registered",
            {"agent_id": agent.agent_id, "operator": principal.subject},
        )
        return jsonable_encoder(agent)

    @app.put("/v1/agents/{agent_id}/policy", tags=["agents", "policies"])
    def update_agent_policy(
        agent_id: str,
        payload: AgentPolicyUpdate,
        principal: Principal = Depends(operator_principal),
    ) -> dict[str, Any]:
        try:
            governance_engine().update_agent_policy(
                agent_id,
                allowed_actions=frozenset(payload.allowed_actions),
                max_action_amount=payload.max_action_amount,
                daily_budget=payload.daily_budget,
                active=payload.active,
                operator=principal.subject,
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

    @app.get("/v1/policies", tags=["policies"])
    def list_policy_versions(
        principal: Principal = Depends(operations_reader),
    ) -> list[dict[str, Any]]:
        return jsonable_encoder(policy_service().repository.list())

    @app.post("/v1/policies/validate", tags=["policies"])
    def validate_policy(
        payload: PolicySource,
        principal: Principal = Depends(operator_principal),
    ) -> dict[str, Any]:
        try:
            return policy_service().evaluator.validate(payload.source)
        except PolicyEvaluationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.post(
        "/v1/policies/drafts",
        status_code=status.HTTP_201_CREATED,
        tags=["policies"],
    )
    def create_policy_draft(
        payload: PolicyDraftCreate,
        principal: Principal = Depends(operator_principal),
    ) -> dict[str, Any]:
        try:
            version = policy_service().create_draft(
                payload.source,
                created_by=principal.subject,
                description=payload.description,
            )
        except PolicyEvaluationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        governance_engine().audit_ledger.append(
            "policy.draft.created",
            {"version_id": version.version_id, "operator": principal.subject},
        )
        return jsonable_encoder(version)

    @app.post("/v1/policies/dry-run", tags=["policies"])
    def dry_run_policy(
        payload: PolicyDryRun,
        principal: Principal = Depends(operator_principal),
    ) -> dict[str, Any]:
        try:
            validation = policy_service().evaluator.validate(payload.source)
        except PolicyEvaluationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        if not validation["valid"]:
            raise HTTPException(status_code=422, detail=validation["errors"])
        try:
            result = policy_service().evaluator.evaluate_source(
                payload.source, payload.input
            )
        except PolicyEvaluationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return jsonable_encoder(result)

    @app.post("/v1/policies/{version_id}/publish", tags=["policies"])
    def publish_policy(
        version_id: str,
        principal: Principal = Depends(operator_principal),
    ) -> dict[str, Any]:
        try:
            version = policy_service().publish(version_id)
        except PolicyEvaluationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        governance_engine().audit_ledger.append(
            "policy.published",
            {"version_id": version.version_id, "operator": principal.subject},
        )
        return jsonable_encoder(version)

    @app.post("/v1/policies/{version_id}/rollback", tags=["policies"])
    def rollback_policy(
        version_id: str,
        principal: Principal = Depends(operator_principal),
    ) -> dict[str, Any]:
        try:
            version = policy_service().rollback(version_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        governance_engine().audit_ledger.append(
            "policy.rolled_back",
            {"version_id": version.version_id, "operator": principal.subject},
        )
        return jsonable_encoder(version)

    @app.post("/v1/policies/compare", tags=["policies"])
    def compare_policy_versions(
        payload: PolicyCompare,
        principal: Principal = Depends(operator_principal),
    ) -> dict[str, Any]:
        try:
            return policy_service().compare(
                payload.left_version, payload.right_version, payload.cases
            )
        except PolicyEvaluationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post(
        "/v1/intents",
        status_code=status.HTTP_201_CREATED,
        tags=["intents"],
    )
    def register_intent(
        payload: IntentCreate,
        principal: Principal = Depends(customer_principal),
    ) -> dict[str, Any]:
        customer_id = require_claim(principal, "customer_id")
        require_match(payload.customer_id, customer_id, "customer")
        expires_at = payload.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        issued_at = payload.issued_at
        if issued_at is not None and issued_at.tzinfo is None:
            issued_at = issued_at.replace(tzinfo=timezone.utc)
        not_before = payload.not_before
        if not_before is not None and not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        intent = IntentPassport(
            intent_id=payload.intent_id,
            customer_id=customer_id,
            agent_id=payload.agent_id,
            action=payload.action,
            max_amount=payload.max_amount,
            currency=payload.currency,
            expires_at=expires_at,
            required_attributes=payload.required_attributes,
            issuer=payload.issuer,
            audience=payload.audience,
            issued_at=issued_at,
            not_before=not_before,
            nonce=payload.nonce,
            key_id=payload.key_id,
            signature=payload.signature,
        )
        try:
            governance_engine().register_intent(
                intent, expected_customer_id=customer_id
            )
        except IntentReplayError as exc:
            governance_engine().audit_ledger.append(
                "intent.registration.rejected",
                {
                    "intent_id": intent.intent_id,
                    "issuer": intent.issuer,
                    "key_id": intent.key_id,
                    "reason": "nonce_replay",
                    "customer_subject": principal.subject,
                },
            )
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except IntentVerificationError as exc:
            governance_engine().audit_ledger.append(
                "intent.registration.rejected",
                {
                    "intent_id": intent.intent_id,
                    "issuer": intent.issuer,
                    "key_id": intent.key_id,
                    "reason": str(exc),
                    "customer_subject": principal.subject,
                },
            )
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return jsonable_encoder(intent)

    @app.post("/v1/actions/authorize", tags=["enforcement"])
    def authorize_action(
        payload: ActionAuthorize,
        principal: Principal = Depends(agent_principal),
    ) -> dict[str, Any]:
        agent_id = require_claim(principal, "agent_id")
        customer_id = require_claim(principal, "customer_id")
        require_match(payload.agent_id, agent_id, "agent")
        if payload.customer_id is not None:
            require_match(payload.customer_id, customer_id, "customer")
        occurred_at = payload.occurred_at or datetime.now(timezone.utc)
        if occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(tzinfo=timezone.utc)
        request = ActionRequest(
            request_id=payload.request_id,
            agent_id=agent_id,
            action=payload.action,
            amount=payload.amount,
            currency=payload.currency.upper(),
            intent_id=payload.intent_id,
            risk_score=payload.risk_score,
            attributes=payload.attributes,
            customer_id=customer_id,
            submitted_by=principal.subject,
            occurred_at=occurred_at,
            claim=(
                RefundClaim(
                    reason=payload.claim.reason,
                    order_value=payload.claim.order_value,
                    days_since_delivery=payload.claim.days_since_delivery,
                    evidence=payload.claim.derived_evidence,
                    order_reference=payload.claim.order_reference,
                    artifacts=tuple(
                        EvidenceArtifact(
                            kind=artifact.kind, reference=artifact.reference
                        )
                        for artifact in payload.claim.artifacts
                    ),
                    complaint=payload.claim.complaint,
                )
                if payload.claim is not None
                else None
            ),
        )
        observation_fields(
            agent_id=agent_id,
            customer_id=customer_id,
            request_id=request.request_id,
            intent_id=request.intent_id,
        )
        started_at = perf_counter()
        try:
            with operation_span(
                "intentguard.policy.authorize", request_id=request.request_id
            ):
                result = governance_engine().authorize_action(request)
        except PolicyEvaluationError as exc:
            governance_engine().audit_ledger.append(
                "policy.evaluation.failed",
                {"request_id": request.request_id, "reason": str(exc)},
            )
            raise HTTPException(
                status_code=503,
                detail="Policy evaluation is unavailable; authorization failed closed.",
            ) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        latency_ms = round((perf_counter() - started_at) * 1000, 3)
        metrics.policy_latency.observe(latency_ms / 1000)
        metrics.authorizations.labels(result.decision.decision.value).inc()
        finding_codes = {finding.code for finding in result.decision.findings}
        if "DAILY_BUDGET_EXCEEDED" in finding_codes:
            metrics.budget_failures.labels("daily_budget_exceeded").inc()
        observation_fields(
            policy_version=result.decision.policy_version,
            decision=result.decision.decision.value,
            reservation_id=(
                result.reservation.reservation_id if result.reservation else None
            ),
            lease_id=result.lease.lease_id if result.lease else None,
        )
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
                "authenticated_subject": principal.subject,
                "customer_id": customer_id,
            },
        )
        return jsonable_encoder(result)

    @app.post(
        "/v1/reservations/{reservation_id}/commit",
        tags=["enforcement"],
    )
    def commit_reservation(
        reservation_id: str,
        payload: ReservationCommit,
        principal: Principal = Depends(agent_principal),
    ) -> dict[str, Any]:
        agent_id = require_claim(principal, "agent_id")
        observation_fields(agent_id=agent_id, reservation_id=reservation_id)
        owned = governance_engine().get_reservation(reservation_id)
        if owned is not None:
            require_match(owned.agent_id, agent_id, "agent")
            observation_fields(request_id=owned.request_id)
        observation_fields(lease_id=payload.lease_id)
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
        reservation_id: str,
        payload: ReservationRelease,
        principal: Principal = Depends(agent_principal),
    ) -> dict[str, Any]:
        agent_id = require_claim(principal, "agent_id")
        owned = governance_engine().get_reservation(reservation_id)
        if owned is not None:
            require_match(owned.agent_id, agent_id, "agent")
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
        "/v1/connectors/reservations/{reservation_id}/commit",
        tags=["connectors", "enforcement"],
    )
    def connector_commit_reservation(
        reservation_id: str,
        payload: ReservationCommit,
        principal: Principal = Depends(connector_principal),
    ) -> dict[str, Any]:
        observation_fields(reservation_id=reservation_id, lease_id=payload.lease_id)
        try:
            reservation = governance_engine().commit_reservation(
                reservation_id, lease_id=payload.lease_id
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            if "expired" in str(exc).lower():
                metrics.lease_expirations.inc()
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        governance_engine().audit_ledger.append(
            "connector.commit.accepted",
            {
                "reservation_id": reservation_id,
                "request_id": reservation.request_id,
                "connector_subject": principal.subject,
            },
        )
        return jsonable_encoder(reservation)

    @app.get("/v1/connectors/lease-key", tags=["connectors", "keys"])
    def connector_lease_key(
        principal: Principal = Depends(connector_principal),
    ) -> dict[str, Any]:
        signer = governance_engine().lease_signer
        if signer is None:
            raise HTTPException(
                status_code=503, detail="Execution lease signing is not configured."
            )
        key = signer.key_registry.get(signer.issuer, signer.key_id)
        if key is None:
            raise HTTPException(status_code=503, detail="Lease verification key missing.")
        return jsonable_encoder(key)

    @app.post(
        "/v1/connectors/reservations/{reservation_id}/release",
        tags=["connectors", "enforcement"],
    )
    def connector_release_reservation(
        reservation_id: str,
        payload: ReservationRelease,
        principal: Principal = Depends(connector_principal),
    ) -> dict[str, Any]:
        try:
            reservation = governance_engine().release_reservation(
                reservation_id, reason=payload.reason
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        governance_engine().audit_ledger.append(
            "connector.release.accepted",
            {
                "reservation_id": reservation_id,
                "request_id": reservation.request_id,
                "connector_subject": principal.subject,
                "reason": payload.reason,
            },
        )
        return jsonable_encoder(reservation)

    @app.post(
        "/v1/agents/{agent_id}/revoke",
        status_code=status.HTTP_204_NO_CONTENT,
        tags=["agents"],
    )
    def revoke_agent(
        agent_id: str,
        principal: Principal = Depends(operator_principal),
    ) -> None:
        observation_fields(agent_id=agent_id)
        started_at = perf_counter()
        governance_engine().revoke_agent(agent_id)
        metrics.revocation_propagation.observe(perf_counter() - started_at)
        governance_engine().audit_ledger.append(
            "gateway.agent.revoked",
            {"agent_id": agent_id, "operator": principal.subject},
        )

    @app.post(
        "/v1/agents/{agent_id}/restore",
        status_code=status.HTTP_204_NO_CONTENT,
        tags=["agents"],
    )
    def restore_agent(
        agent_id: str,
        principal: Principal = Depends(operator_principal),
    ) -> None:
        try:
            governance_engine().restore_agent(agent_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post(
        "/v1/fleet/stop",
        status_code=status.HTTP_204_NO_CONTENT,
        tags=["fleet"],
    )
    def stop_fleet(
        payload: FleetStop,
        principal: Principal = Depends(operator_principal),
    ) -> None:
        governance_engine().stop_fleet(reason=payload.reason)
        governance_engine().audit_ledger.append(
            "gateway.fleet.stopped",
            {"operator": principal.subject, "reason": payload.reason},
        )

    @app.post(
        "/v1/fleet/resume",
        status_code=status.HTTP_204_NO_CONTENT,
        tags=["fleet"],
    )
    def resume_fleet(
        principal: Principal = Depends(operator_principal),
    ) -> None:
        governance_engine().resume_fleet()

    def evidence_scope(principal: Principal) -> str:
        """The organisation whose evidence this caller may touch.

        ``authenticated_principal`` always resolves an organisation, so this
        is unreachable in practice. It is written to fail closed anyway: the
        field is optional on ``Principal``, and an evidence store that reads a
        ``None`` scope would serve across tenants rather than refuse.
        """

        if principal.org_id is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="The authenticated subject belongs to no organisation.",
            )
        return principal.org_id

    @app.post("/v1/evidence", status_code=201, tags=["evidence"])
    def upload_evidence(
        payload: EvidenceUpload,
        principal: Principal = Depends(evidence_writer),
    ) -> dict[str, Any]:
        """Store an evidence image and return the reference a claim can cite.

        Base64 in JSON rather than multipart, deliberately: a multipart parser
        is itself attack surface on the one endpoint whose whole job is taking
        hostile bytes, and staying on JSON keeps the existing authentication,
        rate limiting and validation applying unchanged.
        """

        try:
            content = base64.b64decode(payload.content_base64, validate=True)
        except (BinasciiError, ValueError) as exc:
            raise HTTPException(
                status_code=422, detail="content_base64 is not valid base64."
            ) from exc
        try:
            stored = app.state.evidence_store.put(
                kind=payload.kind,
                content=content,
                uploaded_by=principal.subject,
                org_id=evidence_scope(principal),
                customer_id=principal.customer_id,
            )
        except EvidenceValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        governance_engine().audit_ledger.append(
            "evidence.stored",
            {
                "reference": stored.reference,
                "kind": stored.kind.value,
                "media_type": stored.media_type,
                "byte_length": len(stored.content),
                "uploaded_by": principal.subject,
                "org_id": stored.org_id,
                "customer_id": stored.customer_id,
            },
        )
        return {
            "reference": stored.reference,
            "kind": stored.kind.value,
            "media_type": stored.media_type,
            "byte_length": len(stored.content),
        }

    @app.get("/v1/evidence/{reference}", tags=["evidence"])
    def read_evidence(
        reference: str,
        principal: Principal = Depends(evidence_reader),
    ) -> Response:
        """Serve stored evidence, treating the response as hostile.

        The media type is the one sniffed at upload, never anything a caller
        said. nosniff stops a browser second-guessing it, the disposition
        filename is generated rather than supplied, and the CSP permits
        nothing at all -- so even a file that somehow reached storage with a
        script inside it has no way to run.

        Holding the reference is not the same as being allowed to see it. The
        store answers only within the caller's organisation, and ``may_read``
        then applies the rule inside it. Both refusals are reported as 404,
        identically to a reference that never existed, so the response cannot
        be used to confirm that one does.
        """

        stored = app.state.evidence_store.get(
            reference, org_id=evidence_scope(principal)
        )
        if stored is None or not may_read_evidence(
            stored,
            roles=principal.roles,
            subject=principal.subject,
            customer_id=principal.customer_id,
        ):
            raise HTTPException(status_code=404, detail="No such evidence.")
        return Response(
            content=stored.content,
            media_type=stored.media_type,
            headers={
                "X-Content-Type-Options": "nosniff",
                "Content-Disposition": f'inline; filename="{stored.filename}"',
                "Content-Security-Policy": "default-src 'none'; sandbox",
                "Cache-Control": "private, max-age=300",
                "Referrer-Policy": "no-referrer",
            },
        )

    @app.get("/v1/approvals", tags=["approvals"])
    def list_approvals(
        principal: Principal = Depends(reviewer_principal),
    ) -> list[dict[str, Any]]:
        return jsonable_encoder(governance_engine().list_approvals())

    @app.post(
        "/v1/approvals/{request_id}/approve",
        tags=["approvals"],
    )
    def approve_action(
        request_id: str,
        payload: ApprovalResolution,
        principal: Principal = Depends(reviewer_principal),
    ) -> dict[str, Any]:
        observation_fields(request_id=request_id)
        try:
            result = governance_engine().approve_action(
                request_id,
                reviewer=principal.subject,
                reason=payload.reason,
            )
        except PolicyEvaluationError as exc:
            raise HTTPException(
                status_code=503,
                detail="Policy evaluation is unavailable; approval failed closed.",
            ) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        observation_fields(
            decision=result.decision.decision.value,
            policy_version=result.decision.policy_version,
            reservation_id=(
                result.reservation.reservation_id if result.reservation else None
            ),
            lease_id=result.lease.lease_id if result.lease else None,
        )
        return jsonable_encoder(result)

    @app.post(
        "/v1/approvals/{request_id}/reject",
        tags=["approvals"],
    )
    def reject_action(
        request_id: str,
        payload: ApprovalResolution,
        principal: Principal = Depends(reviewer_principal),
    ) -> dict[str, Any]:
        observation_fields(request_id=request_id)
        try:
            approval = governance_engine().reject_action(
                request_id,
                reviewer=principal.subject,
                reason=payload.reason,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        observation_fields(decision="deny")
        return jsonable_encoder(approval)

    @app.get("/v1/audit/events", tags=["audit"])
    def audit_events(
        response: Response,
        after_sequence: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1),
        principal: Principal = Depends(operations_reader),
    ) -> list[dict[str, Any]]:
        if limit > limits.max_audit_page_size:
            raise HTTPException(
                status_code=422,
                detail=(
                    "The requested audit page exceeds the configured maximum "
                    f"of {limits.max_audit_page_size}."
                ),
            )
        events = governance_engine().audit_ledger.as_dicts(
            after_sequence=after_sequence, limit=limit + 1
        )
        page = events[:limit]
        if len(events) > limit and page:
            response.headers["X-Next-Sequence"] = str(page[-1]["sequence"])
        response.headers["X-Audit-Page-Limit"] = str(limit)
        return jsonable_encoder(page)

    @app.get("/v1/audit/retention", tags=["audit"])
    def audit_retention(
        principal: Principal = Depends(operations_reader),
    ) -> dict[str, Any]:
        return app.state.audit_retention.as_dict()

    @app.get("/v1/audit/status", tags=["audit"])
    def audit_status(
        principal: Principal = Depends(operations_reader),
    ) -> dict[str, Any]:
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
    def agent_intents(
        customer_id: str,
        agent_id: str,
        principal: Principal = Depends(customer_principal),
    ) -> list[dict[str, Any]]:
        """The authorizations this customer has granted this agent."""

        verified_customer = require_claim(principal, "customer_id")
        require_match(customer_id, verified_customer, "customer")
        return jsonable_encoder(
            governance_engine().list_intents(
                customer_id=verified_customer, agent_id=agent_id
            )
        )

    @app.get("/v1/intent-keys", tags=["intents", "keys"])
    def list_intent_keys(
        principal: Principal = Depends(operations_reader),
    ) -> list[dict[str, Any]]:
        return jsonable_encoder(signed_intent_verifier().key_registry.list())

    @app.post(
        "/v1/intent-keys",
        status_code=status.HTTP_201_CREATED,
        tags=["intents", "keys"],
    )
    def register_intent_key(
        payload: IntentKeyCreate,
        principal: Principal = Depends(admin_principal),
    ) -> dict[str, Any]:
        try:
            validate_public_key(payload.public_key)
        except IntentVerificationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        valid_from = payload.valid_from
        if valid_from is not None and valid_from.tzinfo is None:
            valid_from = valid_from.replace(tzinfo=timezone.utc)
        expires_at = payload.expires_at
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if valid_from is not None and expires_at is not None and expires_at <= valid_from:
            raise HTTPException(
                status_code=422,
                detail="The signing key expiration must follow its valid-from time.",
            )
        key = IntentSigningKey(
            key_id=payload.key_id,
            issuer=payload.issuer,
            public_key=payload.public_key,
            valid_from=valid_from,
            expires_at=expires_at,
        )
        try:
            signed_intent_verifier().key_registry.save(key)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        governance_engine().audit_ledger.append(
            "intent.key.registered",
            {
                "issuer": key.issuer,
                "key_id": key.key_id,
                "operator": principal.subject,
            },
        )
        return jsonable_encoder(key)

    @app.post(
        "/v1/intent-keys/{key_id}/revoke",
        tags=["intents", "keys"],
    )
    def revoke_intent_key(
        key_id: str,
        payload: IntentKeyRevoke,
        principal: Principal = Depends(admin_principal),
    ) -> dict[str, Any]:
        try:
            key = signed_intent_verifier().key_registry.revoke(
                payload.issuer, key_id
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        governance_engine().audit_ledger.append(
            "intent.key.revoked",
            {
                "issuer": payload.issuer,
                "key_id": key_id,
                "operator": principal.subject,
            },
        )
        return jsonable_encoder(key)

    @app.post("/v1/agent/message", tags=["agent"])
    def agent_message(
        payload: AgentMessage,
        principal: Principal = Depends(customer_principal),
    ) -> dict[str, Any]:
        """Send one customer message to the governed agent.

        The agent proposes; the policy engine decides. Identity is taken from
        the request rather than from anything the model returns.
        """

        customer_id = require_claim(principal, "customer_id")
        require_match(payload.customer_id, customer_id, "customer")
        observation_fields(
            customer_id=customer_id,
            agent_id=payload.agent_id,
        )
        conversation: GovernedAgent = app.state.agent
        agent_started_at = perf_counter()
        with operation_span("intentguard.agent.turn", agent_id=payload.agent_id):
            turn = conversation.send(
                payload.message,
                customer_id=customer_id,
                agent_id=payload.agent_id,
                submitted_by=principal.subject,
            )
        if turn.trace is not None:
            observation_fields(conversation_trace_id=turn.trace.trace_id)
            metrics.llm_latency.labels(
                turn.trace.provider, turn.trace.model, turn.trace.status
            ).observe(turn.trace.latency_ms / 1000)
            metrics.llm_tokens.labels(
                turn.trace.provider, turn.trace.model, "input"
            ).inc(turn.trace.input_tokens)
            metrics.llm_tokens.labels(
                turn.trace.provider, turn.trace.model, "output"
            ).inc(turn.trace.output_tokens)
        if turn.result is not None:
            metrics.authorizations.labels(turn.result.decision.decision.value).inc()
            planner_seconds = (
                turn.trace.latency_ms / 1000 if turn.trace is not None else 0.0
            )
            metrics.policy_latency.observe(
                max(0.0, perf_counter() - agent_started_at - planner_seconds)
            )
            observation_fields(
                request_id=turn.result.decision.request_id,
                intent_id=turn.proposal.intent_id if turn.proposal else None,
                policy_version=turn.result.decision.policy_version,
                decision=turn.result.decision.decision.value,
                reservation_id=(
                    turn.result.reservation.reservation_id
                    if turn.result.reservation else None
                ),
                lease_id=turn.result.lease.lease_id if turn.result.lease else None,
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
                "trace": turn.trace,
            }
        )

    @app.post("/v1/demo/bootstrap", tags=["demo"])
    def bootstrap_demo(
        principal: Principal = Depends(admin_principal),
    ) -> dict[str, Any]:
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
    def reset_demo(
        principal: Principal = Depends(admin_principal),
    ) -> dict[str, Any]:
        current = governance_engine()
        if current.state_repository is not None:
            raise HTTPException(
                status_code=409,
                detail="Demo reset is disabled while durable state is configured.",
            )
        app.state.engine = PolicyEngine(
            intent_verifier=current.intent_verifier,
            lease_signer=current.lease_signer,
            policy_evaluator=current.policy_evaluator,
        )
        app.state.demo_bootstrapped = False
        app.state.agent = GovernedAgent(
            app.state.engine, planner=build_planner()
        )
        return bootstrap_demo(principal)

    @app.get("/v1/demo/benchmark", tags=["demo", "operations"])
    def demo_benchmark(
        principal: Principal = Depends(admin_principal),
    ) -> dict[str, Any]:
        return jsonable_encoder(run_benchmark())

    @app.post(
        "/v1/demo/benchmark/authorize-probe",
        tags=["demo", "operations"],
    )
    def demo_authorization_probe(
        payload: BenchmarkProbe,
        principal: Principal = Depends(admin_principal),
    ) -> dict[str, Any]:
        """Exercise the full FastAPI authorization path using isolated state."""

        started_at = perf_counter()
        result = app.state.benchmark_probe_engine.authorize_action(
            api_probe_request(payload.request_id)
        )
        server_processing_ms = round((perf_counter() - started_at) * 1000, 4)
        if result.reservation is not None:
            app.state.benchmark_probe_engine.release_reservation(
                result.reservation.reservation_id,
                reason="benchmark_probe_cleanup",
            )
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
