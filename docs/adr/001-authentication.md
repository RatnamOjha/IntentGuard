# ADR 001: Authenticate callers with signed JWTs and enforce ownership at the gateway

- Status: Accepted
- Date: 2026-08-30

## Context

The first prototype accepted agent and customer identifiers from request bodies.
That made policy evaluation deterministic, but it did not establish who was
calling or prevent one caller from naming another agent or customer. The
gateway needs locally reproducible identity while remaining compatible with a
managed OpenID Connect provider.

## Decision

The FastAPI gateway validates RS256 bearer tokens against a cached JWKS. It
checks signature, key ID, issuer, audience, expiry, and not-before time. Roles
are `customer`, `agent`, `operator`, `reviewer`, `connector`, and `admin`.
Agent and customer ownership come from verified claims; body fields are only
accepted when they match those claims. Approval endpoints additionally prevent
a subject from reviewing a request it submitted.

Keycloak supplies the complete local identity environment. Tests use the same
JWT validation path with deterministic keys. The connector uses a separate
client-credentials identity rather than an operator or agent token.

## Consequences

- Identity spoofing, wrong-role access, expired tokens, and invalid signatures
  fail before policy evaluation.
- Audit actors are authenticated subjects instead of body-supplied names.
- A JWKS or identity-provider outage can prevent new authenticated requests;
  cached keys limit unnecessary coupling, but authorization still fails closed.
- Authorization remains separate from authentication: a valid token does not
  imply that a requested action satisfies intent, policy, budget, or risk.

## Alternatives considered

- API keys: easy to demo, but weak for user, workload, role, and ownership
  separation.
- Session cookies: appropriate for a browser application, but not for agent and
  connector workloads.
- Provider-specific SDKs: rejected to keep the boundary standards-based and
  testable without a hosted account.

## Verification

`tests/test_auth.py` and `tests/test_api_auth.py` cover cryptographic validation,
role enforcement, impersonation, verified audit identity, and separation of
duties.
