# IntentGuard Project Context

## Project goal

Build a real-time governance layer for autonomous financial agents.

## Current milestone

Completing integration between the Vinext operator dashboard in `prototype/`
and the FastAPI enforcement gateway.

## What currently works

- Intent-bound permissions
- Per-action and daily limits
- Human-review decisions
- Agent revocation, restoration, and fleet stop
- Tamper-evident audit chain
- FastAPI governance gateway and OpenAPI documentation
- Atomic budget reserve, commit, release, and expiry lifecycle
- Idempotent action authorization
- Fleet-epoch invalidation of outstanding execution leases
- Domain, concurrency, regression, and API tests
- Vinext operator dashboard under `prototype/` on `main`

## Architecture decisions

### 2026-07-26 — Intent-bound authorization

Permissions must be constrained by authenticated customer intent.

### 2026-07-26 — Protected execution boundary

Agents cannot call protected financial APIs directly.

### 2026-07-26 — Budget reservations

Financial actions reserve budget before execution and commit or release it
after the connector reports an outcome.

### 2026-07-27 — Short-lived execution leases

An allowed action receives an opaque, short-lived lease bound to its request,
reservation, agent, and current fleet epoch. Protected connectors must commit
with this lease; a fleet stop increments the epoch and invalidates old work.

### 2026-07-27 — Backward-compatible domain evolution

The original `evaluate` and `record_execution` methods remain available for the
demo. Production-facing API calls use `authorize_action` and the reservation
lifecycle so the policy check and budget hold are atomic.

## Current technical limitations

- State is held in memory.
- Human review is represented as a decision but has no workflow.
- Execution leases are opaque IDs rather than cryptographically signed tokens.
- In-memory locking protects one process; Redis will coordinate multiple replicas.

## Immediate next tasks

- [x] Create FastAPI application
- [x] Define API request and response models
- [x] Implement budget reservation lifecycle
- [x] Add authorization leases and idempotency
- [x] Add concurrency tests
- [x] Build dashboard shell
- [x] Add configurable dashboard CORS origins
- [x] Add agent restoration to the engine and API
- [ ] Implement human approval workflow
- [ ] Add PostgreSQL and Redis adapters

## Work ownership

| Area | Owner | Branch | Status |
|---|---|---|---|
| FastAPI gateway | Backend owner | api-gateway | Ready for integration |
| Vinext dashboard | Frontend owner | main (`prototype/`) | Implemented |

## Running the project

Run the dependency-light domain tests and demo:

```powershell
python -m unittest discover -s tests -v
$env:PYTHONPATH="src"
python examples\demo.py
```

Install and run the API:

```powershell
python -m venv .venv
& .\.venv\bin\python.exe -m pip install -e ".[api,dev]"
& .\.venv\bin\python.exe -m uvicorn intentguard.api:app --reload
```

OpenAPI documentation is available at `http://127.0.0.1:8000/docs`.
Standard Windows Python installations use `.venv\Scripts` instead of
`.venv\bin`.

Browser origins are configured through the comma-separated
`INTENTGUARD_CORS_ORIGINS` environment variable. Defaults cover the dashboard
on ports 3000 and 5173 for both `localhost` and `127.0.0.1`.

## Change log

### 2026-07-27

- Added configurable CORS origins and the Vinext port 3000 defaults.
- Added agent restoration with an API endpoint, audit event, and tests.
- Updated shared context for the dashboard now present under `prototype/`.
- Added the FastAPI governance gateway and frontend-safe CORS configuration.
- Added atomic budget holds with commit, release, and automatic expiry.
- Added idempotent request handling and request-data conflict detection.
- Added fleet epochs so an emergency stop invalidates outstanding leases.
- Added concurrency and API integration tests.
- Documented the frontend/backend contract in `docs/api-contract.md`.

### 2026-07-26

- Initialized the IntentGuard domain foundation.
- Added policy evaluation, intent passports, revocation, and audit chaining.
- Added the initial architecture and product roadmap.
