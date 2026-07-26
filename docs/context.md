# IntentGuard Project Context

## Project goal

Build a real-time governance layer for autonomous financial agents.

## Current milestone

Building the FastAPI enforcement gateway and concurrency-safe budget system.

## What currently works

- Intent-bound permissions
- Per-action and daily limits
- Human-review decisions
- Agent revocation
- Fleet stop
- Tamper-evident audit chain
- Eight passing unit tests

## Architecture decisions

### 2026-07-26 — Intent-bound authorization

Permissions must be constrained by authenticated customer intent.

### 2026-07-26 — Protected execution boundary

Agents cannot call protected financial APIs directly.

### 2026-07-26 — Budget reservations

Financial actions will reserve budget before execution and commit or release it
after the connector reports an outcome.

## Current technical limitations

- State is held in memory.
- Budget enforcement is not concurrency-safe.
- No HTTP API exists yet.
- No persistent database exists yet.
- Human review is represented as a decision but has no workflow.
- Fleet stop does not invalidate previously issued authorizations.

## Immediate next tasks

- [ ] Create FastAPI application
- [ ] Define API request and response models
- [ ] Implement budget reservation lifecycle
- [ ] Add authorization leases and idempotency
- [ ] Add concurrency tests
- [ ] Build dashboard shell

## Work ownership

| Area | Owner | Branch | Status |
|---|---|---|---|
| FastAPI gateway | Name | feature/api-gateway | Planned |
| React dashboard | Name | feature/dashboard | Planned |

## Running the project

```powershell
python -m unittest discover -s tests -v
$env:PYTHONPATH="src"
python examples\demo.py