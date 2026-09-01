# Contributing to IntentGuard

## Development setup

Install Python 3.10 or newer, Node.js 22.13 or newer, pnpm, and uv. From the
repository root:

```powershell
uv sync --all-extras --locked
./scripts/install-opa.ps1

$nodeDir = Join-Path (Resolve-Path '.') '.tools/node-v24.17.0-win-x64'
$env:Path = "$nodeDir;$env:Path"
corepack pnpm@11.24.0 --dir prototype install --frozen-lockfile
```

The checked-in Node directory is a local convenience in this workspace; a
normal Node installation satisfying `prototype/package.json` is equivalent.

## Make changes safely

- Keep LLM output on the proposal side of the authorization boundary.
- Preserve fail-closed behavior for identity, policy, storage, rate limiting,
  lease validation, and connector errors.
- Never make Redis authoritative for budgets, revocation, or consent.
- Add a migration for durable schema changes; do not edit applied migrations.
- Do not commit tokens, private keys, `.env`, provider payloads, or customer
  prompts.
- Update threat-model limitations and an ADR when a trust boundary changes.

## Tests

```powershell
.venv/Scripts/python.exe -m unittest discover -s tests -q
.venv/Scripts/ruff.exe check --select E9,F63,F7,F82 src tests scripts
.venv/Scripts/mypy.exe --follow-imports=skip --ignore-missing-imports scripts/migrate.py src/intentguard/abuse.py

corepack pnpm@11.24.0 --dir prototype lint
corepack pnpm@11.24.0 --dir prototype typecheck
corepack pnpm@11.24.0 --dir prototype test
```

Run `intentguard-evaluate` when changing policy, identity, intent, budget,
approval, lease, connector, outage, concurrency, or LLM behavior. Use the
PostgreSQL integration suite for storage and multi-process invariants.

## Pull requests

A pull request should state the problem, trust boundary or invariant affected,
test evidence, operational impact, migration/rollback plan, and documentation
changes. Keep unrelated formatting and dependency churn separate. Require a
second review for authentication, cryptography, Rego policy, budget SQL,
revocation, and incident-response changes.

## Architecture decisions

Add a numbered record under `docs/adr/` when a change selects or replaces a
security boundary, authoritative store, policy engine, identity mechanism,
deployment model, or public contract. Include context, decision, consequences,
alternatives, and verification.

## Reporting security issues

Do not open a public issue containing an exploit, token, customer data, or live
system detail. Contact the repository owners privately, include the smallest
safe reproduction, and follow `docs/incident-response.md` for containment and
evidence handling.
