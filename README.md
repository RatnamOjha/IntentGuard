# IntentGuard

**Runtime governance for financial AI agents**

IntentGuard is a real-time control plane that evaluates every action proposed by
an autonomous financial agent before that action reaches a payment, servicing,
travel, or claims system.

It combines agent identity, authenticated customer intent, policy-as-code,
dynamic spend limits, risk-based human approval, instant revocation, a fleet
kill switch, and a tamper-evident audit trail.

## Why this matters

Traditional API authorization answers:

> Is this agent allowed to call this API?

IntentGuard answers the stronger question:

> Is this exact action allowed for this agent, customer intent, budget, risk
> level, and point in time?

For example, a travel agent may be allowed to book flights, but a request to
purchase a non-refundable INR 31,000 ticket must still be blocked when the
customer authorized only refundable tickets below INR 18,000.

## Current milestone

The repository contains a dependency-light Python domain core and a FastAPI
governance gateway that demonstrate:

- registered-agent and action-level permissions;
- intent-bound amount, currency, and contextual constraints;
- per-action and rolling daily spend limits;
- an operator approval queue for high-risk actions;
- individual-agent revocation;
- an emergency fleet stop;
- hash-chained audit events with integrity verification.
- concurrency-safe budget reservations and short-lived execution leases;
- fleet-epoch invalidation of outstanding authorizations;
- a live React dashboard connected to the REST and OpenAPI contract.

## Production architecture and current prototype

The listed challenge technologies are examples rather than requirements. We are
using one coherent production path instead of attempting to use every suggested
product. The dashboard labels components as either running now or roadmap so
the prototype does not overstate its implementation.

| Layer | Selected technology | Responsibility |
| --- | --- | --- |
| Operator UI | React, TypeScript, Vite | Policies, budgets, fleet controls, activity, and audit review |
| Governance API | FastAPI, Python | Enforcement gateway and operator APIs |
| Policy decisions | Open Policy Agent, Rego | Granular permission and contextual policy evaluation |
| Durable state | PostgreSQL | Agents, policies, budgets, approvals, and audit metadata |
| Runtime state | Redis | Atomic reservations, counters, revocation epochs, and fleet-stop state |
| Monitoring | Prometheus, Grafana | Latency, decisions, policy failures, and fleet health |
| Enterprise export | Splunk-compatible HTTP event export | Optional downstream security and audit integration |
| Local runtime | Docker Compose | Reproducible end-to-end prototype |
| Deployment path | AWS | ECS/Fargate, RDS, ElastiCache, and managed secrets |

The current executable prototype uses React/Vinext, FastAPI, the deterministic
Python policy engine, and in-memory state. OPA, PostgreSQL, Redis, Prometheus,
Splunk, Docker Compose, and AWS are explicit production-roadmap components.

## Challenge task coverage

| Required task | IntentGuard implementation |
| --- | --- |
| Granular agent permissions | Live versioned agent-policy editor plus deterministic runtime enforcement |
| Dynamic spend caps | Concurrency-safe reserve/commit/release lifecycle with live budget editing |
| Revocation and emergency stop | Per-agent revocation epochs and a fleet-wide kill switch |
| Operator dashboard | Live React console for policy, budgets, approvals, fleet controls, and audit |
| Accuracy, latency, and auditability | 27-control acceptance suite, separate engine/API latency measurements, concurrency tests, and a hash-chained audit trail |

## Quick start

Requires Python 3.9 or newer, Node.js 22.13 or newer, and pnpm. Start the full
demo with one command:

```bash
./scripts/start-demo.sh
```

Open the local URL printed by Vinext, normally `http://localhost:3000`. It
connects to the API at `http://127.0.0.1:8000` and initializes a deterministic
three-agent sandbox.
Interactive API documentation is available at `http://127.0.0.1:8000/docs`.

On Windows PowerShell:

```powershell
.\scripts\start-demo.ps1
```

Run every backend and frontend check with:

```bash
./scripts/test-all.sh
```

The Windows equivalent is `.\scripts\test-all.ps1`.

Generate reproducible acceptance, in-process engine latency, concurrency, and
audit evidence with:

```bash
PYTHONPATH=src .venv/bin/python -m intentguard.benchmark
```

On Windows PowerShell, start the API with:

```powershell
python -m venv .venv
# This laptop's MSYS Python creates .venv/bin rather than .venv/Scripts.
& .\.venv\bin\python.exe -m pip install -e ".[api,dev]"
& .\.venv\bin\python.exe -m unittest discover -s tests -v
& .\.venv\bin\python.exe -m uvicorn intentguard.api:app --reload
```

Then open `http://127.0.0.1:8000/docs`. The shared frontend contract is in
[`docs/api-contract.md`](docs/api-contract.md).

With the standard Windows Python distribution, replace `.venv\bin` with
`.venv\Scripts` in these commands.

The API accepts the Vinext dashboard origins on ports 3000, 3001, and 5173 by
default. For deployed environments, set a comma-separated allowlist:

```powershell
$env:INTENTGUARD_CORS_ORIGINS="https://operator.example.com"
```

Submission resources:

- [`docs/prototype-readiness.md`](docs/prototype-readiness.md) — critical-gap coverage and final checklist
- [`docs/api-contract.md`](docs/api-contract.md) — live frontend/backend contract

## Demo scenarios

The example evaluates four actions:

1. A compliant refundable flight booking is allowed.
2. An over-budget booking is denied.
3. A high-risk request is routed to human review.
4. A pre-stop execution lease is rejected by the protected connector after the
   fleet epoch changes.
5. A live policy edit changes an agent's next decision.

## Project structure

```text
.
├── docs/
│   └── architecture.md
├── examples/
│   └── demo.py
├── src/
│   └── intentguard/
│       ├── audit.py
│       ├── models.py
│       └── policy_engine.py
└── tests/
    └── test_policy_engine.py
```

## Product roadmap

### Round 1: idea submission

- Architecture and problem framing
- Distinctive intent-bound authorization story
- Measurable business and risk outcomes
- Credible prototype plan

### Prototype

- FastAPI governance gateway
- React and TypeScript operator console
- OPA/Rego policy configuration and simulation
- PostgreSQL durable state
- Redis runtime budgets and revocation state
- Three mocked agents: travel, servicing, and benefits
- Human approval queue
- Real-time fleet monitoring and audit replay

### Advanced differentiators

- Signed intent passports and scoped agent credentials
- Delegation lineage for multi-agent workflows
- Velocity and anomaly-based dynamic budgets
- Shadow-mode policy testing
- Counterfactual and adversarial policy tests
- Merkle-backed audit checkpoints

## Hackathon alignment

IntentGuard targets the **Governance Layer for Financial Agents** theme in
[American Express CodeStreet 2026](https://www.hackerearth.com/community/challenges/hackathon/codestreet-2026/).

Its design is also aligned with American Express's public direction around
verified agents, intent intelligence, spend controls, and trusted agentic
commerce through the
[ACE developer kit](https://www.americanexpress.com/en-us/company/agentic-commerce/).
