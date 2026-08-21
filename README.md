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
| Operator UI | React 19, TypeScript, Next.js 16 on Vite | Policies, budgets, fleet controls, activity, and audit review |
| Governance API | FastAPI, Python | Enforcement gateway and operator APIs |
| Policy decisions | Open Policy Agent, Rego | Granular permission and contextual policy evaluation |
| Durable state | PostgreSQL | Agents, policies, budgets, approvals, and audit metadata |
| Runtime state | Redis | Atomic reservations, counters, revocation epochs, and fleet-stop state |
| Monitoring | Prometheus, Grafana | Latency, decisions, policy failures, and fleet health |
| Enterprise export | Splunk-compatible HTTP event export | Optional downstream security and audit integration |
| Local runtime | Docker Compose | Reproducible end-to-end prototype |
| Deployment path | AWS | ECS/Fargate, RDS, ElastiCache, and managed secrets |

The current executable prototype uses React and Next.js built and served by
`vinext` (a Vite-based drop-in replacement for the Next.js CLI), FastAPI, the
deterministic Python policy engine, and in-memory state. OPA, PostgreSQL,
Redis, Prometheus, Splunk, Docker Compose, and AWS are explicit
production-roadmap components.

## Challenge task coverage

| Required task | IntentGuard implementation |
| --- | --- |
| Granular agent permissions | Live versioned agent-policy editor plus deterministic runtime enforcement |
| Dynamic spend caps | Concurrency-safe reserve/commit/release lifecycle with live budget editing |
| Revocation and emergency stop | Per-agent revocation epochs and a fleet-wide kill switch |
| Operator dashboard | Live React console for policy, budgets, approvals, fleet controls, and audit |
| Accuracy, latency, and auditability | 27-control acceptance suite, separate engine/API latency measurements, concurrency tests, and a hash-chained audit trail |

## Quick start

Requires Python 3.10 or newer (the pinned FastAPI, Starlette, and Uvicorn
releases require it), Node.js 22.13 or newer, and pnpm. Start the full demo
with one command:

```bash
./scripts/start-demo.sh
```

Open the local URL printed by `vinext`, normally `http://localhost:3000`. It
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

To start the API on its own from Windows PowerShell, resolve the interpreter
first so the commands work whichever layout `venv` produced:

```powershell
python -m venv .venv
$Python = @('.venv\Scripts\python.exe', '.venv\bin\python.exe') |
    Where-Object { Test-Path $_ } | Select-Object -First 1
& $Python -m pip install -e ".[api,dev]"
& $Python -m unittest discover -s tests -v
& $Python -m uvicorn intentguard.api:app --reload
```

Then open `http://127.0.0.1:8000/docs`. The shared frontend contract is in
[`docs/api-contract.md`](docs/api-contract.md).

The API accepts the operator-console origins on ports 3000, 3001, and 5173 by
default. For deployed environments, set a comma-separated allowlist:

```bash
export INTENTGUARD_CORS_ORIGINS="https://operator.example.com"
```

```powershell
$env:INTENTGUARD_CORS_ORIGINS="https://operator.example.com"
```

Submission resources:

- [`docs/prototype-readiness.md`](docs/prototype-readiness.md) — critical-gap coverage and final checklist
- [`docs/api-contract.md`](docs/api-contract.md) — live frontend/backend contract

## Demo scenarios

Run the worked example against the in-process engine:

```bash
PYTHONPATH=src .venv/bin/python examples/demo.py
```

[`examples/demo.py`](examples/demo.py) registers one travel agent and one
customer intent, then evaluates four actions:

1. A compliant refundable INR 16,000 booking is allowed and recorded as spend.
2. An INR 31,000 booking is denied for breaching the agent's per-action limit,
   the customer's authorized maximum, and the remaining daily budget.
3. A booking with a risk score of 82 is routed to human review.
4. After the operator triggers the fleet emergency stop, a further booking is
   denied.

The script then prints whether the hash-chained audit ledger still verifies.

Lease revocation, protected-connector rejection, and live policy edits are
exercised by the test suite and the operator console rather than by this
script.

## Project structure

```text
.
├── docs/
│   ├── api-contract.md          # REST contract shared with the console
│   ├── architecture.md
│   ├── build-plan.md
│   ├── context.md
│   └── prototype-readiness.md
├── examples/
│   └── demo.py                  # Four-scenario worked example
├── prototype/                   # Operator console (React, Next.js, vinext)
│   ├── app/                     # layout.tsx, page.tsx, globals.css
│   ├── build/                   # sites-vite-plugin.ts
│   ├── db/                      # Drizzle schema and client
│   ├── lib/intentguard-api.ts   # Typed client for the governance API
│   ├── public/
│   ├── tests/rendered-html.test.mjs
│   ├── worker/index.ts          # Cloudflare worker entry point
│   └── vite.config.ts
├── scripts/
│   ├── start-demo.sh            # and start-demo.ps1
│   └── test-all.sh              # and test-all.ps1
├── src/
│   └── intentguard/
│       ├── __init__.py          # Public package surface
│       ├── api.py               # FastAPI governance gateway
│       ├── audit.py             # Hash-chained audit ledger
│       ├── benchmark.py         # Acceptance, latency, and race evidence
│       ├── models.py            # Domain models
│       └── policy_engine.py     # Runtime policy evaluation
└── tests/
    ├── test_api.py
    ├── test_authorization_flow.py
    ├── test_benchmark.py
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
