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

The repository currently contains a dependency-light Python domain core that
demonstrates:

- registered-agent and action-level permissions;
- intent-bound amount, currency, and contextual constraints;
- per-action and rolling daily spend limits;
- risk-based human review;
- individual-agent revocation;
- an emergency fleet stop;
- hash-chained audit events with integrity verification.

## Locked prototype stack

The listed challenge technologies are examples rather than requirements. We are
using one coherent stack instead of attempting to use every suggested product:

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

## Challenge task coverage

| Required task | IntentGuard implementation |
| --- | --- |
| Granular agent permissions | Agent registry plus versioned OPA/Rego policies |
| Dynamic spend caps | Atomic reserve/commit/release budget engine backed by Redis |
| Revocation and emergency stop | Per-agent revocation epochs and a fleet-wide kill switch |
| Operator dashboard | React console for policy, budget, activity, controls, and audit |
| Accuracy, latency, and auditability | Policy test suites, load tests, Prometheus metrics, and a hash-chained audit trail |

## Quick start

Requires Python 3.9 or newer.

```bash
python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 examples/demo.py
```

## Demo scenarios

The example evaluates four actions:

1. A compliant refundable flight booking is allowed.
2. An over-budget booking is denied.
3. A high-risk request is routed to human review.
4. A valid request is denied after the fleet emergency stop is activated.

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
