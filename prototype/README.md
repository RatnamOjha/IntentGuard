# IntentGuard operator-console prototype

This is the interactive first-round prototype for IntentGuard, a governance
control plane for autonomous financial agents.

The console demonstrates:

- allow, review, and block policy decisions;
- identity, permission, budget, and risk evaluation;
- dynamic spend utilization for each agent;
- individual agent revocation and restoration;
- a fleet-wide emergency stop;
- append-only audit events and enforcement latency.

All interactions currently use deterministic in-memory demo state. The Python
policy-engine foundation in the repository root is the starting point for the
FastAPI, OPA, PostgreSQL, and Redis integration.

## Run locally

Requires Node.js 22.13 or newer and pnpm.

```bash
pnpm install
pnpm run dev
```

Open `http://localhost:3000`.

## Validate

```bash
pnpm run lint
pnpm test
```

The production build uses Vinext and the included Sites/Cloudflare worker
configuration. `.openai/hosting.json` stores the associated private Sites
project ID; it contains no source-repository credentials.

