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
- live versioned permission and budget configuration;
- protected-connector rejection of stale execution leases;
- 27-control acceptance coverage, separate engine/API latency measurements,
  concurrency safety, and audit evidence.

All interactions call the FastAPI governance gateway. The console bootstraps a
deterministic three-agent sandbox, evaluates scenarios through the real policy
engine, commits allowed budget reservations, controls live revocation state,
and resolves high-risk requests through the operator approval queue.

## Run locally

The simplest way to start both services is from the repository root:

```bash
./scripts/start-demo.sh
```

On Windows PowerShell:

```powershell
.\scripts\start-demo.ps1
```

For frontend-only development, start the FastAPI service separately first.
Requires Node.js 22.13 or newer and pnpm.

```bash
pnpm install
pnpm run dev
```

Open `http://localhost:3000`.

The dashboard uses `http://127.0.0.1:8000` by default. Override it when needed:

```bash
NEXT_PUBLIC_INTENTGUARD_API_URL=http://localhost:8000 pnpm run dev
```

## Validate

```bash
pnpm run lint
pnpm test
```

The production build uses Vinext and the included Cloudflare worker
configuration.
