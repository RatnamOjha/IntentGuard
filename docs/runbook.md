# IntentGuard operator runbook

This runbook covers the local production-like stack. Commands assume the
repository root and PowerShell; equivalent `stack.sh` and Docker Compose
commands are documented in `deployment.md`.

## Start and verify

```powershell
Copy-Item .env.compose.example .env.compose
# Replace every local-only secret in .env.compose.
./scripts/stack.ps1 up
./scripts/stack.ps1 status
```

Verify these endpoints:

| Check | Expected result |
| --- | --- |
| `http://localhost:3000` | Operator console renders |
| `http://localhost:8000/health/live` | `{"status":"ok"}` |
| `http://localhost:8000/health/ready` | HTTP 200 and `status=ready` |
| `http://localhost:8100/health` | Connector healthy |
| `http://localhost:8181/health` | OPA healthy |
| `http://localhost:9090/-/ready` | Prometheus ready |
| `http://localhost:3002/api/health` | Grafana database OK |

The gateway readiness check fails with HTTP 503 when an authoritative database
or configured distributed rate limiter is unavailable.

## Routine operations

```powershell
./scripts/stack.ps1 logs
./scripts/stack.ps1 status
./scripts/stack.ps1 down
```

Use the console or authenticated API to revoke one agent before using the fleet
stop. A fleet stop increments the fleet epoch, releases outstanding holds, and
invalidates leases issued under the previous epoch. Resuming allows only newly
authorized work; it never revives an old lease.

## Policy change

1. Create a draft and record its purpose.
2. Validate the Rego source.
3. Dry-run representative allow, deny, and review inputs.
4. Compare the draft with the active version.
5. Publish using an operator identity.
6. Watch policy failure, decision, latency, and denial-rate panels.
7. Roll back to the prior version if behavior differs from the reviewed cases.

Never edit the active policy file inside a running container as a production
change mechanism.

## Database migration

The Compose migration job runs before seed and application startup. For a
manually managed database:

```powershell
$env:INTENTGUARD_DATABASE_URL = 'postgresql://...'
.venv/Scripts/python.exe scripts/migrate.py
```

Migrations are ordered and recorded in `schema_migrations`. Back up the
database before a production migration and test restore before relying on that
backup.

## Capacity signals

Investigate sustained increases in policy p95/p99 latency, authorization 5xx,
OPA errors, database pool saturation, rate-limit rejections, pending approvals,
outstanding reservations, or connector circuit-open events. The resource bounds
documented in `abuse-controls.md` intentionally reject excess work instead of
allowing unbounded queues.

## Recovery and reset

Restarting application containers is safe because authoritative state is in
PostgreSQL. Do not run `reset` during incident diagnosis: it deletes local
volumes. For disposable local data only:

```powershell
./scripts/stack.ps1 reset
```

After recovery, verify readiness, authorize a low-value test action, confirm
connector commit, inspect its audit events, and verify the audit checkpoint.
Use `incident-response.md` for security or integrity events.
