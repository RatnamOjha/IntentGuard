# IntentGuard incident response

## Priorities

1. Prevent new unsafe execution.
2. Preserve audit, trace, database, and identity-provider evidence.
3. Reconcile every outstanding reservation and external provider action.
4. Restore service with fresh authority rather than reviving stale leases.

## Severity guide

| Severity | Example | Initial response target |
| --- | --- | --- |
| SEV-1 | Suspected unauthorized execution, signing-key compromise, audit-chain failure, or budget overspend | Immediate fleet stop and incident command |
| SEV-2 | OPA/database/identity outage, connector failure storm, or widespread authorization errors | Contain affected path and restore dependency |
| SEV-3 | Elevated latency, isolated agent fault, or growing approval queue | Revoke or throttle affected scope and investigate |

## Containment

- Suspected single-agent compromise: revoke that agent and preserve its token,
  request, lease, connector, and audit identifiers.
- Broad or unknown scope: activate the fleet stop. This changes the fleet epoch
  so previously issued leases are rejected.
- Signing-key compromise: stop the fleet, revoke the affected public key,
  rotate signing material, restart signers, and require fresh authorization.
- Policy tampering: stop publication, identify the last reviewed version, and
  use the policy rollback endpoint. Keep the rejected and active sources.
- Connector failure storm: leave its circuit breaker open, confirm reservations
  were released, and do not bypass lease verification to restore throughput.

## Evidence collection

Record UTC start time, reporter, affected subjects, request and reservation IDs,
policy version, fleet and revocation epochs, lease key ID, deployment revision,
and every containment action. Preserve:

- PostgreSQL snapshot and migration version;
- gateway and connector structured logs;
- Tempo traces and Prometheus/Grafana time ranges;
- Keycloak authentication and admin events;
- OPA version and active policy hash;
- audit events, checkpoint, and first invalid link if verification failed;
- provider references and reconciliation output.

Do not reset local volumes or rewrite audit records during collection.

## Scenario procedures

### Budget overspend or reservation mismatch

Stop the affected agent or fleet, prevent further connector commits, compare
committed and reserved totals with provider records, and identify request-ID
reuse or duplicate execution. Reconcile conservatively; never increase a cap to
make an invariant violation disappear.

### Database unavailable

Confirm `/health/ready` reports `database`, inspect database health and pool
capacity, and keep gateway replicas out of service until PostgreSQL is
authoritative again. Restart stateless services only after database recovery.

### Redis unavailable

Distributed rate limiting fails closed. Restore Redis or deliberately switch to
an approved degraded configuration only after assessing abuse exposure; do not
silently fall back per replica in a multi-instance environment.

### OPA unavailable

Authorization fails closed before budget reservation. Restore the pinned OPA
binary/service and run the native policy matrix before returning traffic.

### Audit-chain verification failure

Treat it as evidence-integrity loss. Stop mutation of the affected store,
capture the checkpoint and first invalid link, compare replicas/backups, and do
not declare the incident resolved by recomputing hashes over modified history.

## Recovery and closure

Before resuming, verify dependency readiness, active policy version, key set,
fleet epoch, reservation totals, connector idempotency, and audit integrity.
Run a low-value canary through authorization and connector commit. Document
timeline, root cause, customer or financial impact, detection gap, corrective
actions, owners, and due dates. Add a regression scenario to the unified
evaluation suite when technically possible.
