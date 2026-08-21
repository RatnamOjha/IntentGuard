# IntentGuard API contract

The FastAPI application is the shared boundary between the governance backend
and operator dashboard. During local development it runs at
`http://127.0.0.1:8000`; interactive OpenAPI documentation is available at
`/docs`.

## Action lifecycle

```text
POST /v1/actions/authorize
  -> deny: display the decision and findings
  -> review: create a pending operator approval
  -> allow: receive reservation_id and lease_id

Operator resolves a review
  -> approve: receive a fresh reservation_id and lease_id
  -> reject: seal a final denial in the audit chain

Protected connector executes the approved action
  -> success: POST /v1/reservations/{id}/commit
  -> failure: POST /v1/reservations/{id}/release
```

The frontend should use stable finding `code` values for filters and finding
`message` values for operator-facing explanations.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Service health |
| GET | `/v1/fleet/status` | Fleet stop state and current epoch |
| GET | `/v1/agents` | Agent permission, status, and live budget snapshots |
| POST | `/v1/agents` | Register or update an agent profile |
| PUT | `/v1/agents/{id}/policy` | Publish a versioned permission and budget envelope |
| POST | `/v1/intents` | Register authenticated customer intent |
| POST | `/v1/actions/authorize` | Evaluate policy and reserve budget atomically |
| POST | `/v1/reservations/{id}/commit` | Consume held budget after success |
| POST | `/v1/reservations/{id}/release` | Return held budget after failure |
| POST | `/v1/agents/{id}/revoke` | Revoke an agent and release its holds |
| POST | `/v1/agents/{id}/restore` | Restore a revoked registered agent |
| POST | `/v1/fleet/stop` | Stop the fleet and invalidate outstanding leases |
| POST | `/v1/fleet/resume` | Resume new evaluations at the current epoch |
| GET | `/v1/approvals` | Return the operator approval queue |
| POST | `/v1/approvals/{id}/approve` | Approve and issue a fresh bounded lease |
| POST | `/v1/approvals/{id}/reject` | Reject and record the final denial |
| GET | `/v1/audit/events` | Return the ordered audit stream |
| GET | `/v1/audit/status` | Verify the SHA-256 chain and return its head |
| POST | `/v1/demo/bootstrap` | Idempotently initialize the dashboard sandbox |
| POST | `/v1/demo/reset` | Reset the deterministic dashboard sandbox |
| GET | `/v1/demo/benchmark` | Run 27 acceptance controls plus in-process engine latency, concurrency, and audit checks |
| POST | `/v1/demo/benchmark/authorize-probe` | Exercise an isolated authorization path for browser-to-FastAPI round-trip measurement |

## Authorization example

Request:

```json
{
  "request_id": "request-001",
  "agent_id": "travel-01",
  "action": "book_flight",
  "amount": "15000",
  "currency": "INR",
  "intent_id": "intent-001",
  "risk_score": 20,
  "attributes": {"refundable": true}
}
```

Allowed response shape:

```json
{
  "decision": {
    "request_id": "request-001",
    "decision": "allow",
    "findings": [{
      "code": "POLICY_SATISFIED",
      "message": "The action satisfies all active runtime policies.",
      "blocking": false
    }],
    "remaining_daily_budget": "15000",
    "policy_version": "2026.07"
  },
  "reservation": {
    "reservation_id": "res_...",
    "status": "held",
    "expires_at": "2026-07-27T10:00:30Z"
  },
  "lease": {
    "lease_id": "lease_...",
    "fleet_epoch": 0,
    "expires_at": "2026-07-27T10:00:30Z"
  }
}
```

## Error behavior

- `404`: reservation does not exist.
- `409`: request ID conflicts, lease is invalid, or reservation is not held.
- `422`: request body failed validation.

Policy denials and review decisions are valid `200` responses so the dashboard
can display their structured findings.

## Browser origins

The gateway allows the operator console on ports `3000` and `3001` for both
`localhost` and `127.0.0.1` by default. Vite origins on port 5173 remain
supported. Override the complete allowlist with a comma-separated environment
variable:

```text
INTENTGUARD_CORS_ORIGINS=https://operator.example.com,https://review.example.com
```
