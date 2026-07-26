# IntentGuard API contract

The FastAPI application is the shared boundary between the governance backend
and operator dashboard. During local development it runs at
`http://127.0.0.1:8000`; interactive OpenAPI documentation is available at
`/docs`.

## Action lifecycle

```text
POST /v1/actions/authorize
  -> deny or review: display the decision and findings
  -> allow: receive reservation_id and lease_id

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
| POST | `/v1/agents` | Register or update an agent profile |
| POST | `/v1/intents` | Register authenticated customer intent |
| POST | `/v1/actions/authorize` | Evaluate policy and reserve budget atomically |
| POST | `/v1/reservations/{id}/commit` | Consume held budget after success |
| POST | `/v1/reservations/{id}/release` | Return held budget after failure |
| POST | `/v1/agents/{id}/revoke` | Revoke an agent and release its holds |
| POST | `/v1/agents/{id}/restore` | Restore a revoked registered agent |
| POST | `/v1/fleet/stop` | Stop the fleet and invalidate outstanding leases |
| POST | `/v1/fleet/resume` | Resume new evaluations at the current epoch |
| GET | `/v1/audit/events` | Return the ordered audit stream |

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

The gateway allows the Vinext dashboard at `localhost:3000` and
`127.0.0.1:3000` by default. Vite origins on port 5173 remain supported.
Override the complete allowlist with a comma-separated environment variable:

```text
INTENTGUARD_CORS_ORIGINS=https://operator.example.com,https://review.example.com
```
