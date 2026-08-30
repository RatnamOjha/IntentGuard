# IntentGuard API contract

The FastAPI application is the shared boundary between the governance backend
and operator dashboard. During local development it runs at
`http://127.0.0.1:8000`; interactive OpenAPI documentation is available at
`/docs`.

## Authentication

All `/v1` routes require `Authorization: Bearer <RS256 JWT>`; `/health` remains
public. Tokens must carry the configured issuer and audience, a live `exp`, a
`sub`, and one of the supported roles. Agent tokens also carry `agent_id` and
`customer_id`; customer tokens carry `customer_id`.

| Boundary | Required role | Verified ownership |
|---|---|---|
| Customer intent creation and agent chat | `customer` | `customer_id` claim |
| Action authorization and reservation completion | `agent` | `agent_id` and `customer_id` claims |
| Agent policy and fleet operations | `operator` | operator is JWT `sub` |
| Approval queue and decisions | `reviewer` | reviewer is JWT `sub` |
| Connector fleet/key lookup and commit/release | `connector` | connector is JWT `sub` |
| Demo reset and benchmarks | `admin` | administrative role |

`admin` may access every role boundary. A reviewer cannot resolve an action
whose verified submitter has the same `sub`.

`GET /metrics` is also public for the locally configured Prometheus scraper.
Production deployments should restrict it at the network boundary. Every HTTP
response carries `x-correlation-id` and `x-trace-id`; callers may supply a
bounded `x-correlation-id` and W3C `traceparent` header for end-to-end tracing.

Authenticated routes return `X-RateLimit-Limit` and
`X-RateLimit-Remaining`. Exhausted windows return `429` with `Retry-After`;
distributed-limiter outages return `503` and fail closed. Bodies over the
configured byte limit return `413`.

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

## Signed intent registration

The customer submits the exact passport produced by its consent service. The
gateway never rewrites signed fields before verification:

```json
{
  "intent_id": "intent-001",
  "customer_id": "customer-01",
  "agent_id": "travel-01",
  "action": "book_hotel",
  "max_amount": "18000",
  "currency": "INR",
  "required_attributes": {"city": "BOM", "refundable": true},
  "issuer": "https://consent.example",
  "audience": "intentguard-api",
  "issued_at": "2026-08-27T10:00:00Z",
  "not_before": "2026-08-27T10:00:00Z",
  "expires_at": "2026-08-27T11:00:00Z",
  "nonce": "nonce-7d8f...",
  "key_id": "consent-2026-08",
  "signature": "base64url-ed25519-signature"
}
```

Invalid signatures, keys, claims, or time windows return `422`; a consumed
nonce returns `409`. Public keys are raw Ed25519 keys encoded with unpadded
base64url.

## Protected booking connector

The separate connector service listens on `http://127.0.0.1:8100` by default.
`POST /v1/bookings` accepts the booking fields, `reservation_id`, and the
`lease_token` returned by authorization. The connector independently verifies
the token signature, expiry, audience, key status, request/agent/action/amount/
currency bindings, and live fleet epoch before provider execution. Exact
retries return the stored response; conflicting reuse returns `409`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Service health |
| GET | `/v1/fleet/status` | Fleet stop state and current epoch |
| GET | `/v1/agents` | Agent permission, status, and live budget snapshots |
| POST | `/v1/agents` | Register or update an agent profile |
| PUT | `/v1/agents/{id}/policy` | Publish a versioned permission and budget envelope |
| GET | `/v1/policies` | List Rego drafts and published/retired versions |
| POST | `/v1/policies/validate` | Compile candidate Rego without activation |
| POST | `/v1/policies/dry-run` | Evaluate candidate Rego without state mutation |
| POST | `/v1/policies/drafts` | Store a validated candidate version |
| POST | `/v1/policies/{id}/publish` | Atomically activate a validated version |
| POST | `/v1/policies/{id}/rollback` | Reactivate a previously published version |
| POST | `/v1/policies/compare` | Compare two versions over supplied input cases |
| POST | `/v1/intents` | Register authenticated customer intent |
| POST | `/v1/agent/message` | Convert customer text to a governed proposal and decision |
| GET | `/v1/intent-keys` | List registered consent-service public keys |
| POST | `/v1/intent-keys` | Register/rotate an Ed25519 public key (admin) |
| POST | `/v1/intent-keys/{id}/revoke` | Revoke an intent signing key (admin) |
| POST | `/v1/actions/authorize` | Evaluate policy and reserve budget atomically |
| POST | `/v1/reservations/{id}/commit` | Consume held budget after success |
| POST | `/v1/reservations/{id}/release` | Return held budget after failure |
| POST | `/v1/connectors/reservations/{id}/commit` | Connector-only final commit |
| POST | `/v1/connectors/reservations/{id}/release` | Connector-only failure release |
| POST | `/v1/agents/{id}/revoke` | Revoke an agent and release its holds |
| POST | `/v1/agents/{id}/restore` | Restore a revoked registered agent |
| POST | `/v1/fleet/stop` | Stop the fleet and invalidate outstanding leases |
| POST | `/v1/fleet/resume` | Resume new evaluations at the current epoch |
| GET | `/v1/approvals` | Return the operator approval queue |
| POST | `/v1/approvals/{id}/approve` | Approve and issue a fresh bounded lease |
| POST | `/v1/approvals/{id}/reject` | Reject and record the final denial |
| GET | `/v1/audit/events` | Return the ordered audit stream |
| GET | `/v1/audit/retention` | Describe append-only archive eligibility policy |
| GET | `/v1/audit/status` | Verify the SHA-256 chain and return its head |
| POST | `/v1/demo/bootstrap` | Idempotently initialize the dashboard sandbox |
| POST | `/v1/demo/reset` | Reset the deterministic dashboard sandbox |
| GET | `/metrics` | Prometheus exposition for gateway operational metrics |
| GET | `/v1/demo/benchmark` | Run 27 acceptance controls plus in-process engine latency, concurrency, and audit checks |
| POST | `/v1/demo/benchmark/authorize-probe` | Exercise an isolated authorization path for browser-to-FastAPI round-trip measurement |

## Authorization example

## Agent message trace

`POST /v1/agent/message` returns the proposal and authorization result plus a
safe `trace` object. The trace contains `trace_id`, provider, model,
`prompt_version`, token counts, estimated cost, latency, attempt count, status,
and a one-way request fingerprint. It deliberately excludes raw customer text
and provider credentials. A malformed or excessive tool-call response is a
controlled refusal and never reaches authorization.

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
- `413`: request body exceeds the configured maximum.
- `429`: authenticated principal exceeded its rate window.
- `409`: request ID conflicts, lease is invalid, or reservation is not held.
- `503`: a fail-closed policy or distributed rate-limit dependency is unavailable.
- `422`: request body failed validation.

Audit events are cursor-paginated with `after_sequence` and `limit`. A response
with more data carries `X-Next-Sequence`; clients pass that value as the next
`after_sequence`.

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
