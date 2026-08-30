# Rate limiting and abuse controls

IntentGuard applies bounded controls before work can accumulate indefinitely.
Defaults are configured in `.env.example` and can be tightened independently
for agent, customer, operator/reviewer, and connector traffic.

## Request limits

- Authenticated sliding windows are keyed by verified agent ID, customer ID,
  or token subject—not by caller-supplied body fields.
- Successful responses expose `X-RateLimit-Limit` and
  `X-RateLimit-Remaining`; rejections return `429` and `Retry-After`.
- `INTENTGUARD_REDIS_URL` selects an atomic Redis sorted-set/Lua limiter shared
  across replicas. A Redis outage fails closed with `503`.
- Without Redis, tests and offline demos use the thread-safe in-process limiter.
- Request bodies are buffered only up to `INTENTGUARD_MAX_REQUEST_BODY_BYTES`;
  oversized fixed-length or streamed bodies return `413` before authentication
  or Pydantic parsing.

## Stateful capacity controls

The policy engine refuses a new authorization when an agent already has the
configured maximum number of held reservations. The stable finding code is
`OUTSTANDING_RESERVATION_LIMIT`.

High-risk requests fail closed with `APPROVAL_QUEUE_FULL` when the pending
human-review queue reaches capacity. Existing approvals remain resolvable, so
operators can drain the queue without accepting more work.

## Connector failure storms

The protected connector opens its provider circuit after a configurable number
of consecutive timeouts or failures. While open, new provider calls fail fast,
their budget reservations are released, and no provider request is attempted.
After the recovery interval, exactly one half-open probe is admitted. Success
closes the circuit; failure reopens it.

HTTP calls from the connector back to the governance gateway have an explicit
timeout. The LLM, JWKS client, PostgreSQL pools, and OPA subprocess already have
their own bounded timeouts.

## Audit pagination and retention

`GET /v1/audit/events` accepts `after_sequence` and `limit`. Pages are capped
by `INTENTGUARD_MAX_AUDIT_PAGE_SIZE`; `X-Next-Sequence` is returned when more
events remain.

Audit events become archive-eligible after
`INTENTGUARD_AUDIT_ARCHIVE_AFTER_DAYS`. IntentGuard never deletes them in place:
removing entries would invalidate the tamper-evident chain. The active policy is
available from `GET /v1/audit/retention`; a deployment must copy eligible
records and their checkpoints to immutable archive storage before lifecycle
management outside the gateway.
