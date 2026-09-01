# Production observability

IntentGuard instruments the governance gateway and protected booking connector
with the same request context. Every response carries `x-correlation-id` and
`x-trace-id`. Incoming W3C `traceparent` headers are continued and outbound
gateway/connector HTTP calls propagate the active context.

## Local stack

Start Prometheus, Grafana, and Tempo:

```bash
docker compose -f docker-compose.observability.yml up -d
```

Start the IntentGuard demo with `OTEL_EXPORTER_OTLP_ENDPOINT` set to
`http://127.0.0.1:4318`, as shown in `.env.example`. Open:

- Grafana: `http://127.0.0.1:3002` (`admin` / `intentguard` locally)
- Prometheus: `http://127.0.0.1:9090`
- Tempo API: `http://127.0.0.1:3200`
- Gateway metrics: `http://127.0.0.1:8000/metrics`
- Connector metrics: `http://127.0.0.1:8100/metrics`

The provisioned **IntentGuard Operational Overview** dashboard includes
authorization decisions, gateway p50/p95/p99, policy p95, approval age,
connector results and failures, lease/budget failures, LLM latency and tokens,
revocation propagation, and HTTP 5xx rate. Grafana also provisions Tempo for
trace lookup.

Stop only the monitoring stack with:

```bash
docker compose -f docker-compose.observability.yml down
```

## Request and trace fields

Structured JSON request logs and spans include fields when appropriate:

- correlation and OpenTelemetry trace IDs;
- authenticated subject, agent, and customer IDs;
- action request and customer intent IDs;
- policy version and decision;
- reservation and lease IDs;
- connector result;
- HTTP route, status, and latency.

Request bodies, authorization headers, model prompts, lease tokens, and intent
signatures are deliberately excluded. Business identifiers appear in logs and
spans, not Prometheus labels, to avoid unbounded metric cardinality.

## Metrics

| Metric | Purpose |
|---|---|
| `intentguard_authorization_requests_total` | Allow, deny, and review decisions |
| `intentguard_policy_evaluation_duration_seconds` | Policy latency histogram |
| `intentguard_http_request_duration_seconds` | Per-service/route API histogram for p50/p95/p99 |
| `intentguard_budget_reservation_failures_total` | Budget-cap reservation failures |
| `intentguard_approval_queue_oldest_age_seconds` | Live age of the oldest pending approval |
| `intentguard_lease_expirations_total` | Expired leases rejected at commit |
| `intentguard_connector_requests_total` | Connector outcomes |
| `intentguard_connector_failures_total` | Connector failure reasons |
| `intentguard_llm_duration_seconds` | Provider/model/status LLM latency |
| `intentguard_llm_tokens_total` | Input and output token usage |
| `intentguard_revocation_propagation_seconds` | Time to apply revocation and release holds |
| `intentguard_abuse_rejections_total` | Rate-limit and dependency-related abuse rejections |

Prometheus histograms are intentional: p50, p95, and p99 are calculated with
`histogram_quantile` in PromQL rather than estimated inside the application.
