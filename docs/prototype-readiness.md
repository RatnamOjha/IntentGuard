# Prototype submission readiness

This checklist maps the critical pre-submission review directly to working
prototype evidence.

| Priority | Implemented evidence | Verification |
|---|---|---|
| Authentication and identity | RS256 JWT validation against JWKS, role dependencies, agent/customer ownership, verified audit actors, and separation of duties | `test_auth.py`, `test_api_auth.py` |
| Policy and budget configuration | Operator console edits stateful envelopes; OPA/Rego versions support validate, dry-run, publish, compare, rollback, and explainable findings | `test_policy_as_code.py`, native `opa test policies` matrix |
| Protected connector boundary | Standalone FastAPI connector independently verifies signed leases, field bindings, expiry and fleet epoch; persists idempotency; releases holds on provider timeout/failure | `test_booking_connector.py` |
| Dynamic decision trace | Identity, intent, permission, budget, risk, and connector stages render pass, review, or fail from backend finding codes | Frontend build, lint, and render test |
| No misleading placeholders | Navigation scrolls to functional workspaces, audit export downloads JSON evidence, and integrations are labeled running-now or production-roadmap | Frontend build and render test |
| Reliable startup | One-command macOS/Linux and Windows launchers use the correct source path, reload scope, CORS defaults, and pinned Python dependencies | `scripts/start-demo.*`, shell syntax check |
| Measured evaluation evidence | A unified harness runs 44 named correctness, security, and reliability scenarios, 31 deterministic acceptance controls, 12 LLM-containment cases, budget races, and p50/p95/p99 probes for policy, concurrent authorization, protected connector execution, and approval routing | `evaluations/suite.json`, `tests/test_evaluation.py`, `docs/evidence/evaluation-2026-08-30.json` |
| LLM reliability and containment | OpenAI Responses, xAI/Groq, and offline planners share strict proposal validation, one allowlisted tool, bounded retries/timeouts, redacted trace telemetry, and a 12-scenario adversarial evaluation with zero policy bypass | `tests/test_agent.py`, `tests/test_llm_eval.py`, `docs/evidence/llm-evaluation-2026-08-29.json` |
| Production observability | W3C OpenTelemetry propagation, correlation headers, structured JSON logs, low-cardinality Prometheus metrics, Tempo trace storage, and a provisioned Grafana operations dashboard cover the gateway, policy, approvals, leases, LLM, revocation, and protected connector | `tests/test_observability.py`, `docker-compose.observability.yml`, `docs/observability.md` |
| Abuse resistance | Verified-identity rate windows with atomic Redis support, request-body caps, outstanding-reservation and approval-queue bounds, audit pagination/retention, dependency timeouts, and a half-open connector circuit breaker fail closed under floods and outages | `tests/test_abuse.py`, `test_timeout_storm_opens_circuit_and_fails_fast`, `docs/abuse-controls.md` |
| Reproducible deployment | Health-gated Compose runs PostgreSQL, Redis, OPA, Keycloak, migrations, seed data, gateway, connector, Tempo, Prometheus, Grafana, and frontend; CI covers quality, tests, dependency audits, Semgrep, Bandit, builds, and Trivy; AWS has an ECS/Fargate target | `docker-compose.yml`, `.github/workflows/ci.yml`, `deploy/aws/ecs-fargate.yml`, `docs/deployment.md` |
| Portfolio operations package | A 90-second demo, three architectural decisions, operator runbook, incident playbooks, load-test provenance, evaluation methodology, contribution policy, and a two-minute README map implementation claims to evidence and honest limits | `docs/demo-script.md`, `docs/adr/`, `docs/runbook.md`, `docs/incident-response.md`, `docs/load-test-results.md`, `docs/evaluation-methodology.md`, `CONTRIBUTING.md` |
| Adversarial resilience | Eight attack classes are driven against the real engine and the real gateway: intent tampering, replay after revocation, budget time-of-check/time-of-use, a 50-iteration concurrent spend race, fleet-epoch bypass, self-reported risk, cross-customer intent reuse, and audit-chain mutation, deletion, reordering, and truncation | `tests/test_adversarial.py` |
| Documented limits | Defences, non-defences, trust boundaries, and design assumptions are written down rather than implied | [`docs/threat-model.md`](threat-model.md) |
| Readability | Findings, event rows, metrics, configuration controls, and evidence labels use presentation-legible sizing and responsive layouts | Frontend production build |
| Submission demo | A timed 90-second narration, interaction sequence, and four-image capture list are prepared separately from the repository | Submission recording checklist |

## Honest prototype boundary

The current executable system uses FastAPI, OPA/Rego policy decisions with Python stateful orchestration,
engine, selectable in-memory/PostgreSQL state, Ed25519-signed customer intent,
and a protected booking connector with signed execution leases. OpenTelemetry,
Prometheus, Grafana, Tempo, Redis, Keycloak, PostgreSQL, and the application
services are locally reproducible through Docker Compose. The dashboard labels
Splunk, KMS-managed private keys, and a live AWS environment as production
roadmap components. The checked-in Fargate template is deployment-ready but is
not represented as a public deployment without account-specific evidence.

## Final human submission steps

1. Run `./scripts/test-all.sh`.
2. Run `./scripts/start-demo.sh` and reset the sandbox.
3. Record the prepared 90-second demonstration flow.
4. Capture the four listed screenshots.
5. Export the audit evidence JSON from the dashboard.
6. Upload the deck, demo video, screenshots, and repository link.
