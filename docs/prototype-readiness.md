# Prototype submission readiness

This checklist maps the critical pre-submission review directly to working
prototype evidence.

| Priority | Implemented evidence | Verification |
|---|---|---|
| Policy and budget configuration | Operator console edits permitted actions, per-action limit, daily budget, and active status; FastAPI publishes a new policy version and appends `policy.updated` | `test_operator_can_update_agent_policy`, `test_operator_can_publish_agent_policy` |
| Protected connector boundary | Stale-lease scenario authorizes an action, changes the fleet epoch, and proves connector commit is rejected | `test_stale_lease_is_rejected_and_audited` |
| Dynamic decision trace | Identity, intent, permission, budget, risk, and connector stages render pass, review, or fail from backend finding codes | Frontend build, lint, and render test |
| No misleading placeholders | Navigation scrolls to functional workspaces, audit export downloads JSON evidence, and integrations are labeled running-now or production-roadmap | Frontend build and render test |
| Reliable startup | One-command macOS/Linux and Windows launchers use the correct source path, reload scope, CORS defaults, and pinned Python dependencies | `scripts/start-demo.*`, shell syntax check |
| Measured evaluation evidence | Backend runs 30 deterministic acceptance controls and in-process engine percentiles; the dashboard separately measures browser-to-FastAPI p50/p95/p99 latency, a concurrent budget race, and audit integrity | `test_benchmark_is_reproducible_and_safe`, `test_authorization_probe_uses_isolated_full_policy_path` |
| Adversarial resilience | Six attack classes are driven against the real engine and the real gateway: intent tampering, replay after revocation, budget time-of-check/time-of-use, a 50-iteration concurrent spend race, fleet-epoch bypass, and audit-chain mutation, deletion, and reordering | `tests/test_adversarial.py` |
| Documented limits | Defences, non-defences, trust boundaries, and design assumptions are written down rather than implied | [`docs/threat-model.md`](threat-model.md) |
| Readability | Findings, event rows, metrics, configuration controls, and evidence labels use presentation-legible sizing and responsive layouts | Frontend production build |
| Submission demo | A timed 90-second narration, interaction sequence, and four-image capture list are prepared separately from the repository | Submission recording checklist |

## Honest prototype boundary

The current executable system uses FastAPI, a deterministic Python policy
engine, and in-memory state. The dashboard labels OPA/Rego, PostgreSQL, Redis,
Prometheus, Splunk, KMS-backed signing, Docker Compose, and AWS as production
roadmap components. It does not claim those components are already running.

## Final human submission steps

1. Run `./scripts/test-all.sh`.
2. Run `./scripts/start-demo.sh` and reset the sandbox.
3. Record the prepared 90-second demonstration flow.
4. Capture the four listed screenshots.
5. Export the audit evidence JSON from the dashboard.
6. Upload the deck, demo video, screenshots, and repository link.
