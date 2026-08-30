# Evaluation methodology

## Objective

The evaluation asks four different questions and reports them separately:

1. Correctness: does the system make the expected policy, intent, budget,
   approval, and lease decision?
2. Security: do injection, spoofing, replay, cross-customer, policy-tampering,
   and direct-connector attempts fail?
3. Reliability: does authority remain safe across restart, dependency outage,
   timeout, duplication, and concurrency?
4. Performance: what latency and throughput does each measured boundary show?

Passing a policy test is not a load test, and low latency is not a security
result. The report preserves that distinction.

## Scenario sources

`evaluations/suite.json` is the reviewable manifest of named correctness,
security, and reliability scenarios. Each entry maps one requirement to one
existing unittest ID. Running tests individually makes duration, skip, failure,
and traceback attribution explicit.

The harness also incorporates:

- 31 deterministic policy boundary and adversarial acceptance controls from
  `intentguard.benchmark`;
- 12 deterministic LLM proposal/containment cases from
  `evaluations/llm_cases.json`;
- a concurrent budget race and audit-chain verification;
- policy, concurrent authorization, protected connector, and approval queue
  latency probes.

## Pass criteria

The report fails when any named scenario fails, any acceptance control fails,
an LLM case differs from its expected proposal or decision, or the budget race
overspends. A missing optional dependency produces `passed_with_skips`, not an
unqualified pass. The committed evidence run has no manifest skips.

Security-critical expected outcomes are refusals, not exceptions hidden by the
runner. For example, an OPA outage must deny before budget reservation, direct
connector access must return an authentication failure, and replay must not
create a second provider action.

## Performance calculation

Every timed probe records milliseconds from a monotonic high-resolution clock.
p50, p95, and p99 use the sorted nearest observed sample. Throughput is requests
divided by total elapsed wall time. The report includes request count,
concurrency, scope, environment, and maximum where applicable.

Database contention is deliberately excluded from the generic runner. It is
measured by the dedicated PostgreSQL multiprocess tests so an evaluator cannot
load-test a database merely because `INTENTGUARD_DATABASE_URL` is present.

## Reproducibility

```powershell
uv sync --all-extras --locked
./scripts/install-opa.ps1
intentguard-evaluate `
  --iterations 1000 `
  --concurrent-requests 500 `
  --concurrency 16 `
  --connector-iterations 100 `
  --approval-iterations 200 `
  --output-json docs/evidence/evaluation-local.json `
  --output-markdown docs/evidence/evaluation-local.md
```

The JSON file is the machine-readable artifact. The Markdown file is rendered
from that same in-memory report, preventing hand-maintained metric drift.

## Interpretation and limits

- Deterministic offline LLM cases test containment and parsing, not the quality
  distribution of a hosted model across changing versions.
- In-memory timing isolates implementation overhead; it does not estimate
  remote database, OPA, provider, or identity latency.
- A passing suite increases confidence in enumerated controls. It does not prove
  absence of vulnerabilities.
- New incidents, policy features, and connector types should add manifest cases
  before their evidence is considered complete.
