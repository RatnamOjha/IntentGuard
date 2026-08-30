# Load-test results

## Scope and provenance

This page reports checked-in, reproducible measurements; it is not a production
capacity claim. The raw historical HTTP benchmark is in
`docs/evidence/benchmark-2026-08-22.txt`. The current unified run is in
`docs/evidence/evaluation-2026-08-30.json` and records its own environment.

## End-to-end HTTP baseline

The benchmark sent 500 authorization requests to a real local Uvicorn process
at concurrency 16. It includes loopback networking, HTTP parsing, request
validation, the authorization path, and serialization.

| Metric | Result |
| --- | ---: |
| p50 | 6.85 ms |
| p95 | 9.62 ms |
| p99 | 13.59 ms |
| Maximum | 17.13 ms |
| Throughput | 2,002 requests/s |

Environment: Apple M3, 8 cores, 16 GB RAM, macOS 26.2, CPython 3.12.2.

## Step 11 component measurements

| Scope | Requests | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: |
| In-process policy engine | 1,000 | 0.0486 ms | 0.0698 ms | 0.0890 ms |
| Concurrent authorization | 500 | 0.0475 ms | 0.0797 ms | 0.4173 ms |
| Signed lease verification, provider call, and commit | 100 | 0.2281 ms | 0.2711 ms | 0.3826 ms |
| Review routing and queue insertion | 200 | 0.0857 ms | 0.1111 ms | 0.1540 ms |

Single-thread policy throughput was 24,032 decisions/s and concurrent
authorization throughput was 12,456.8 decisions/s on the recorded Windows
evaluation host. Cross-machine comparisons are directional only.

## Correctness under concurrency

Twenty simultaneous INR 2,000 requests targeted one INR 10,000 daily cap.
Exactly five were allowed, INR 10,000 was reserved, and observed overspend was
zero. Separate PostgreSQL contract tests use multiple operating-system
processes to prove that the database—not a Python lock—holds the shared cap.

## Method

- Warm application process; local machine; monotonic high-resolution timers.
- Percentiles are calculated from per-request samples.
- Throughput uses a separate loop so per-sample timer calls do not distort it.
- Connector timing includes lease verification, in-memory idempotency, mock
  provider execution, and reservation commit.
- Approval timing includes risk routing and queue insertion.

## Limitations

- The committed HTTP test is loopback, without TLS, remote JWKS, production
  network latency, PostgreSQL, or a remote OPA service.
- The unified component run uses in-memory repositories to avoid load-testing
  an arbitrary database selected by an environment variable.
- The mock provider does not represent a third-party latency distribution.
- No soak, autoscaling, multi-region, or noisy-neighbor test has been run.
- These numbers should be used to reproduce regressions, not to promise a
  production service-level objective.

## Reproduce

```powershell
intentguard-evaluate `
  --output-json docs/evidence/evaluation-local.json `
  --output-markdown docs/evidence/evaluation-local.md

python -m intentguard.benchmark
```

Use a dedicated disposable PostgreSQL database for the multiprocess contention
suite; never point a load test at production by convenience.
