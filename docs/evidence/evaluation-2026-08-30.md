# IntentGuard evaluation evidence

Generated: `2026-08-29T19:01:13.374520+00:00`  
Overall status: **PASSED**

## Scenario results

| Category | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Correctness | 12 | 0 | 0 |
| Security | 19 | 0 | 0 |
| Reliability | 13 | 0 | 0 |

Deterministic acceptance controls: **31**  
LLM containment scenarios: **12**  
Maximum observed budget overspend: **0**

## Performance

| Scope | Requests | p50 ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: | ---: |
| in_process_policy_engine | 1000 | 0.0486 | 0.0698 | 0.089 |
| concurrent_in_process_authorization | 500 | 0.0475 | 0.0797 | 0.4173 |
| signed_lease_verify_provider_commit | 100 | 0.2281 | 0.2711 | 0.3826 |
| review_routing_and_queue_insert | 200 | 0.0857 | 0.1111 | 0.154 |

Single-thread throughput: **24032.0 decisions/s**  
Concurrent throughput: **12456.8 decisions/s**  
Audit chain verified: **true**

Database contention is intentionally measured by the isolated PostgreSQL integration race suite, not against an arbitrary configured database.
