# Required refund claims — verification, 21 October 2026

Scope: ADR 008 on `fix/required-refund-claims`. Local checks, not a deployed
release or a live-model evaluation. No external payment was made.

## Results

| Check | Observed result |
|---|---|
| Full backend suite, dedicated PostgreSQL database with migrations 0001–0006 and OPA required | 393 tests run in 19.868 seconds; 391 passed, 2 skipped |
| New required-claim tests within that suite | 23 tests, including both evaluators and older published Rego |
| Native `opa test policies --verbose --fail-on-empty` | 8/8 passed |
| Unified evaluation, including three new refund-context scenarios | 47/47 passed: 13 correctness, 20 security, 14 reliability |
| Evaluation acceptance controls / offline LLM containment | 31/31 and 12/12 passed; observed overspend 0; audit verified |
| Python fatal-error lint and diff whitespace check | Passed |
| Frontend `tsc --noEmit` | Passed |
| Existing documentation/link checks | 2/2 passed |

The skips are the deliberate evaluation-runner fixture and the opt-in 50-round
torn-read reproducer. PostgreSQL integration and ordinary multiprocess tests
ran; they were not skipped. The new tests first demonstrated the omission
against the previous implementation before the fix was applied.

## Real HTTP check

A local Uvicorn server on an ephemeral loopback port used the real authenticated
HTTP handlers and OPA with in-memory state and mocked model transport:

```text
HTTP direct missing claim: DENY / CLAIM_REQUIRED / no lease or reservation
HTTP model chat photoless defect: DENY / shipping_refund alternative
HTTP model chat with photo citation: ALLOW / internal budget COMMITTED
HTTP audit verification: true
```

This verifies the chat proposal-to-policy wiring and internal budget lifecycle.
It does not verify an external refund provider, photo authenticity, a hosted
model's tool-schema acceptance, or a production deployment.

## Test setup issue found during verification

The first full run against a newly migrated disposable database failed the HTTP
benchmark with 403. Its default test subject (`user-01`) had no organization
membership. `measure_http_round_trip` constructs an environment-configured app,
so a configured database enables membership enforcement even though its spend
probe uses isolated state.

The same test failed on unmodified `79debd4` in a separate detached worktree.
For this verification, the disposable database was seeded with an admin membership
for that test subject. The full suite then passed. No authorization behavior was
weakened and no benchmark code was changed. The benchmark fixture's dependence on
database setup remains a separate open test-harness issue.

## Reproduction

Use a newly created, dedicated local database; these tests mutate database state.
Never use an existing application database. With a unique `CLAIMS_TEST_DB` name:

```bash
createdb "$CLAIMS_TEST_DB"
export INTENTGUARD_DATABASE_URL="postgresql:///$CLAIMS_TEST_DB"
.venv/bin/python scripts/migrate.py
psql -d "$CLAIMS_TEST_DB" -v ON_ERROR_STOP=1 -c \
  "INSERT INTO org_members (org_id, subject, roles) VALUES ('org_default', 'user-01', ARRAY['admin'])"

INTENTGUARD_REQUIRE_OPA_TESTS=1 INTENTGUARD_LOG_LEVEL=WARNING \
  PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -q
.tools/opa test policies --verbose --fail-on-empty
PYTHONPATH=src .venv/bin/python -m intentguard.evaluation \
  --iterations 100 --concurrent-requests 100 \
  --connector-iterations 25 --approval-iterations 50
```

Redis was not configured for this run. The evaluation's performance probes use
in-memory state and are not measurements of PostgreSQL authorization latency.
The disposable database and baseline worktree were removed after verification.
