-- Durable policy-engine state shared by every API replica.

CREATE TABLE IF NOT EXISTS governance_metadata (
    singleton        BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    policy_version   TEXT        NOT NULL,
    policy_revision  INTEGER     NOT NULL DEFAULT 0 CHECK (policy_revision >= 0),
    fleet_stopped    BOOLEAN     NOT NULL DEFAULT FALSE,
    fleet_epoch      BIGINT      NOT NULL DEFAULT 0 CHECK (fleet_epoch >= 0),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_policies (
    agent_id    TEXT PRIMARY KEY REFERENCES agents (agent_id) ON DELETE CASCADE,
    payload     JSONB       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS customer_intents (
    intent_id   TEXT PRIMARY KEY,
    payload     JSONB       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS approval_requests (
    request_id  TEXT PRIMARY KEY,
    payload     JSONB       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS authorization_records (
    request_id       TEXT PRIMARY KEY,
    request_payload  JSONB       NOT NULL,
    result_payload   JSONB       NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS authorization_leases (
    lease_id    TEXT PRIMARY KEY,
    payload     JSONB       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_revocations (
    agent_id          TEXT PRIMARY KEY REFERENCES agents (agent_id) ON DELETE CASCADE,
    revocation_epoch  BIGINT      NOT NULL CHECK (revocation_epoch > 0),
    revoked_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS authorization_counters (
    agent_id             TEXT NOT NULL REFERENCES agents (agent_id) ON DELETE CASCADE,
    budget_date          DATE NOT NULL,
    authorization_count  INTEGER NOT NULL CHECK (authorization_count >= 0),
    PRIMARY KEY (agent_id, budget_date)
);

CREATE TABLE IF NOT EXISTS audit_events (
    sequence       BIGINT PRIMARY KEY,
    occurred_at    TIMESTAMPTZ NOT NULL,
    event_type     TEXT        NOT NULL,
    payload        JSONB       NOT NULL,
    previous_hash  TEXT        NOT NULL,
    event_hash     TEXT        NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_metadata (
    singleton    BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    event_count  BIGINT NOT NULL DEFAULT 0 CHECK (event_count >= 0),
    head_hash    TEXT   NOT NULL
);

INSERT INTO audit_metadata (singleton, event_count, head_hash)
VALUES (TRUE, 0, repeat('0', 64))
ON CONFLICT (singleton) DO NOTHING;
