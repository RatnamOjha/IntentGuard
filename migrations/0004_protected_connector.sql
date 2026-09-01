-- Connector-verifiable lease keys and durable execution idempotency.

CREATE TABLE IF NOT EXISTS lease_signing_keys (
    issuer      TEXT        NOT NULL,
    key_id      TEXT        NOT NULL,
    public_key  TEXT        NOT NULL,
    active      BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, key_id)
);

CREATE TABLE IF NOT EXISTS connector_executions (
    request_id          TEXT PRIMARY KEY,
    request_fingerprint TEXT        NOT NULL,
    status              TEXT        NOT NULL,
    response_payload    JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
