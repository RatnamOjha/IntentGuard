-- Rotating Ed25519 customer-consent keys and one-time passport nonces.

CREATE TABLE IF NOT EXISTS intent_signing_keys (
    issuer       TEXT        NOT NULL,
    key_id       TEXT        NOT NULL,
    public_key   TEXT        NOT NULL,
    active       BOOLEAN     NOT NULL DEFAULT TRUE,
    valid_from   TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, key_id),
    CHECK (expires_at IS NULL OR valid_from IS NULL OR expires_at > valid_from)
);

CREATE TABLE IF NOT EXISTS intent_nonces (
    issuer       TEXT        NOT NULL,
    nonce        TEXT        NOT NULL,
    intent_id    TEXT        NOT NULL,
    consumed_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (issuer, nonce)
);

CREATE INDEX IF NOT EXISTS intent_nonces_consumed_at_idx
    ON intent_nonces (consumed_at);
