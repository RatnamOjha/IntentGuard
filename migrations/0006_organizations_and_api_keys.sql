-- Organisations, membership, and API keys.
--
-- ADR 004: organisation identity is owned here rather than taken from a
-- Keycloak claim, so an organisation can exist before anyone from it has ever
-- logged in. That is what lets us issue a design partner a key on day one.
--
-- Keycloak stays operator SSO only: a validated token yields a subject, and
-- org_members maps that subject to an organisation and its roles.

CREATE TABLE IF NOT EXISTS organizations (
    org_id      TEXT PRIMARY KEY,
    name        TEXT        NOT NULL,
    slug        TEXT        NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Which authenticated subjects belong to which organisation.
CREATE TABLE IF NOT EXISTS org_members (
    org_id      TEXT        NOT NULL REFERENCES organizations (org_id) ON DELETE CASCADE,
    subject     TEXT        NOT NULL,
    roles       TEXT[]      NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, subject)
);

-- One organisation per subject for now. ADR 004 defers multi-org membership
-- until a partner asks for it; this index is what makes that explicit rather
-- than accidental, and dropping it is the whole change when they do.
CREATE UNIQUE INDEX IF NOT EXISTS org_members_one_org_per_subject
    ON org_members (subject);

-- How a customer's agent authenticates. The secret itself is never stored:
-- `prefix` is the indexed lookup handle and `key_hash` is SHA-256 of the whole
-- key, compared in constant time.
CREATE TABLE IF NOT EXISTS api_keys (
    key_id        TEXT PRIMARY KEY,
    org_id        TEXT        NOT NULL REFERENCES organizations (org_id) ON DELETE CASCADE,
    name          TEXT        NOT NULL,
    prefix        TEXT        NOT NULL,
    key_hash      TEXT        NOT NULL,
    roles         TEXT[]      NOT NULL,
    -- An agent key is bound to the identity it may act as, so a key cannot
    -- claim to be a different agent or customer than the one it was issued for.
    agent_id      TEXT,
    customer_id   TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS api_keys_prefix_idx ON api_keys (prefix);
CREATE INDEX IF NOT EXISTS api_keys_org_idx    ON api_keys (org_id);

-- Everything that exists today belongs to one organisation. Later migrations
-- add org_id to the governance tables and backfill them to this row, so an
-- installed database keeps working with no behaviour change.
INSERT INTO organizations (org_id, name, slug)
VALUES ('org_default', 'Default Organisation', 'default')
ON CONFLICT (org_id) DO NOTHING;
