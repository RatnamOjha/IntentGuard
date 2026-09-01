CREATE TABLE IF NOT EXISTS policy_versions (
    version_id    TEXT PRIMARY KEY,
    source        TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('draft', 'published', 'retired')),
    created_at    TIMESTAMPTZ NOT NULL,
    created_by    TEXT NOT NULL,
    description   TEXT NOT NULL,
    based_on      TEXT REFERENCES policy_versions(version_id),
    published_at  TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS one_published_policy
    ON policy_versions ((status)) WHERE status = 'published';
