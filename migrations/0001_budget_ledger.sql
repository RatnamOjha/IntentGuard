-- Budget ledger.
--
-- The in-process RLock that guarded budget state could not survive a second
-- replica: two processes meant two independent counters and real overspend.
-- Correctness now lives in the database, where every replica shares it.
--
-- One row per (agent, day). `committed` is spend that happened; `reserved` is
-- spend held against an authorization that has not yet completed. The cap is
-- checked against the sum of both, so a hold is as binding as a payment.

CREATE TABLE IF NOT EXISTS agents (
    agent_id           TEXT PRIMARY KEY,
    name               TEXT           NOT NULL,
    daily_budget       NUMERIC(20, 4) NOT NULL CHECK (daily_budget >= 0),
    max_action_amount  NUMERIC(20, 4) NOT NULL CHECK (max_action_amount >= 0),
    active             BOOLEAN        NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ    NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS budget_days (
    agent_id     TEXT           NOT NULL REFERENCES agents (agent_id) ON DELETE CASCADE,
    budget_date  DATE           NOT NULL,
    committed    NUMERIC(20, 4) NOT NULL DEFAULT 0 CHECK (committed >= 0),
    reserved     NUMERIC(20, 4) NOT NULL DEFAULT 0 CHECK (reserved  >= 0),
    PRIMARY KEY (agent_id, budget_date)
);

-- CREATE TYPE has no IF NOT EXISTS, so guard it to keep the file re-runnable.
DO $$
BEGIN
    CREATE TYPE reservation_status AS ENUM ('held', 'committed', 'released', 'expired');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END
$$;

CREATE TABLE IF NOT EXISTS reservations (
    reservation_id  TEXT PRIMARY KEY,
    request_id      TEXT               NOT NULL,
    agent_id        TEXT               NOT NULL REFERENCES agents (agent_id) ON DELETE CASCADE,
    amount          NUMERIC(20, 4)     NOT NULL CHECK (amount > 0),
    currency        TEXT               NOT NULL,
    budget_date     DATE               NOT NULL,
    status          reservation_status NOT NULL DEFAULT 'held',
    expires_at      TIMESTAMPTZ        NOT NULL,
    created_at      TIMESTAMPTZ        NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ
);

-- Reclaiming expired holds scans by (status, expires_at); everything else
-- looks a reservation up by its agent's day.
CREATE INDEX IF NOT EXISTS reservations_expiry_idx
    ON reservations (status, expires_at) WHERE status = 'held';
CREATE INDEX IF NOT EXISTS reservations_agent_day_idx
    ON reservations (agent_id, budget_date);
