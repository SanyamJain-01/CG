CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id            UUID PRIMARY KEY,
    email         CITEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scans (
    id             UUID PRIMARY KEY,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status         TEXT NOT NULL CHECK (status IN ('QUEUED','RUNNING','SUCCEEDED','FAILED')),
    filename       TEXT NOT NULL,
    archive_sha256 TEXT,
    archive_bytes  BIGINT,
    file_count     INT,
    attempts       INT NOT NULL DEFAULT 0 CHECK (attempts <= 3),
    heartbeat_at   TIMESTAMPTZ,
    error_code     TEXT,
    error_detail   TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ,
    CHECK (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at)
);

CREATE INDEX scans_user_created ON scans (user_id, created_at DESC);
CREATE INDEX scans_pending ON scans (created_at) WHERE status IN ('QUEUED','RUNNING');
