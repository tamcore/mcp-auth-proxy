CREATE TABLE keys (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('static', 'oauth')),
    label       TEXT NOT NULL,
    secret_hash TEXT NOT NULL UNIQUE,
    upstreams   TEXT NOT NULL,
    ttl_seconds INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT
) STRICT;

CREATE TABLE sessions (
    key_id     TEXT PRIMARY KEY REFERENCES keys (id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    origin     TEXT NOT NULL CHECK (origin IN ('otp', 'approve'))
) STRICT;

CREATE TABLE challenges (
    id         TEXT PRIMARY KEY,
    key_id     TEXT NOT NULL REFERENCES keys (id),
    otp_hash   TEXT NOT NULL,
    tool_name  TEXT NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'exhausted')),
    attempts   INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_challenges_key_status ON challenges (key_id, status);

CREATE TABLE oauth_clients (
    client_id     TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    confidential  INTEGER NOT NULL,
    created_at    TEXT NOT NULL
) STRICT;

CREATE TABLE access_tokens (
    token_hash TEXT PRIMARY KEY,
    key_id     TEXT NOT NULL REFERENCES keys (id),
    client_id  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_access_tokens_key ON access_tokens (key_id);

CREATE TABLE upstream_tokens (
    upstream      TEXT PRIMARY KEY,
    access_token  TEXT NOT NULL,
    refresh_token TEXT,
    expires_at    TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
) STRICT;
