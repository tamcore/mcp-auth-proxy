-- Multi-user support. Users are seeded from config; a user missing from the
-- database gets an auto-generated password on first start. Per-user upstreams
-- live here and are visible only to their owner. keys.user_id binds a key to
-- a user (NULL = legacy single-user key).
CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
) STRICT;

CREATE TABLE user_upstreams (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users (id),
    name       TEXT NOT NULL,
    url        TEXT,
    command    TEXT,
    headers    TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (user_id, name)
) STRICT;

ALTER TABLE keys ADD COLUMN user_id TEXT REFERENCES users (id);
