-- Admin role (toggled only via the config `admins` list), temporary user
-- disable, and single-use invite links. A user created from config starts
-- without a password: an admin hands over the invite link, and the user sets
-- their own password through it.
ALTER TABLE users ADD COLUMN admin INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;

CREATE TABLE invites (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users (id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT
) STRICT;

CREATE INDEX idx_invites_user ON invites (user_id);
