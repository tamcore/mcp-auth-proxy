-- Passkeys (WebAuthn credentials) per user, and a per-user cutoff that logs
-- out every web session issued before it (set on password change).
ALTER TABLE users ADD COLUMN sessions_since TEXT;
CREATE TABLE passkeys (
    id           BLOB PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users (id),
    name         TEXT NOT NULL,
    credential   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_used_at TEXT
) STRICT;
CREATE INDEX idx_passkeys_user ON passkeys (user_id);
