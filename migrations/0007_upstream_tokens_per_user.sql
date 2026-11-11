-- Upstream OAuth tokens belong to one proxy user: each user links their own
-- upstream account. user_id '' is the unowned slot used by the CLI and keys
-- without a user.
CREATE TABLE upstream_tokens_new (
    upstream      TEXT NOT NULL,
    user_id       TEXT NOT NULL DEFAULT '',
    access_token  TEXT NOT NULL,
    refresh_token TEXT,
    expires_at    TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (upstream, user_id)
) STRICT;
INSERT INTO upstream_tokens_new (upstream, access_token, refresh_token, expires_at, created_at, updated_at)
SELECT upstream, access_token, refresh_token, expires_at, created_at, updated_at FROM upstream_tokens;
DROP TABLE upstream_tokens;
ALTER TABLE upstream_tokens_new RENAME TO upstream_tokens;
