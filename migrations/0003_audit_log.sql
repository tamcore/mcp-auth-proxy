-- Audit log: one row per proxied tool call. Scoped to the owning user so the
-- portal only ever shows a user their own clients' activity. response is NULL
-- unless audit.log_responses is enabled.
CREATE TABLE audit_log (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users (id),
    key_id     TEXT NOT NULL REFERENCES keys (id),
    key_label  TEXT NOT NULL,
    tool_name  TEXT NOT NULL,
    arguments  TEXT,
    response   TEXT,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_audit_user_time ON audit_log (user_id, created_at DESC);
CREATE INDEX idx_audit_created ON audit_log (created_at);
