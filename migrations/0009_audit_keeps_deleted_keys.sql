-- Revoked keys can be removed; their audit history stays (key_label is
-- copied into each row), so audit_log.key_id no longer references keys.
CREATE TABLE audit_log_new (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users (id),
    key_id     TEXT NOT NULL,
    key_label  TEXT NOT NULL,
    tool_name  TEXT NOT NULL,
    arguments  TEXT,
    response   TEXT,
    created_at TEXT NOT NULL
) STRICT;
INSERT INTO audit_log_new SELECT id, user_id, key_id, key_label, tool_name, arguments, response, created_at FROM audit_log;
DROP TABLE audit_log;
ALTER TABLE audit_log_new RENAME TO audit_log;
CREATE INDEX idx_audit_user_time ON audit_log (user_id, created_at DESC);
CREATE INDEX idx_audit_created ON audit_log (created_at);
