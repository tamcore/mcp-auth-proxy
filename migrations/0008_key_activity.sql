-- Last request seen with a key and its last successful proxied tool call,
-- shown in the portal.
ALTER TABLE keys ADD COLUMN last_used_at TEXT;
ALTER TABLE keys ADD COLUMN last_success_at TEXT;
