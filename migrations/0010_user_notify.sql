-- Per-user push target. Replaces the global ntfy configuration: every user
-- gets the one-time codes of their own keys on their own ntfy topic.
CREATE TABLE user_notify (
    user_id    TEXT PRIMARY KEY REFERENCES users (id),
    url        TEXT NOT NULL,
    topic      TEXT NOT NULL,
    token      TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
) STRICT;
