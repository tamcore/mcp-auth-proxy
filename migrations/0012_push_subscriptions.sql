-- Web Push subscriptions: one row per browser/device of a user. The endpoint
-- and keys come from the browser's PushSubscription; auth is a credential.
CREATE TABLE push_subscriptions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users (id),
    endpoint   TEXT NOT NULL UNIQUE,
    p256dh     TEXT NOT NULL,
    auth       TEXT NOT NULL,
    label      TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_push_subscriptions_user ON push_subscriptions (user_id);
