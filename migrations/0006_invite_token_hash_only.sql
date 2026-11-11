-- Invite tokens are stored as hashes only. Unused invites are dropped; serve
-- re-mints and logs a fresh link for every user without a password.
DELETE FROM invites WHERE used_at IS NULL;
ALTER TABLE invites DROP COLUMN token;
