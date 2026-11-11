-- Store the invite token in plaintext so the login page can show the pending
-- invite link for users who have not set a password yet. The token is the
-- credential, is single-use, and expires; once consumed or expired the row is
-- not displayed. API tokens remain hash-only.
ALTER TABLE invites ADD COLUMN token TEXT;
