package store

import (
	"context"
	"fmt"
	"time"
)

// Challenge statuses.
const (
	ChallengePending   = "pending"
	ChallengeApproved  = "approved"
	ChallengeDenied    = "denied"
	ChallengeExhausted = "exhausted"
)

// Session origins.
const (
	OriginOTP     = "otp"
	OriginApprove = "approve"
)

// Session is a per-key authorization window.
type Session struct {
	KeyID     string
	CreatedAt time.Time
	ExpiresAt time.Time
	Origin    string
}

// GetSession returns the live session for a key, or ErrNotFound when there is
// none or it has expired (expired sessions read as not-found).
func (s *Store) GetSession(ctx context.Context, keyID string, now time.Time) (*Session, error) {
	var sess Session
	var created, expires string
	err := scanOne(ctx, s, `SELECT key_id, created_at, expires_at, origin FROM sessions WHERE key_id = ?`,
		[]any{keyID}, &sess.KeyID, &created, &expires, &sess.Origin)
	if err != nil {
		return nil, err
	}
	var err2 error
	if sess.CreatedAt, err2 = ParseTime(created); err2 != nil {
		return nil, fmt.Errorf("store: decode session created_at: %w", err2)
	}
	if sess.ExpiresAt, err2 = ParseTime(expires); err2 != nil {
		return nil, fmt.Errorf("store: decode session expires_at: %w", err2)
	}
	if !now.Before(sess.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &sess, nil
}

// UpsertSession creates or replaces the session for a key.
func (s *Store) UpsertSession(ctx context.Context, sess *Session) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO sessions (key_id, created_at, expires_at, origin) VALUES (?, ?, ?, ?)
ON CONFLICT (key_id) DO UPDATE SET created_at = excluded.created_at,
    expires_at = excluded.expires_at, origin = excluded.origin`,
		sess.KeyID, FormatTime(sess.CreatedAt), FormatTime(sess.ExpiresAt), sess.Origin)
	if err != nil {
		return fmt.Errorf("store: upsert session: %w", err)
	}
	return nil
}

// DeleteSession removes the session for a key, if any.
func (s *Store) DeleteSession(ctx context.Context, keyID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE key_id = ?`, keyID)
	return err
}

// Challenge is a pending one-time-code gate for one key. PendingOTP carries the
// plaintext code for the single ntfy push only; it is never persisted (db:"-").
type Challenge struct {
	ID         string
	KeyID      string
	OTPHash    string
	ToolName   string
	Status     string
	Attempts   int
	CreatedAt  time.Time
	ExpiresAt  time.Time
	PendingOTP string `db:"-"`
}

// PendingChallenge returns the key's live pending challenge, or ErrNotFound.
func (s *Store) PendingChallenge(ctx context.Context, keyID string, now time.Time) (*Challenge, error) {
	ch, err := s.challengeWhere(ctx, `key_id = ? AND status = ?`, []any{keyID, ChallengePending})
	if err != nil {
		return nil, err
	}
	if !now.Before(ch.ExpiresAt) {
		return nil, ErrNotFound
	}
	return ch, nil
}

// PendingChallengeAny returns the key's pending challenge even if expired, so
// the gate can distinguish "expired" from "no challenge".
func (s *Store) PendingChallengeAny(ctx context.Context, keyID string) (*Challenge, error) {
	return s.challengeWhere(ctx, `key_id = ? AND status = ?`, []any{keyID, ChallengePending})
}

// ChallengeByID loads a challenge regardless of status.
func (s *Store) ChallengeByID(ctx context.Context, id string) (*Challenge, error) {
	return s.challengeWhere(ctx, `id = ?`, []any{id})
}

func (s *Store) challengeWhere(ctx context.Context, where string, args []any) (*Challenge, error) {
	var ch Challenge
	var created, expires string
	err := scanOne(ctx, s, `SELECT id, key_id, otp_hash, tool_name, status, attempts, created_at, expires_at
FROM challenges WHERE `+where, args,
		&ch.ID, &ch.KeyID, &ch.OTPHash, &ch.ToolName, &ch.Status, &ch.Attempts, &created, &expires)
	if err != nil {
		return nil, err
	}
	var perr error
	if ch.CreatedAt, perr = ParseTime(created); perr != nil {
		return nil, fmt.Errorf("store: decode challenge created_at: %w", perr)
	}
	if ch.ExpiresAt, perr = ParseTime(expires); perr != nil {
		return nil, fmt.Errorf("store: decode challenge expires_at: %w", perr)
	}
	return &ch, nil
}

// CreateChallenge inserts a challenge and supersedes the key's older pending
// one, so at most one challenge per key is pending.
func (s *Store) CreateChallenge(ctx context.Context, ch *Challenge) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin create challenge: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`UPDATE challenges SET status = ? WHERE key_id = ? AND status = ? AND id != ?`,
		ChallengeExhausted, ch.KeyID, ChallengePending, ch.ID); err != nil {
		return fmt.Errorf("store: supersede pending challenge: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO challenges (id, key_id, otp_hash, tool_name, status, attempts, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ch.ID, ch.KeyID, ch.OTPHash, ch.ToolName, ch.Status, ch.Attempts, FormatTime(ch.CreatedAt), FormatTime(ch.ExpiresAt))
	if err != nil {
		return fmt.Errorf("store: create challenge: %w", err)
	}
	return tx.Commit()
}

// UpdateChallenge sets status and the attempts counter of one challenge.
func (s *Store) UpdateChallenge(ctx context.Context, id, status string, attempts int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE challenges SET status = ?, attempts = ? WHERE id = ?`, status, attempts, id)
	if err != nil {
		return fmt.Errorf("store: update challenge: %w", err)
	}
	return nil
}
