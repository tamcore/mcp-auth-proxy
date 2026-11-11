package store

import (
	"context"
	"fmt"
	"time"
)

// UserNotify is a user's ntfy push target. Token is a credential: never
// logged or rendered back.
type UserNotify struct {
	UserID    string
	URL       string
	Topic     string
	Token     string
	UpdatedAt time.Time
}

// GetUserNotify loads the user's push target, or ErrNotFound.
func (s *Store) GetUserNotify(ctx context.Context, userID string) (*UserNotify, error) {
	var n UserNotify
	var updated string
	err := scanOne(ctx, s, `SELECT user_id, url, topic, token, updated_at FROM user_notify WHERE user_id = ?`,
		[]any{userID}, &n.UserID, &n.URL, &n.Topic, &n.Token, &updated)
	if err != nil {
		return nil, err
	}
	if n.UpdatedAt, err = ParseTime(updated); err != nil {
		return nil, fmt.Errorf("store: decode user_notify updated_at: %w", err)
	}
	return &n, nil
}

// SaveUserNotify upserts the user's push target.
func (s *Store) SaveUserNotify(ctx context.Context, n *UserNotify) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO user_notify (user_id, url, topic, token, updated_at) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (user_id) DO UPDATE SET url = excluded.url, topic = excluded.topic, token = excluded.token,
    updated_at = excluded.updated_at`,
		n.UserID, n.URL, n.Topic, n.Token, FormatTime(nowUTC()))
	if err != nil {
		return fmt.Errorf("store: save user notify: %w", err)
	}
	return nil
}

// DeleteUserNotify removes the user's push target.
func (s *Store) DeleteUserNotify(ctx context.Context, userID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM user_notify WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("store: delete user notify: %w", err)
	}
	return nil
}

// PendingRequest is a live challenge on one of a user's keys.
type PendingRequest struct {
	Challenge
	KeyLabel string
}

// PendingChallengesForUser lists the live pending challenges of the user's
// keys, newest first.
func (s *Store) PendingChallengesForUser(ctx context.Context, userID string, now time.Time) ([]PendingRequest, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT c.id, c.key_id, c.tool_name, c.created_at, c.expires_at, k.label
FROM challenges c JOIN keys k ON k.id = c.key_id
WHERE k.user_id = ? AND c.status = ? AND c.expires_at > ?
ORDER BY c.created_at DESC`, userID, ChallengePending, FormatTime(now))
	if err != nil {
		return nil, fmt.Errorf("store: list pending challenges: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []PendingRequest
	for rows.Next() {
		var p PendingRequest
		var created, expires string
		if err := rows.Scan(&p.ID, &p.KeyID, &p.ToolName, &created, &expires, &p.KeyLabel); err != nil {
			return nil, err
		}
		if p.CreatedAt, err = ParseTime(created); err != nil {
			return nil, err
		}
		if p.ExpiresAt, err = ParseTime(expires); err != nil {
			return nil, err
		}
		p.Status = ChallengePending
		out = append(out, p)
	}
	return out, rows.Err()
}
