package store

import (
	"context"
	"fmt"
	"time"
)

// PushSubscription is one browser's Web Push subscription. Auth is a
// credential: never logged or rendered back.
type PushSubscription struct {
	ID        string
	UserID    string
	Endpoint  string
	P256dh    string
	Auth      string
	Label     string
	CreatedAt time.Time
}

// SavePushSubscription upserts by endpoint; a browser re-subscribing under
// another login moves to that user.
func (s *Store) SavePushSubscription(ctx context.Context, p *PushSubscription) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO push_subscriptions (id, user_id, endpoint, p256dh, auth, label, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (endpoint) DO UPDATE SET user_id = excluded.user_id, p256dh = excluded.p256dh, auth = excluded.auth,
    label = excluded.label`,
		p.ID, p.UserID, p.Endpoint, p.P256dh, p.Auth, p.Label, FormatTime(p.CreatedAt))
	if err != nil {
		return fmt.Errorf("store: save push subscription: %w", err)
	}
	return nil
}

// ListPushSubscriptions returns the user's subscriptions, oldest first.
func (s *Store) ListPushSubscriptions(ctx context.Context, userID string) ([]*PushSubscription, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, user_id, endpoint, p256dh, auth, label, created_at FROM push_subscriptions
WHERE user_id = ? ORDER BY rowid`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list push subscriptions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*PushSubscription
	for rows.Next() {
		var p PushSubscription
		var created string
		if err := rows.Scan(&p.ID, &p.UserID, &p.Endpoint, &p.P256dh, &p.Auth, &p.Label, &created); err != nil {
			return nil, err
		}
		if p.CreatedAt, err = ParseTime(created); err != nil {
			return nil, fmt.Errorf("store: decode push subscription created_at: %w", err)
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

// DeletePushSubscription removes one of the user's subscriptions.
func (s *Store) DeletePushSubscription(ctx context.Context, id, userID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return fmt.Errorf("store: delete push subscription: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeletePushSubscriptionByEndpoint drops a subscription the push service
// reported as gone.
func (s *Store) DeletePushSubscriptionByEndpoint(ctx context.Context, endpoint string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE endpoint = ?`, endpoint); err != nil {
		return fmt.Errorf("store: delete push subscription: %w", err)
	}
	return nil
}
