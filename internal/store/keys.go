package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Key kinds.
const (
	KeyKindStatic = "static"
	KeyKindOAuth  = "oauth"
)

// Key is one AI client's credential. SecretHash is sha256-hex of the token;
// the plaintext token is shown exactly once at creation and never stored.
type Key struct {
	ID         string
	Kind       string
	Label      string
	SecretHash string
	Upstreams  []string
	TTLSeconds int64
	CreatedAt  time.Time
	RevokedAt  *time.Time
	UserID     *string
}

// Revoked reports whether the key has been revoked.
func (k *Key) Revoked() bool { return k.RevokedAt != nil }

// CreateKey inserts a key. upstreams is stored as JSON.
func (s *Store) CreateKey(ctx context.Context, k *Key) error {
	ups, err := json.Marshal(k.Upstreams)
	if err != nil {
		return fmt.Errorf("store: marshal upstreams: %w", err)
	}
	var revoked, userID any
	if k.RevokedAt != nil {
		revoked = FormatTime(*k.RevokedAt)
	}
	if k.UserID != nil {
		userID = *k.UserID
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO keys (id, kind, label, secret_hash, upstreams, ttl_seconds, created_at, revoked_at, user_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.Kind, k.Label, k.SecretHash, string(ups), k.TTLSeconds, FormatTime(k.CreatedAt), revoked, userID)
	if err != nil {
		return fmt.Errorf("store: create key: %w", err)
	}
	return nil
}

// KeyByHash resolves a key by its secret hash.
func (s *Store) KeyByHash(ctx context.Context, hash string) (*Key, error) {
	return s.keyWhere(ctx, `secret_hash = ?`, hash)
}

// KeyByID resolves a key by ID.
func (s *Store) KeyByID(ctx context.Context, id string) (*Key, error) {
	return s.keyWhere(ctx, `id = ?`, id)
}

func (s *Store) keyWhere(ctx context.Context, where string, arg string) (*Key, error) {
	var k Key
	var ups, created string
	var revoked, userID any
	err := scanOne(ctx, s, `SELECT id, kind, label, secret_hash, upstreams, ttl_seconds, created_at, revoked_at, user_id
FROM keys WHERE `+where, []any{arg},
		&k.ID, &k.Kind, &k.Label, &k.SecretHash, &ups, &k.TTLSeconds, &created, &revoked, &userID)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(ups), &k.Upstreams); err != nil {
		return nil, fmt.Errorf("store: decode upstreams for key %s: %w", k.ID, err)
	}
	k.CreatedAt, err = ParseTime(created)
	if err != nil {
		return nil, fmt.Errorf("store: decode created_at: %w", err)
	}
	if rs, ok := revoked.(string); ok && rs != "" {
		t, perr := ParseTime(rs)
		if perr != nil {
			return nil, fmt.Errorf("store: decode revoked_at: %w", perr)
		}
		k.RevokedAt = &t
	}
	if us, ok := userID.(string); ok && us != "" {
		k.UserID = &us
	}
	return &k, nil
}

// ListKeys returns all keys, revoked included, newest first.
func (s *Store) ListKeys(ctx context.Context) ([]*Key, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, label, secret_hash, upstreams,
    ttl_seconds, created_at, revoked_at, user_id FROM keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Key
	for rows.Next() {
		k, err := scanKeyRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeKey sets revoked_at. It is idempotent.
func (s *Store) RevokeKey(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		FormatTime(at), id)
	if err != nil {
		return fmt.Errorf("store: revoke key: %w", err)
	}
	// Revoking a key kills its session and pending challenge.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE key_id = ?`, id); err != nil {
		return fmt.Errorf("store: drop session on revoke: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE challenges SET status = 'exhausted' WHERE key_id = ? AND status = 'pending'`, id); err != nil {
		return fmt.Errorf("store: supersede challenges on revoke: %w", err)
	}
	return nil
}

func scanKeyRow(sc scanner) (*Key, error) {
	var k Key
	var ups, created string
	var revoked, userID any
	cols := []any{&k.ID, &k.Kind, &k.Label, &k.SecretHash, &ups, &k.TTLSeconds, &created, &revoked, &userID}
	if err := sc.Scan(cols...); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(ups), &k.Upstreams); err != nil {
		return nil, fmt.Errorf("store: decode upstreams: %w", err)
	}
	var err error
	if k.CreatedAt, err = ParseTime(created); err != nil {
		return nil, fmt.Errorf("store: decode created_at: %w", err)
	}
	if rs, ok := revoked.(string); ok && rs != "" {
		t, perr := ParseTime(rs)
		if perr != nil {
			return nil, fmt.Errorf("store: decode revoked_at: %w", perr)
		}
		k.RevokedAt = &t
	}
	if us, ok := userID.(string); ok && us != "" {
		k.UserID = &us
	}
	return &k, nil
}
