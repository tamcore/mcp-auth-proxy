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
	// LastUsedAt is the last authenticated request; LastSuccessAt the last
	// proxied tool call that returned without error.
	LastUsedAt    *time.Time
	LastSuccessAt *time.Time
}

const keyColumns = `id, kind, label, secret_hash, upstreams, ttl_seconds, created_at, revoked_at, user_id,
    last_used_at, last_success_at`

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
	return scanKeyRow(s.db.QueryRowContext(ctx, `SELECT `+keyColumns+` FROM keys WHERE `+where, arg))
}

// ListKeys returns all keys, revoked included, newest first.
func (s *Store) ListKeys(ctx context.Context) ([]*Key, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+keyColumns+` FROM keys ORDER BY created_at DESC`)
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

// UpdateKeyUpstreams replaces the upstreams of a key the user owns.
func (s *Store) UpdateKeyUpstreams(ctx context.Context, id, userID string, upstreams []string) error {
	ups, err := json.Marshal(upstreams)
	if err != nil {
		return fmt.Errorf("store: marshal upstreams: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE keys SET upstreams = ? WHERE id = ? AND user_id = ?`,
		string(ups), id, userID)
	if err != nil {
		return fmt.Errorf("store: update key upstreams: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkKeyUsed records an authenticated request with the key.
func (s *Store) MarkKeyUsed(ctx context.Context, id string, at time.Time) error {
	return s.setKeyTime(ctx, "last_used_at", id, at)
}

// MarkKeySuccess records a successful proxied tool call with the key.
func (s *Store) MarkKeySuccess(ctx context.Context, id string, at time.Time) error {
	return s.setKeyTime(ctx, "last_success_at", id, at)
}

// setKeyTime sets one of the fixed activity columns.
func (s *Store) setKeyTime(ctx context.Context, column, id string, at time.Time) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE keys SET `+column+` = ? WHERE id = ?`, FormatTime(at), id); err != nil {
		return fmt.Errorf("store: set key %s: %w", column, err)
	}
	return nil
}

func scanKeyRow(sc scanner) (*Key, error) {
	var k Key
	var ups, created string
	var revoked, userID, used, success any
	cols := []any{&k.ID, &k.Kind, &k.Label, &k.SecretHash, &ups, &k.TTLSeconds, &created, &revoked, &userID,
		&used, &success}
	if err := sc.Scan(cols...); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(ups), &k.Upstreams); err != nil {
		return nil, fmt.Errorf("store: decode upstreams for key %s: %w", k.ID, err)
	}
	var err error
	if k.CreatedAt, err = ParseTime(created); err != nil {
		return nil, fmt.Errorf("store: decode created_at: %w", err)
	}
	for _, f := range []struct {
		raw any
		dst **time.Time
	}{{revoked, &k.RevokedAt}, {used, &k.LastUsedAt}, {success, &k.LastSuccessAt}} {
		if *f.dst, err = optionalTime(f.raw); err != nil {
			return nil, err
		}
	}
	if us, ok := userID.(string); ok && us != "" {
		k.UserID = &us
	}
	return &k, nil
}

// optionalTime decodes a nullable TEXT timestamp column.
func optionalTime(raw any) (*time.Time, error) {
	rs, ok := raw.(string)
	if !ok || rs == "" {
		return nil, nil
	}
	t, err := ParseTime(rs)
	if err != nil {
		return nil, fmt.Errorf("store: decode timestamp: %w", err)
	}
	return &t, nil
}
