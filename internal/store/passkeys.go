package store

import (
	"context"
	"fmt"
	"time"
)

// Passkey is one WebAuthn credential of a user. Credential is the library's
// JSON form (public key, sign count, flags); it holds no secret.
type Passkey struct {
	ID         []byte
	UserID     string
	Name       string
	Credential string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

const passkeyColumns = `id, user_id, name, credential, created_at, last_used_at`

// AddPasskey stores a newly registered passkey.
func (s *Store) AddPasskey(ctx context.Context, p *Passkey) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO passkeys (id, user_id, name, credential, created_at) VALUES (?, ?, ?, ?, ?)`,
		p.ID, p.UserID, p.Name, p.Credential, FormatTime(p.CreatedAt))
	if err != nil {
		return fmt.Errorf("store: add passkey: %w", err)
	}
	return nil
}

// ListPasskeys returns the user's passkeys, oldest first.
func (s *Store) ListPasskeys(ctx context.Context, userID string) ([]*Passkey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+passkeyColumns+` FROM passkeys WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list passkeys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PasskeyByID loads a passkey by credential ID, or ErrNotFound.
func (s *Store) PasskeyByID(ctx context.Context, id []byte) (*Passkey, error) {
	return scanPasskey(s.db.QueryRowContext(ctx, `SELECT `+passkeyColumns+` FROM passkeys WHERE id = ?`, id))
}

// MarkPasskeyUsed stores the updated credential (sign count) after a login.
func (s *Store) MarkPasskeyUsed(ctx context.Context, id []byte, credential string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE passkeys SET credential = ?, last_used_at = ? WHERE id = ?`,
		credential, FormatTime(at), id)
	if err != nil {
		return fmt.Errorf("store: mark passkey used: %w", err)
	}
	return nil
}

// DeletePasskey removes one of the user's passkeys, or returns ErrNotFound.
func (s *Store) DeletePasskey(ctx context.Context, userID string, id []byte) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM passkeys WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return fmt.Errorf("store: delete passkey: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanPasskey(sc scanner) (*Passkey, error) {
	var p Passkey
	var created string
	var used any
	if err := sc.Scan(&p.ID, &p.UserID, &p.Name, &p.Credential, &created, &used); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	if p.CreatedAt, err = ParseTime(created); err != nil {
		return nil, fmt.Errorf("store: decode passkey created_at: %w", err)
	}
	if p.LastUsedAt, err = optionalTime(used); err != nil {
		return nil, err
	}
	return &p, nil
}
