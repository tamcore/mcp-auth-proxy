package store

import (
	"context"
	"fmt"
	"time"
)

// KeyState is what /metrics reports about one live (not revoked) key.
type KeyState struct {
	Username        string // "" for a key without an owner
	Label           string
	LastUsedAt      *time.Time
	LastSuccessAt   *time.Time
	AuthorizedAt    *time.Time // start of the current or last session
	AuthorizedUntil *time.Time
	AuthPending     bool // a challenge is open and not expired
}

// KeyStates returns the state of every live key at now.
func (s *Store) KeyStates(ctx context.Context, now time.Time) ([]KeyState, error) {
	pending, err := s.pendingKeys(ctx, now)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT k.id, k.label, COALESCE(u.username, ''), k.last_used_at, k.last_success_at, s.created_at, s.expires_at
FROM keys k LEFT JOIN users u ON u.id = k.user_id LEFT JOIN sessions s ON s.key_id = k.id
WHERE k.revoked_at IS NULL ORDER BY k.id`)
	if err != nil {
		return nil, fmt.Errorf("store: key states: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []KeyState
	for rows.Next() {
		var id string
		var st KeyState
		var used, success, from, until any
		if err := rows.Scan(&id, &st.Label, &st.Username, &used, &success, &from, &until); err != nil {
			return nil, err
		}
		for _, f := range []struct {
			raw any
			dst **time.Time
		}{{used, &st.LastUsedAt}, {success, &st.LastSuccessAt}, {from, &st.AuthorizedAt}, {until, &st.AuthorizedUntil}} {
			if *f.dst, err = optionalTime(f.raw); err != nil {
				return nil, err
			}
		}
		st.AuthPending = pending[id]
		out = append(out, st)
	}
	return out, rows.Err()
}

// pendingKeys returns the keys with a pending challenge that has not expired.
// Expiry is compared in Go: the stored RFC 3339 text does not sort as time.
func (s *Store) pendingKeys(ctx context.Context, now time.Time) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key_id, expires_at FROM challenges WHERE status = ?`, ChallengePending)
	if err != nil {
		return nil, fmt.Errorf("store: pending challenges: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var keyID, expires string
		if err := rows.Scan(&keyID, &expires); err != nil {
			return nil, err
		}
		if t, err := ParseTime(expires); err == nil && now.Before(t) {
			out[keyID] = true
		}
	}
	return out, rows.Err()
}
