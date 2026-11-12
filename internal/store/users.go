package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const userColumns = `id, username, password_hash, admin, disabled, created_at, sessions_since`

// User is one login of the multi-user instance. PasswordHash is empty until the
// user sets a password via invite link. Admin is toggled only in the config.
type User struct {
	ID           string
	Username     string
	PasswordHash string
	Admin        bool
	Disabled     bool
	CreatedAt    time.Time
	// SessionsSince rejects web sessions issued before it (password change).
	SessionsSince *time.Time
}

// HashPassword bcrypt-hashes a plaintext password.
func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("store: hash password: %w", err)
	}
	return string(h), nil
}

// CheckPassword verifies a plaintext password against the stored hash. An empty
// hash (password not set yet) never matches.
func CheckPassword(hash, pw string) bool {
	if hash == "" {
		// Same bcrypt cost for unknown users, so timing does not reveal usernames.
		_ = bcrypt.CompareHashAndPassword([]byte(noUserHash), []byte(pw))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

const noUserHash = "$2a$10$pxZOwl1JSFsfog0AXY2.C.ESdBCMkq1gRVH.MoLgv3UwIRTeJqh7O"

// CreateUser inserts a user.
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	admin, disabled := 0, 0
	if u.Admin {
		admin = 1
	}
	if u.Disabled {
		disabled = 1
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO users (id, username, password_hash, admin, disabled, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, admin, disabled, FormatTime(u.CreatedAt))
	if err != nil {
		return fmt.Errorf("store: create user: %w", err)
	}
	return nil
}

// SetUserPassword sets a user's password hash.
func (s *Store) SetUserPassword(ctx context.Context, userID, hash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, userID)
	if err != nil {
		return fmt.Errorf("store: set password: %w", err)
	}
	return nil
}

// SetUserDisabled temporarily disables or re-enables a user.
// It never disables the last enabled admin: the check and the update are one
// statement, so two admins disabling each other at once cannot both succeed.
func (s *Store) SetUserDisabled(ctx context.Context, userID string, disabled bool) error {
	q, args := `UPDATE users SET disabled = 0 WHERE id = ?`, []any{userID}
	if disabled {
		q = `UPDATE users SET disabled = 1 WHERE id = ? AND (admin = 0 OR
			(SELECT COUNT(*) FROM users WHERE admin = 1 AND disabled = 0 AND id != ?) > 0)`
		args = append(args, userID)
	}
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("store: set disabled: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		if _, err := s.UserByID(ctx, userID); err != nil {
			return err
		}
		return ErrLastAdmin
	}
	return nil
}

func scanUser(sc scanner) (*User, error) {
	var u User
	var created string
	var admin, disabled int
	var since any
	if err := sc.Scan(&u.ID, &u.Username, &u.PasswordHash, &admin, &disabled, &created, &since); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var perr error
	if u.CreatedAt, perr = ParseTime(created); perr != nil {
		return nil, fmt.Errorf("store: decode user created_at: %w", perr)
	}
	u.Admin = admin == 1
	u.Disabled = disabled == 1
	if u.SessionsSince, perr = optionalTime(since); perr != nil {
		return nil, perr
	}
	return &u, nil
}

// SetSessionsSince logs out every web session of the user issued before t.
func (s *Store) SetSessionsSince(ctx context.Context, userID string, t time.Time) error {
	q := `UPDATE users SET sessions_since = ? WHERE id = ?`
	if _, err := s.db.ExecContext(ctx, q, FormatTime(t), userID); err != nil {
		return fmt.Errorf("store: set sessions_since: %w", err)
	}
	return nil
}

// UserByName resolves a user by username.
func (s *Store) UserByName(ctx context.Context, name string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE username = ?`, name))
}

// UserByID resolves a user by id.
func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

// ListUsers returns all users.
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+userColumns+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// EnsureConfigUsers makes sure every configured username exists. Missing users
// are created without a password plus a single-use invite token; admin flags
// come from the config admins list. It returns username -> invite token for
// newly created users so the caller can hand over the link exactly once.
func (s *Store) EnsureConfigUsers(ctx context.Context, usernames, admins []string,
	now time.Time) (map[string]string, error) {
	adminSet := map[string]bool{}
	for _, a := range admins {
		adminSet[a] = true
	}
	invites := map[string]string{}
	for _, name := range usernames {
		u, err := s.UserByName(ctx, name)
		if err == nil {
			if u.Admin != adminSet[name] {
				d := 0
				if adminSet[name] {
					d = 1
				}
				q := `UPDATE users SET admin = ? WHERE id = ?`
				if _, err := s.db.ExecContext(ctx, q, d, u.ID); err != nil {
					return nil, err
				}
			}
			if u.PasswordHash == "" {
				// No password set yet: re-mint an invite on every start so the
				// bootstrap link stays visible in the logs until used.
				token, err := s.CreateInvite(ctx, u.ID, now)
				if err != nil {
					return nil, err
				}
				invites[name] = token
			}
			continue
		}
		if err != ErrNotFound {
			return nil, err
		}
		id := make([]byte, 8)
		if _, err := rand.Read(id); err != nil {
			return nil, err
		}
		u = &User{ID: "u_" + hex.EncodeToString(id), Username: name, Admin: adminSet[name], CreatedAt: now}
		if err := s.CreateUser(ctx, u); err != nil {
			return nil, err
		}
		token, err := s.CreateInvite(ctx, u.ID, now)
		if err != nil {
			return nil, err
		}
		invites[name] = token
	}
	return invites, nil
}

// inviteTTL is how long an invite link stays valid.
const inviteTTL = 7 * 24 * time.Hour

// Invite is a single-use password-set link.
type Invite struct {
	TokenHash string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// CreateInvite mints an invite token for a user, revokes the user's older
// unused invites, and returns the plaintext token (stored only as a hash).
func (s *Store) CreateInvite(ctx context.Context, userID string, now time.Time) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM invites WHERE user_id = ? AND used_at IS NULL`, userID); err != nil {
		return "", fmt.Errorf("store: revoke old invites: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO invites (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		HashSecret(token), userID, FormatTime(now), FormatTime(now.Add(inviteTTL)))
	if err != nil {
		return "", fmt.Errorf("store: create invite: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

// ConsumeInvite atomically marks the token used, sets the user's password
// hash, and returns the user, or ErrNotFound for unknown/expired/used tokens.
func (s *Store) ConsumeInvite(ctx context.Context, token, passwordHash string, now time.Time) (*User, error) {
	hash := HashSecret(token)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var userID string
	var expires, used any
	err = tx.QueryRowContext(ctx,
		`SELECT user_id, expires_at, used_at FROM invites WHERE token_hash = ?`,
		hash).
		Scan(&userID, &expires, &used)
	if err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if used != nil {
		return nil, ErrNotFound
	}
	exp, perr := ParseTime(expires.(string))
	if perr != nil || !now.Before(exp) {
		return nil, ErrNotFound
	}
	q := `UPDATE invites SET used_at = ? WHERE token_hash = ?`
	if _, err := tx.ExecContext(ctx, q, FormatTime(now), hash); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, userID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.UserByID(ctx, userID)
}
