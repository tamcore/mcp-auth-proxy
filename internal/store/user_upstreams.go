package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
)

// UserUpstream is an MCP server a single user configured in the database.
type UserUpstream struct {
	ID        string
	UserID    string
	Name      string
	URL       string
	Command   []string
	Headers   map[string]string
	CreatedAt time.Time
}

// Config converts the row to an upstream config (namespace name unchanged).
func (u *UserUpstream) Config() config.UpstreamConfig {
	return config.UpstreamConfig{
		Name:    u.Name,
		URL:     u.URL,
		Command: u.Command,
		Headers: u.Headers,
	}
}

// CreateUserUpstream inserts a per-user upstream.
func (s *Store) CreateUserUpstream(ctx context.Context, u *UserUpstream) error {
	cmd, err := json.Marshal(u.Command)
	if err != nil {
		return fmt.Errorf("store: marshal command: %w", err)
	}
	hdr, err := json.Marshal(u.Headers)
	if err != nil {
		return fmt.Errorf("store: marshal headers: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO user_upstreams (id, user_id, name, url, command, headers, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.UserID, u.Name, u.URL, string(cmd), string(hdr), FormatTime(u.CreatedAt))
	if err != nil {
		return fmt.Errorf("store: create user upstream: %w", err)
	}
	return nil
}

// ListUserUpstreams returns all upstreams owned by a user.
func (s *Store) ListUserUpstreams(ctx context.Context, userID string) ([]*UserUpstream, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, user_id, name, url, command, headers, created_at FROM user_upstreams WHERE user_id = ? ORDER BY name`,
		userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*UserUpstream
	for rows.Next() {
		u, err := scanUserUpstream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// RunnableUserUpstreams returns the user's upstreams the proxy may start:
// stdio commands run only for admins, so a non-admin's command row (e.g.
// after a demotion) is never executed.
func (s *Store) RunnableUserUpstreams(ctx context.Context, userID string) ([]*UserUpstream, error) {
	user, err := s.UserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	all, err := s.ListUserUpstreams(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*UserUpstream, 0, len(all))
	for _, u := range all {
		if len(u.Command) == 0 || user.Admin {
			out = append(out, u)
		}
	}
	return out, nil
}

// DeleteUserUpstream removes one owned upstream. It fails if the id does not
// belong to the user.
func (s *Store) DeleteUserUpstream(ctx context.Context, userID, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM user_upstreams WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return fmt.Errorf("store: delete user upstream: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanUserUpstream(sc scanner) (*UserUpstream, error) {
	var u UserUpstream
	var cmd, hdr, created string
	if err := sc.Scan(&u.ID, &u.UserID, &u.Name, &u.URL, &cmd, &hdr, &created); err != nil {
		return nil, err
	}
	var perr error
	if err := json.Unmarshal([]byte(cmd), &u.Command); err != nil {
		return nil, fmt.Errorf("store: decode command: %w", err)
	}
	if hdr != "" && hdr != "null" {
		if err := json.Unmarshal([]byte(hdr), &u.Headers); err != nil {
			return nil, fmt.Errorf("store: decode headers: %w", err)
		}
	}
	if u.CreatedAt, perr = ParseTime(created); perr != nil {
		return nil, fmt.Errorf("store: decode created_at: %w", perr)
	}
	return &u, nil
}
