package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// OAuthClient is a config-registered client of the client-facing
// authorization server.
type OAuthClient struct {
	ClientID     string
	Name         string
	RedirectURIs []string
	Confidential bool
	CreatedAt    time.Time
}

// UpsertOAuthClient registers a client from config.
func (s *Store) UpsertOAuthClient(ctx context.Context, c *OAuthClient) error {
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return fmt.Errorf("store: marshal redirect uris: %w", err)
	}
	conf := 0
	if c.Confidential {
		conf = 1
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO oauth_clients (client_id, name, redirect_uris, confidential, created_at) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (client_id) DO UPDATE SET name = excluded.name,
    redirect_uris = excluded.redirect_uris, confidential = excluded.confidential`,
		c.ClientID, c.Name, string(uris), conf, FormatTime(c.CreatedAt))
	if err != nil {
		return fmt.Errorf("store: upsert oauth client: %w", err)
	}
	return nil
}

// OAuthClientByID loads a registered client.
func (s *Store) OAuthClientByID(ctx context.Context, clientID string) (*OAuthClient, error) {
	var c OAuthClient
	var uris, created string
	var conf int
	err := scanOne(ctx, s,
		`SELECT client_id, name, redirect_uris, confidential, created_at FROM oauth_clients WHERE client_id = ?`,
		[]any{clientID}, &c.ClientID, &c.Name, &uris, &conf, &created)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(uris), &c.RedirectURIs); err != nil {
		return nil, fmt.Errorf("store: decode redirect uris: %w", err)
	}
	c.Confidential = conf == 1
	if c.CreatedAt, err = ParseTime(created); err != nil {
		return nil, fmt.Errorf("store: decode client created_at: %w", err)
	}
	return &c, nil
}

// ListOAuthClients returns all registered clients.
func (s *Store) ListOAuthClients(ctx context.Context) ([]*OAuthClient, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT client_id, name, redirect_uris, confidential, created_at FROM oauth_clients ORDER BY client_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*OAuthClient
	for rows.Next() {
		var c OAuthClient
		var uris, created string
		var conf int
		if err := rows.Scan(&c.ClientID, &c.Name, &uris, &conf, &created); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(uris), &c.RedirectURIs); err != nil {
			return nil, err
		}
		c.Confidential = conf == 1
		if c.CreatedAt, err = ParseTime(created); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// AccessToken is a client-facing OAuth access token (map_*). Only the hash is
// stored.
type AccessToken struct {
	TokenHash string
	KeyID     string
	ClientID  string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// CreateAccessToken stores a new access token hash.
func (s *Store) CreateAccessToken(ctx context.Context, t *AccessToken) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO access_tokens (token_hash, key_id, client_id, expires_at, created_at)
VALUES (?, ?, ?, ?, ?)`,
		t.TokenHash, t.KeyID, t.ClientID, FormatTime(t.ExpiresAt), FormatTime(t.CreatedAt))
	if err != nil {
		return fmt.Errorf("store: create access token: %w", err)
	}
	return nil
}

// AccessTokenByHash resolves an unexpired access token by hash.
func (s *Store) AccessTokenByHash(ctx context.Context, hash string, now time.Time) (*AccessToken, error) {
	var t AccessToken
	var expires, created string
	err := scanOne(ctx, s,
		`SELECT token_hash, key_id, client_id, expires_at, created_at FROM access_tokens WHERE token_hash = ?`,
		[]any{hash}, &t.TokenHash, &t.KeyID, &t.ClientID, &expires, &created)
	if err != nil {
		return nil, err
	}
	var perr error
	if t.ExpiresAt, perr = ParseTime(expires); perr != nil {
		return nil, fmt.Errorf("store: decode token expires_at: %w", perr)
	}
	if t.CreatedAt, perr = ParseTime(created); perr != nil {
		return nil, fmt.Errorf("store: decode token created_at: %w", perr)
	}
	if !now.Before(t.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &t, nil
}

// UpstreamToken is the stored token set of one upstream OAuth link.
type UpstreamToken struct {
	Upstream     string
	AccessToken  string
	RefreshToken string
	ExpiresAt    *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// GetUpstreamToken loads the stored token set for an upstream.
func (s *Store) GetUpstreamToken(ctx context.Context, upstream string) (*UpstreamToken, error) {
	var t UpstreamToken
	var expires any
	var created, updated string
	err := scanOne(ctx, s,
		`SELECT upstream, access_token, refresh_token, expires_at, created_at, updated_at
FROM upstream_tokens WHERE upstream = ?`,
		[]any{upstream},
		&t.Upstream, &t.AccessToken, &t.RefreshToken, &expires, &created, &updated)
	if err != nil {
		return nil, err
	}
	var perr error
	if t.CreatedAt, perr = ParseTime(created); perr != nil {
		return nil, fmt.Errorf("store: decode upstream token created_at: %w", perr)
	}
	if t.UpdatedAt, perr = ParseTime(updated); perr != nil {
		return nil, fmt.Errorf("store: decode upstream token updated_at: %w", perr)
	}
	if es, ok := expires.(string); ok && es != "" {
		et, perr := ParseTime(es)
		if perr != nil {
			return nil, fmt.Errorf("store: decode upstream token expires_at: %w", perr)
		}
		t.ExpiresAt = &et
	}
	return &t, nil
}

// SaveUpstreamToken upserts the (possibly rotated) token set of an upstream.
func (s *Store) SaveUpstreamToken(ctx context.Context, t *UpstreamToken) error {
	var expires any
	if t.ExpiresAt != nil {
		expires = FormatTime(*t.ExpiresAt)
	}
	now := FormatTime(nowUTC())
	_, err := s.db.ExecContext(ctx, `
INSERT INTO upstream_tokens (upstream, access_token, refresh_token, expires_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (upstream) DO UPDATE SET access_token = excluded.access_token, refresh_token = excluded.refresh_token,
    expires_at = excluded.expires_at, updated_at = excluded.updated_at`,
		t.Upstream, t.AccessToken, t.RefreshToken, expires, now, now)
	if err != nil {
		return fmt.Errorf("store: save upstream token: %w", err)
	}
	return nil
}
