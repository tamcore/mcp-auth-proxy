// Package identity resolves incoming credentials (static mak_ keys or OAuth
// map_ access tokens) to a store.Key. Identity is never authorization: resolving
// a credential only proves who the client is, not that a tool call is allowed.
package identity

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

// ErrUnauthorized is the single sentinel for any credential failure. Callers
// must not leak which check failed, and no token material is ever logged.
var ErrUnauthorized = errors.New("identity: unauthorized")

// Token prefixes.
const (
	StaticPrefix = "mak_"
	OAuthPrefix  = "map_"
)

// Resolver maps bearer or path tokens to keys.
type Resolver struct {
	store *store.Store
	now   func() time.Time
}

// New builds a Resolver.
func New(s *store.Store, now func() time.Time) *Resolver {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Resolver{store: s, now: now}
}

// Resolve maps a presented token to a live, unrevoked key.
func (r *Resolver) Resolve(ctx context.Context, token string) (*store.Key, error) {
	switch {
	case strings.HasPrefix(token, StaticPrefix):
		return r.resolveStatic(ctx, token)
	case strings.HasPrefix(token, OAuthPrefix):
		return r.resolveOAuth(ctx, token)
	default:
		return nil, ErrUnauthorized
	}
}

func (r *Resolver) resolveStatic(ctx context.Context, token string) (*store.Key, error) {
	key, err := r.store.KeyByHash(ctx, store.HashSecret(token))
	if err != nil {
		return nil, ErrUnauthorized
	}
	return r.checkLive(ctx, key)
}

func (r *Resolver) resolveOAuth(ctx context.Context, token string) (*store.Key, error) {
	at, err := r.store.AccessTokenByHash(ctx, store.HashSecret(token), r.now())
	if err != nil {
		return nil, ErrUnauthorized
	}
	key, err := r.store.KeyByID(ctx, at.KeyID)
	if err != nil {
		return nil, ErrUnauthorized
	}
	return r.checkLive(ctx, key)
}

func (r *Resolver) checkLive(ctx context.Context, key *store.Key) (*store.Key, error) {
	if key.Revoked() {
		return nil, ErrUnauthorized
	}
	if key.UserID != nil {
		u, err := r.store.UserByID(ctx, *key.UserID)
		if err != nil || u.Disabled {
			return nil, ErrUnauthorized
		}
	}
	return key, nil
}
