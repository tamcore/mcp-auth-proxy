package identity

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

const oauthKeyID = "k_o"

func setup(t *testing.T) (*Resolver, *store.Store) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	static := &store.Key{ID: "k_s", Kind: store.KeyKindStatic, Label: "s", SecretHash: store.HashSecret("mak_static"),
		Upstreams: []string{"e"}, TTLSeconds: 60, CreatedAt: now}
	oauth := &store.Key{ID: oauthKeyID, Kind: store.KeyKindOAuth, Label: "o", SecretHash: store.HashSecret("x"),
		Upstreams: []string{"e"}, TTLSeconds: 60, CreatedAt: now}
	for _, k := range []*store.Key{static, oauth} {
		if err := st.CreateKey(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	at := &store.AccessToken{TokenHash: store.HashSecret("map_live"), KeyID: oauthKeyID, ClientID: "c",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := st.CreateAccessToken(ctx, at); err != nil {
		t.Fatal(err)
	}
	expired := &store.AccessToken{TokenHash: store.HashSecret("map_old"), KeyID: oauthKeyID, ClientID: "c",
		ExpiresAt: now.Add(-time.Minute), CreatedAt: now.Add(-2 * time.Hour)}
	if err := st.CreateAccessToken(ctx, expired); err != nil {
		t.Fatal(err)
	}
	return New(st, func() time.Time { return now }), st
}

func TestResolveStatic(t *testing.T) {
	r, _ := setup(t)
	key, err := r.Resolve(context.Background(), "mak_static")
	if err != nil || key.ID != "k_s" {
		t.Fatalf("static: %v %+v", err, key)
	}
}

func TestResolveOAuth(t *testing.T) {
	r, _ := setup(t)
	key, err := r.Resolve(context.Background(), "map_live")
	if err != nil || key.ID != oauthKeyID {
		t.Fatalf("oauth: %v %+v", err, key)
	}
}

func TestResolveFailures(t *testing.T) {
	r, st := setup(t)
	ctx := context.Background()
	cases := []string{"mak_wrong", "map_old", "map_unknown", "garbage", ""}
	for _, tok := range cases {
		if _, err := r.Resolve(ctx, tok); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("token %q: want ErrUnauthorized, got %v", tok, err)
		}
	}
	// Revoked key refused even with a valid static token.
	if err := st.RevokeKey(ctx, "k_s", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(ctx, "mak_static"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked key: want ErrUnauthorized, got %v", err)
	}
}
