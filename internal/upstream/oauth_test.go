package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func TestRefreshRotationPersists(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	var refreshes atomic.Int32
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("resource") != "https://api/mcp" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n := refreshes.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  fmt.Sprintf("at-new-%d", n),
			"refresh_token": fmt.Sprintf("rt-new-%d", n),
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer tokenSrv.Close()

	// Upstream API: 401 without the right bearer, 200 with it.
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-new-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer apiSrv.Close()

	cfg := config.UpstreamConfig{
		Name: "api",
		URL:  apiSrv.URL,
		OAuth: &config.UpstreamOAuthConfig{
			AuthorizeURL: "http://unused/authorize",
			TokenURL:     tokenSrv.URL,
			ClientID:     "cid",
			Resource:     "https://api/mcp",
		},
	}
	expired := time.Now().Add(-time.Minute)
	if err := st.SaveUpstreamToken(ctx, &store.UpstreamToken{
		Upstream: "api", AccessToken: "at-stale", RefreshToken: "rt-old", ExpiresAt: &expired,
	}); err != nil {
		t.Fatal(err)
	}
	u := &Upstream{cfg: cfg, store: st, httpc: apiSrv.Client()}
	hc := u.httpClientWithAuth()
	resp, err := hc.Get(apiSrv.URL + "/data")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if refreshes.Load() == 0 {
		t.Fatal("refresh token was not used")
	}
	got, err := st.GetUpstreamToken(ctx, "api", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "at-new-1" || got.RefreshToken != "rt-new-1" {
		t.Fatalf("rotated set not persisted: %+v", got)
	}
}

func TestNoTokenIsNotFatal(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer apiSrv.Close()
	u := &Upstream{cfg: config.UpstreamConfig{Name: "open", URL: apiSrv.URL}, store: st, httpc: apiSrv.Client()}
	hc := u.httpClientWithAuth()
	resp, err := hc.Get(apiSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestUpstreamWithoutOAuthNeverSendsAStoredToken(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	operator := &store.UpstreamToken{Upstream: "linked", AccessToken: "operator-token"}
	if err := st.SaveUpstreamToken(ctx, operator); err != nil {
		t.Fatal(err)
	}
	var got atomic.Value
	got.Store("")
	userSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer userSrv.Close()
	u := NewFromConfig(config.UpstreamConfig{Name: "linked", URL: userSrv.URL}, st, userSrv.Client(), nil)
	resp, err := u.httpClientWithAuth().Get(userSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if auth := got.Load().(string); auth != "" {
		t.Fatalf("a user upstream named like a linked config upstream got %q", auth)
	}
}
