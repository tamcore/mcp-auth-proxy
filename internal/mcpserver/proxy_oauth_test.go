package mcpserver

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/gate"
	"github.com/tamcore/mcp-auth-proxy/internal/metrics"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
	"github.com/tamcore/mcp-auth-proxy/internal/upstream"
)

// bearerUpstream fronts the echo upstream, rejects requests without a bearer
// and records which bearers it saw.
func bearerUpstream(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	target, _ := url.Parse(echoUpstream(t).URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	var mu sync.Mutex
	var seen []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		seen = append(seen, strings.TrimPrefix(auth, "Bearer "))
		mu.Unlock()
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

const oauthUp = "garmin"

// seedOAuthUsers creates u_a and u_b with their own tokens and u_c without.
func seedOAuthUsers(t *testing.T, st *store.Store, now time.Time) {
	t.Helper()
	ctx := context.Background()
	for _, uid := range []string{"u_a", "u_b", "u_c"} {
		if err := st.CreateUser(ctx, &store.User{ID: uid, Username: uid, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		if uid == "u_c" {
			continue
		}
		tok := &store.UpstreamToken{Upstream: oauthUp, UserID: uid, AccessToken: "at-" + uid}
		if err := st.SaveUpstreamToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOAuthUpstreamUsesKeyOwnersToken(t *testing.T) {
	ctx := context.Background()
	up, seen := bearerUpstream(t)
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	seedOAuthUsers(t, st, now)
	key := func(uid string) *store.Key {
		k := &store.Key{ID: "k_" + uid, Kind: store.KeyKindStatic, Label: uid, SecretHash: "h_" + uid,
			Upstreams: []string{oauthUp}, TTLSeconds: 3600, CreatedAt: now, UserID: &uid}
		if err := st.CreateKey(ctx, k); err != nil {
			t.Fatal(err)
		}
		return k
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pool := upstream.NewPool([]config.UpstreamConfig{{Name: oauthUp, URL: up.URL, OAuth: &config.UpstreamOAuthConfig{
		AuthorizeURL: "https://idp/authorize", TokenURL: "https://idp/token", ClientID: "c"}}}, st, nil, logger)
	g := gate.New(gate.Options{Store: st, Digits: 5, Expiry: time.Minute, MaxAttempts: 3, DefaultTTL: time.Hour,
		BaseURL: "http://p", SignSecret: []byte("0123456789abcdef0123456789abcdef"), Notifier: &fakeNotifier{}})
	p := New(Options{Pool: pool, Store: st, Gate: g, Metrics: metrics.New(nil), Logger: logger})

	for _, uid := range []string{"u_a", "u_b"} {
		if _, err := p.ServerFor(ctx, key(uid)); err != nil {
			t.Fatalf("%s: %v", uid, err)
		}
	}
	for _, b := range seen() {
		if b != "at-u_a" && b != "at-u_b" {
			t.Fatalf("unexpected bearer %q", b)
		}
	}
	got := strings.Join(seen(), ",")
	if !strings.Contains(got, "at-u_a") || !strings.Contains(got, "at-u_b") {
		t.Fatalf("each user must use their own token, saw %s", got)
	}
	assertUnlinkedKeepsAuth(t, p, key("u_c"))
}

// assertUnlinkedKeepsAuth checks that an unlinked upstream drops only its own
// tools: the key still gets the auth tool.
func assertUnlinkedKeepsAuth(t *testing.T, p *Proxy, k *store.Key) {
	t.Helper()
	srv, err := p.ServerFor(context.Background(), k)
	if err != nil {
		t.Fatalf("unlinked upstream must not fail the whole key: %v", err)
	}
	res, err := connectClient(t, srv).ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	if len(names) != 1 || names[0] != AuthToolName {
		t.Fatalf("want only the auth tool, got %v", names)
	}
}
