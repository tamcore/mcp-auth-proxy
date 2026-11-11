package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/gate"
	"github.com/tamcore/mcp-auth-proxy/internal/mcpserver"
	"github.com/tamcore/mcp-auth-proxy/internal/metrics"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
	"github.com/tamcore/mcp-auth-proxy/internal/upstream"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	secret, err := store.EnsureSignSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		BaseURL:    "http://proxy.local",
		ListenAddr: "127.0.0.1:0",
		StateDir:   dir,
		SessionTTL: 8 * time.Hour,
		OTP:        config.OTPConfig{Digits: 5, Expiry: 3 * time.Minute, Attempts: 3, RenotifyFloor: 30 * time.Second},
		Upstreams:  []config.UpstreamConfig{{Name: "echo", Command: []string{"true"}}},
		OAuth:      config.OAuthConfig{TokenTTL: 24 * time.Hour, AuthorizeCodeTTL: 10 * time.Minute},
	}
	g := gate.New(gate.Options{
		Store: st, Digits: 5, Expiry: 3 * time.Minute, MaxAttempts: 3,
		RenotifyFloor: 30 * time.Second, DefaultTTL: 8 * time.Hour,
		BaseURL: cfg.BaseURL, SignSecret: secret,
	})
	m := metrics.New(nil)
	g.OnChallenge = m.Challenge
	pool := upstream.NewPool(cfg.Upstreams, st, nil, nil)
	proxy := mcpserver.New(mcpserver.Options{Pool: pool, Store: st, Gate: g, Metrics: m, AuditEnabled: true})
	srv, err := New(ctx, cfg, st, g, proxy, m, secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestMetricsEndpoint(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status %d", resp.StatusCode)
	}
}

func TestMCPRequiresCredential(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate")
	}
}

func TestApproveBadSigIs403(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Post(ts.URL+"/approve/c1?sig=deadbeef", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
	resp2, err := http.Post(ts.URL+"/deny/c1", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("missing sig: want 403, got %d", resp2.StatusCode)
	}
}

func TestAuthorizeRequiresWebLogin(t *testing.T) {
	ts := newTestServer(t)
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	for _, q := range []string{
		"", "response_type=code", "response_type=code&client_id=nope&redirect_uri=https://x/cb",
	} {
		resp, err := client.Get(ts.URL + "/oauth/authorize?" + q)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("q=%q: want 302 to login, got %d", q, resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login") {
			t.Fatalf("q=%q: location %q", q, loc)
		}
	}
}

func TestLoginPageServed(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login page: %d", resp.StatusCode)
	}
}
