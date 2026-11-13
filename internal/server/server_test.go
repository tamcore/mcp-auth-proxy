package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	ts := httptest.NewServer(newTestSrv(t).Handler())
	t.Cleanup(ts.Close)
	return ts
}

func newTestSrv(t *testing.T) *Server {
	t.Helper()
	return newTestSrvLogged(t, nil)
}

func newTestSrvLogged(t *testing.T, logger *slog.Logger) *Server {
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
	m := metrics.New(nil, st, logger)
	g.OnChallenge = func(ctx context.Context, key *store.Key) { m.Challenge(metrics.WhoOf(ctx, st, key)) }
	pool := upstream.NewPool(cfg.Upstreams, st, nil, nil)
	proxy := mcpserver.New(mcpserver.Options{Pool: pool, Store: st, Gate: g, Metrics: m, AuditEnabled: true})
	srv, err := New(ctx, cfg, st, g, proxy, m, secret, logger)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func statusOf(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestOpsEndpointsOnlyOnOpsListener(t *testing.T) {
	srv := newTestSrv(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	ops := httptest.NewServer(srv.OpsHandler())
	defer ops.Close()
	for _, path := range []string{"/metrics", "/healthz", "/readyz"} {
		if code := statusOf(t, ops.URL+path); code != http.StatusOK {
			t.Fatalf("ops %s: %d", path, code)
		}
		if code := statusOf(t, ts.URL+path); code == http.StatusOK {
			t.Fatalf("app listener must not serve %s", path)
		}
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

func TestConsentRequiresWebLogin(t *testing.T) {
	ts := newTestServer(t)
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	form := url.Values{"response_type": {"code"}, "client_id": {"c"}, "redirect_uri": {"https://x/cb"},
		"code_challenge": {"x"}, "code_challenge_method": {"S256"}}
	resp, err := client.PostForm(ts.URL+"/oauth/consent", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "/login") {
		t.Fatalf("want 302 to login, got %d %q", resp.StatusCode, loc)
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

func TestApproveDenyAllowCrossOriginFromNtfyWebApp(t *testing.T) {
	ts := newTestServer(t)
	for _, path := range []string{"/approve/x", "/deny/x"} {
		req, _ := http.NewRequest(http.MethodOptions, ts.URL+path, nil)
		req.Header.Set("Origin", "https://ntfy.example")
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent || resp.Header.Get("Access-Control-Allow-Origin") != "*" ||
			!strings.Contains(resp.Header.Get("Access-Control-Allow-Methods"), http.MethodPost) {
			t.Fatalf("%s preflight: %d %v", path, resp.StatusCode, resp.Header)
		}
		resp, err = http.Post(ts.URL+path+"?sig=bad", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("%s: bad sig must stay 403 and carry CORS: %d", path, resp.StatusCode)
		}
	}
}

func TestAccessLogRedactsSecrets(t *testing.T) {
	var buf bytes.Buffer
	srv := newTestSrvLogged(t, slog.New(slog.NewJSONHandler(&buf, nil)))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	for _, path := range []string{"/mcp/mak_supersecret", "/invite/invsecret", "/approve/c1?sig=sigsecret"} {
		_ = statusOf(t, ts.URL+path)
	}
	logs := buf.String()
	for _, secret := range []string{"mak_supersecret", "invsecret", "sigsecret"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("access log leaks %q: %s", secret, logs)
		}
	}
	for _, want := range []string{`"msg":"http request"`, `"path":"/mcp/[redacted]"`, `"path":"/invite/[redacted]"`,
		`"path":"/approve/c1"`, `"status":401`} {
		if !strings.Contains(logs, want) {
			t.Fatalf("access log missing %s: %s", want, logs)
		}
	}
}

func TestAuthenticatedRequestMarksKeyUsed(t *testing.T) {
	srv := newTestSrv(t)
	ctx := context.Background()
	const token = "mak_lastused"
	key := &store.Key{ID: "k_used", Kind: store.KeyKindStatic, Label: "l", SecretHash: store.HashSecret(token),
		Upstreams: []string{}, TTLSeconds: 60, CreatedAt: time.Now().UTC()}
	if err := srv.store.CreateKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	got, err := srv.store.KeyByID(ctx, key.ID)
	if err != nil || got.LastUsedAt == nil {
		t.Fatalf("authenticated request must set last_used_at: %+v %v", got, err)
	}
}

func TestApproveResultLinksBackToPortal(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Post(ts.URL+"/approve/x?sig=bad", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `href="/"`) || !strings.Contains(string(body), "Back to portal") {
		t.Fatal("result page must link back to the portal")
	}
}

func TestHSTSOnlyForHTTPSBaseURL(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})
	for base, want := range map[string]bool{"https://proxy.example": true, "http://127.0.0.1:8080": false} {
		rec := httptest.NewRecorder()
		strictTransport(base, ok).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if got := rec.Header().Get("Strict-Transport-Security") != ""; got != want {
			t.Fatalf("%s: HSTS set=%v, want %v", base, got, want)
		}
	}
}
