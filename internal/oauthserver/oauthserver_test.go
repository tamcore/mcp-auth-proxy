package oauthserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
	"github.com/tamcore/mcp-auth-proxy/internal/ui"
)

const (
	testClientID = "claude"
	testRedirect = "https://claude.ai/api/mcp/cb"
)

func testConfig() *config.Config {
	return &config.Config{
		BaseURL:    "http://proxy.local",
		ListenAddr: "127.0.0.1:0",
		StateDir:   "./data",
		SessionTTL: 8 * time.Hour,
		OAuth: config.OAuthConfig{
			TokenTTL:         24 * time.Hour,
			AuthorizeCodeTTL: 10 * time.Minute,
			Clients: []config.ClientConfig{{
				ClientID:     testClientID,
				Name:         "Claude",
				RedirectURIs: []string{testRedirect},
			}},
		},
		Upstreams: []config.UpstreamConfig{{Name: "echo", Command: []string{"x"}}},
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s, err := New(context.Background(), st, testConfig(), ui.New(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func challengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func authorizeQuery(verifier, method string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirect},
		"code_challenge":        {challengeS256(verifier)},
		"code_challenge_method": {method},
		"state":                 {"st1"},
	}
}

// consentAndGetCode runs authorize+consent and returns the issued code.
func consentAndGetCode(t *testing.T, s *Server, verifier string) string {
	t.Helper()
	q := authorizeQuery(verifier, "S256")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	s.HandleAuthorize(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorize: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "never authorizes tool calls") &&
		!strings.Contains(rec.Body.String(), "Every proxied tool call still requires") {
		t.Fatalf("consent page not honest: %s", rec.Body.String())
	}
	form := url.Values{}
	for k := range q {
		form.Set(k, q.Get(k))
	}
	form.Set("label", "Claude on laptop")
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.HandleConsent(rec2, req2)
	if rec2.Code != http.StatusFound {
		t.Fatalf("consent: %d %s", rec2.Code, rec2.Body.String())
	}
	loc, err := url.Parse(rec2.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query().Get("code")
}

func tokenForm(code, verifier string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"client_id":     {testClientID},
		"code_verifier": {verifier},
	}
}

func TestAuthorizeFailClosedMatrix(t *testing.T) {
	s := newTestServer(t)
	base := authorizeQuery("v", "S256")
	mutate := map[string]func(q url.Values){
		"unknown client":  func(q url.Values) { q.Set("client_id", "nope") },
		"bad redirect":    func(q url.Values) { q.Set("redirect_uri", "https://evil/cb") },
		"plain pkce":      func(q url.Values) { q.Set("code_challenge_method", "plain") },
		"missing method":  func(q url.Values) { q.Del("code_challenge_method") },
		"missing chall":   func(q url.Values) { q.Del("code_challenge") },
		"wrong resp type": func(q url.Values) { q.Set("response_type", "token") },
	}
	for name, m := range mutate {
		t.Run(name, func(t *testing.T) {
			q := authorizeQuery("v", "S256")
			m(q)
			rec := httptest.NewRecorder()
			s.HandleAuthorize(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d", rec.Code)
			}
			var e map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e["error"] == "" {
				t.Fatalf("error body: %s", rec.Body.String())
			}
		})
	}
	_ = base
}

func TestFullFlowIssuesToken(t *testing.T) {
	s := newTestServer(t)
	verifier := "test-verifier-123"
	code := consentAndGetCode(t, s, verifier)
	if code == "" {
		t.Fatal("no code")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm(code, verifier).Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.HandleToken(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	tok, _ := resp["access_token"].(string)
	if !strings.HasPrefix(tok, "map_") {
		t.Fatalf("token prefix: %q", tok)
	}
	if resp["token_type"] != "Bearer" {
		t.Fatalf("token_type: %v", resp["token_type"])
	}
	if _, ok := resp["refresh_token"]; ok {
		t.Fatal("v1 must not issue refresh tokens")
	}
}

func TestTokenEndpointFailClosed(t *testing.T) {
	s := newTestServer(t)
	verifier := "v-abc"
	code := consentAndGetCode(t, s, verifier)
	post := func(f url.Values) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		s.HandleToken(rec, req)
		return rec
	}
	if rec := post(tokenForm(code, "wrong-verifier")); rec.Code == http.StatusOK {
		t.Fatal("wrong verifier must fail")
	}
	// Reuse of the consumed code must fail (single-use): use a fresh code though,
	// because the wrong-verifier attempt consumed it.
	code2 := consentAndGetCode(t, s, verifier)
	if rec := post(tokenForm(code2, verifier)); rec.Code != http.StatusOK {
		t.Fatalf("valid exchange failed: %s", rec.Body.String())
	}
	if rec := post(tokenForm(code2, verifier)); rec.Code == http.StatusOK {
		t.Fatal("code reuse must fail")
	}
	bad := tokenForm("nonexistent", verifier)
	if rec := post(bad); rec.Code == http.StatusOK {
		t.Fatal("unknown code must fail")
	}
	wrongGrant := tokenForm(code, verifier)
	wrongGrant.Set("grant_type", "refresh_token")
	if rec := post(wrongGrant); rec.Code == http.StatusBadRequest {
		if !strings.Contains(rec.Body.String(), "unsupported_grant_type") {
			t.Fatalf("body %s", rec.Body.String())
		}
	} else {
		t.Fatal("refresh_token grant must be rejected")
	}
	mismatch := tokenForm(code, verifier)
	mismatch.Set("redirect_uri", "https://other/cb")
	if rec := post(mismatch); rec.Code == http.StatusOK {
		t.Fatal("redirect mismatch must fail")
	}
}
