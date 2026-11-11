package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func TestAdminLinksOAuthUpstream(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("code") != "the-code" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt"}`))
	}))
	defer tokenSrv.Close()
	st, ts := newTestUI(t, func(c *config.Config) {
		c.Upstreams = append(c.Upstreams, config.UpstreamConfig{Name: "garmin", URL: "https://g/mcp",
			OAuth: &config.UpstreamOAuthConfig{AuthorizeURL: "https://idp/authorize", TokenURL: tokenSrv.URL, ClientID: "cid"}})
	})
	ctx := context.Background()
	hash, _ := store.HashPassword("secret-pw")
	for _, u := range []*store.User{
		{ID: "u_link_admin", Username: testAlice, PasswordHash: hash, Admin: true, CreatedAt: time.Now().UTC()},
		{ID: "u_link_user", Username: testBob, PasswordHash: hash, CreatedAt: time.Now().UTC()},
	} {
		if err := st.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	alice := login(t, ts, testAlice, "secret-pw")
	bob := login(t, ts, testBob, "secret-pw")

	if loc := postLink(t, ts, bob, "garmin"); loc != "/" {
		t.Fatalf("non-admin must be sent away, got %q", loc)
	}
	authz, err := url.Parse(postLink(t, ts, alice, "garmin"))
	if err != nil || authz.Host != "idp" {
		t.Fatalf("admin must be sent to the authorize endpoint: %v %v", authz, err)
	}
	if got := authz.Query().Get("redirect_uri"); got != "http://proxy.local/admin/upstream/callback" {
		t.Fatalf("redirect_uri %q", got)
	}
	state := authz.Query().Get("state")

	if code := callback(t, ts, bob, state); code == http.StatusSeeOther {
		t.Fatal("another user must not finish the admin's link")
	}
	if code := callback(t, ts, alice, state); code != http.StatusSeeOther {
		t.Fatalf("callback: %d", code)
	}
	if tok, err := st.GetUpstreamToken(ctx, "garmin"); err != nil || tok.AccessToken != "at" {
		t.Fatalf("token not stored: %+v %v", tok, err)
	}
	if code := callback(t, ts, alice, state); code != http.StatusBadRequest {
		t.Fatalf("state must be single-use, got %d", code)
	}
}

func postLink(t *testing.T, ts *httptest.Server, cookie *http.Cookie, name string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/upstream/link",
		strings.NewReader(url.Values{"name": {name}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.Header.Get("Location")
}

func callback(t *testing.T, ts *httptest.Server, cookie *http.Cookie, state string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet,
		ts.URL+"/admin/upstream/callback?"+url.Values{"state": {state}, "code": {"the-code"}}.Encode(), nil)
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
