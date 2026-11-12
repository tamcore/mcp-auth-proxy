package webui

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

const (
	linkAdminID = "u_link_admin"
	linkUserID  = "u_link_user"
	linkPw      = "secret-pw"
	garmin      = "garmin"
)

// newLinkUI serves a garmin OAuth upstream (alice only via restricted
// "private-oauth") and seeds alice (admin) and bob.
func newLinkUI(t *testing.T, tokenURL string) (*store.Store, *httptest.Server) {
	t.Helper()
	oauth := &config.UpstreamOAuthConfig{AuthorizeURL: "https://idp/authorize", TokenURL: tokenURL, ClientID: "cid"}
	st, ts := newTestUI(t, func(c *config.Config) {
		c.Upstreams = append(c.Upstreams,
			config.UpstreamConfig{Name: garmin, URL: "https://g/mcp", OAuth: oauth},
			config.UpstreamConfig{Name: "private-oauth", URL: "https://p/mcp", OAuth: oauth, Users: []string{testAlice}})
	})
	hash, _ := store.HashPassword(linkPw)
	now := time.Now().UTC()
	for _, u := range []*store.User{
		{ID: linkAdminID, Username: testAlice, PasswordHash: hash, Admin: true, CreatedAt: now},
		{ID: linkUserID, Username: testBob, PasswordHash: hash, CreatedAt: now},
	} {
		if err := st.CreateUser(context.Background(), u); err != nil {
			t.Fatal(err)
		}
	}
	return st, ts
}

func TestUserLinksOwnUpstreamAccount(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("code") != "the-code" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt"}`))
	}))
	defer tokenSrv.Close()
	st, ts := newLinkUI(t, tokenSrv.URL)
	ctx := context.Background()
	alice := login(t, ts, testAlice, linkPw)
	bob := login(t, ts, testBob, linkPw)

	if loc := postLink(t, ts, bob, "private-oauth"); loc != "" {
		t.Fatalf("bob must not link an upstream he may not use, got redirect %q", loc)
	}
	authz, err := url.Parse(postLink(t, ts, bob, garmin))
	if err != nil || authz.Host != "idp" {
		t.Fatalf("user must be sent to the authorize endpoint: %v %v", authz, err)
	}
	if got := authz.Query().Get("redirect_uri"); got != "http://proxy.local/portal/upstream/callback" {
		t.Fatalf("redirect_uri %q", got)
	}
	state := authz.Query().Get("state")
	if code := callback(t, ts, alice, state); code == http.StatusSeeOther {
		t.Fatal("another user must not finish bob's link")
	}
	if code := callback(t, ts, bob, state); code != http.StatusSeeOther {
		t.Fatalf("callback: %d", code)
	}
	if tok, err := st.GetUpstreamToken(ctx, garmin, linkUserID); err != nil || tok.AccessToken != "at" {
		t.Fatalf("token not stored for bob: %+v %v", tok, err)
	}
	if _, err := st.GetUpstreamToken(ctx, garmin, linkAdminID); err == nil {
		t.Fatal("bob's link must not give alice a token")
	}
	if code := callback(t, ts, bob, state); code != http.StatusBadRequest {
		t.Fatalf("state must be single-use, got %d", code)
	}
}

func TestPortalShowsOwnLinkState(t *testing.T) {
	st, ts := newLinkUI(t, "https://idp/token")
	bob := login(t, ts, testBob, linkPw)
	body := portalBody(t, ts, bob)
	if !strings.Contains(body, "not linked") || !strings.Contains(body, `action="/portal/upstream/link"`) {
		t.Fatal("portal must show link state and a Link button to every user")
	}
	if err := st.SaveUpstreamToken(context.Background(),
		&store.UpstreamToken{Upstream: garmin, UserID: linkAdminID, AccessToken: "at"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(portalBody(t, ts, bob), "Re-link") {
		t.Fatal("alice's link must not show as linked for bob")
	}
	if !strings.Contains(portalBody(t, ts, login(t, ts, testAlice, linkPw)), "Re-link") {
		t.Fatal("alice's garmin must show as linked for alice")
	}
}

func postLink(t *testing.T, ts *httptest.Server, cookie *http.Cookie, name string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/portal/upstream/link",
		strings.NewReader(url.Values{nameField: {name}}.Encode()))
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
		ts.URL+"/portal/upstream/callback?"+url.Values{"state": {state}, "code": {"the-code"}}.Encode(), nil)
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func portalBody(t *testing.T, ts *httptest.Server, cookie *http.Cookie) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestOwnUpstreamWithBearerToken(t *testing.T) {
	st, ts := newLinkUI(t, "https://idp/token")
	bob := login(t, ts, testBob, linkPw)
	form := url.Values{nameField: {"ha"}, urlField: {mcpUpstream(t, "llat_secret")}, "bearer": {"llat_secret"}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/portal/upstream", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(bob)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	ups, err := st.ListUserUpstreams(context.Background(), linkUserID)
	if err != nil || len(ups) != 1 || ups[0].Headers["Authorization"] != "Bearer llat_secret" {
		t.Fatalf("bearer not stored as Authorization header: %+v %v", ups, err)
	}
	if strings.Contains(portalBody(t, ts, bob), "llat_secret") {
		t.Fatal("token must never be shown again")
	}
}
