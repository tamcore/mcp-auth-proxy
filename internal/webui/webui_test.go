package webui

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/gate"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
	view "github.com/tamcore/mcp-auth-proxy/internal/ui"
)

const (
	testAlice  = "alice"
	testBob    = "bob"
	userField  = "username"
	testEcho   = "echo"
	testClaude = "claude"
	testBobPw  = "bob-password-1"
	pwField    = "password"
)

func newTestUI(t *testing.T, mutate ...func(*config.Config)) (*store.Store, *httptest.Server) {
	t.Helper()
	st, ts, _ := newTestUIGate(t, mutate...)
	return st, ts
}

// newTestUIGate also returns the gate that backs the portal's pending card.
func newTestUIGate(t *testing.T, mutate ...func(*config.Config)) (*store.Store, *httptest.Server, *gate.Gate) {
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
		Users:      []string{testAlice, testBob},
		Upstreams: []config.UpstreamConfig{
			{Name: testEcho, Command: []string{"true"}},
			{Name: "private", Command: []string{"true"}, Users: []string{testAlice}},
		},
		Audit: config.AuditConfig{Enabled: true, Retention: 720 * time.Hour},
		OAuth: config.OAuthConfig{TokenTTL: time.Hour, AuthorizeCodeTTL: 10 * time.Minute},
	}
	for _, f := range mutate {
		f(cfg)
	}
	g := gate.New(gate.Options{Store: st, Digits: 5, Expiry: 3 * time.Minute, MaxAttempts: 3,
		RenotifyFloor: 30 * time.Second, DefaultTTL: 8 * time.Hour, BaseURL: cfg.BaseURL, SignSecret: secret})
	ui := New(st, cfg, secret, view.New(nil), g, nil)
	mux := http.NewServeMux()
	ui.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return st, ts, g
}

func seedUser(t *testing.T, st *store.Store, name, pw string) *store.User {
	t.Helper()
	hash, err := store.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{ID: "u_" + name, Username: name, PasswordHash: hash, CreatedAt: time.Now().UTC()}
	if err := st.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func login(t *testing.T, ts *httptest.Server, user, pw string) *http.Cookie {
	t.Helper()
	resp, err := noRedirectClient().PostForm(ts.URL+"/login", url.Values{userField: {user}, "password": {pw}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookie {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func TestLoginLogoutFlow(t *testing.T) {
	st, ts := newTestUI(t)
	seedUser(t, st, testAlice, "secret-pw")

	// wrong password -> 401
	resp, err := noRedirectClient().PostForm(ts.URL+"/login", url.Values{userField: {testAlice}, "password": {"nope"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong pw: %d", resp.StatusCode)
	}

	cookie := login(t, ts, testAlice, "secret-pw")

	// portal reachable with cookie
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.AddCookie(cookie)
	resp, err = noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), testAlice) {
		t.Fatalf("portal: %d %s", resp.StatusCode, body)
	}
	// alice sees the private upstream, bob would not
	if !strings.Contains(string(body), "private") {
		t.Fatal("alice should see the alice-only upstream")
	}

	// without cookie -> redirect to /login
	resp, err = noRedirectClient().Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("anon portal: %d", resp.StatusCode)
	}
}

func TestPortalKeyCreateVisibilityAndAudit(t *testing.T) {
	st, ts := newTestUI(t)
	alice := seedUser(t, st, testAlice, "pw-alice")
	seedUser(t, st, testBob, "pw-bob")
	cookie := login(t, ts, testAlice, "pw-alice")

	// create a key choosing an upstream bob-only/private not allowed: "private" IS alice's; use a bogus one
	form := url.Values{"label": {testClaude}, upstreamField: {testEcho, "bogus"}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/portal/key", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bogus upstream must be rejected: %d", resp.StatusCode)
	}

	// valid creation shows the token once
	form = url.Values{"label": {testClaude}, upstreamField: {testEcho}}
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/portal/key", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err = noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "mak_") {
		t.Fatalf("token not shown once: %d", resp.StatusCode)
	}
	assertNewKeyBanner(t, string(body))
	keys, err := st.ListKeys(context.Background())
	if err != nil || len(keys) != 1 || keys[0].UserID == nil || *keys[0].UserID != alice.ID {
		t.Fatalf("key not bound to alice: %v %v", keys, err)
	}

	// audit entry visible on the audit page
	resp2 := strings.NewReader("")
	_ = resp2
	if err := st.AppendAudit(context.Background(), &store.AuditEntry{
		ID: "a_1", UserID: alice.ID, KeyID: keys[0].ID, KeyLabel: testClaude,
		ToolName: "echo__echo", Arguments: `{"text":"hi"}`, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/portal/audit", nil)
	req.AddCookie(cookie)
	resp, err = noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "echo__echo") || !strings.Contains(string(body), "text") {
		t.Fatalf("audit page missing entry: %s", body)
	}

	// bob cannot see alice's audit
	bobCookie := login(t, ts, testBob, "pw-bob")
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/portal/audit", nil)
	req.AddCookie(bobCookie)
	resp, err = noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(body), "echo__echo") {
		t.Fatal("bob must not see alice's audit entries")
	}
}

func TestEnsureConfigUsersMintsInvitesOnce(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	invites, err := st.EnsureConfigUsers(ctx, []string{testAlice, testBob}, []string{testAlice}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(invites) != 2 || invites[testAlice] == "" {
		t.Fatalf("invites: %v", invites)
	}
	u, err := st.UserByName(ctx, testAlice)
	if err != nil || !u.Admin || u.Disabled {
		t.Fatalf("alice must be admin: %+v %v", u, err)
	}
	if store.CheckPassword(u.PasswordHash, "anything") {
		t.Fatal("fresh user must have no usable password before the invite sets one")
	}
	// invite is consumable exactly once
	if _, err := st.ConsumeInvite(ctx, invites[testAlice], time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ConsumeInvite(ctx, invites[testAlice], time.Now().UTC()); err != store.ErrNotFound {
		t.Fatalf("reuse must fail: %v", err)
	}
	// second run re-mints invites for users who still have no password
	invites2, err := st.EnsureConfigUsers(ctx, []string{testAlice, testBob}, nil, time.Now().UTC())
	if err != nil || len(invites2) != 2 {
		t.Fatalf("passwordless users must get a fresh invite each start: %v %v", invites2, err)
	}
	// re-minting revokes the previous unused link
	if _, err := st.ConsumeInvite(ctx, invites[testBob], time.Now().UTC()); err != store.ErrNotFound {
		t.Fatalf("superseded invite must be invalid: %v", err)
	}
	if _, err := st.ConsumeInvite(ctx, invites2[testBob], time.Now().UTC()); err != nil {
		t.Fatalf("fresh invite must work: %v", err)
	}
}

func TestLoginPageNeverShowsInvites(t *testing.T) {
	st, ts := newTestUI(t)
	if _, err := st.EnsureConfigUsers(context.Background(), []string{testAlice}, nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(body), "/invite/") || strings.Contains(string(body), testAlice) {
		t.Fatal("login page must not expose invite links or usernames")
	}
}

func TestAdminMarksPendingInvite(t *testing.T) {
	st, ts := newTestUI(t)
	ctx := context.Background()
	hash, err := store.HashPassword("secret-pw")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := st.CreateUser(ctx, &store.User{ID: "u_alice", Username: testAlice, PasswordHash: hash, Admin: true,
		CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(ctx, &store.User{ID: "u_bob", Username: testBob, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin", nil)
	req.AddCookie(login(t, ts, testAlice, "secret-pw"))
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "invite pending") {
		t.Fatalf("admin page must mark bob as invite pending: %d", resp.StatusCode)
	}
}

func TestInviteFlowAndAdmin(t *testing.T) {
	st, ts := newTestUI(t)
	ctx := context.Background()
	now := time.Now().UTC()
	alice := &store.User{ID: "u_alice", Username: testAlice, Admin: true, CreatedAt: now}
	bob := &store.User{ID: "u_bob", Username: testBob, CreatedAt: now}
	for _, u := range []*store.User{alice, bob} {
		if err := st.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	token, err := st.CreateInvite(ctx, bob.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	inviteFlow(t, ts, token)
	adminFlow(t, ts, st, ctx, alice, bob)
}

// inviteFlow exercises the set-password invite end to end for bob.
func inviteFlow(t *testing.T, ts *httptest.Server, token string) {
	t.Helper()
	client := noRedirectClient()
	resp, err := client.Get(ts.URL + "/invite/" + token)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invite page: %d", resp.StatusCode)
	}
	form := url.Values{pwField: []string{testBobPw}, "password2": []string{testBobPw}}
	resp, err = client.PostForm(ts.URL+"/invite/"+token, form)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("invite set: %d", resp.StatusCode)
	}
	var bobCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookie {
			bobCookie = c
		}
	}
	if bobCookie == nil {
		t.Fatal("invite set must log the user in")
	}
	resp, err = client.Get(ts.URL + "/invite/" + token)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("used invite must 404: %d", resp.StatusCode)
	}
	if c := login(t, ts, testBob, testBobPw); c == nil {
		t.Fatal("login after invite failed")
	}
	// non-admin is redirected away from /admin
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin", nil)
	req.AddCookie(bobCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("non-admin /admin: %d", resp.StatusCode)
	}
}

// adminFlow checks the admin page and that disabling bob blocks his login.
func adminFlow(t *testing.T, ts *httptest.Server, st *store.Store, ctx context.Context, alice, bob *store.User) {
	t.Helper()
	client := noRedirectClient()
	hash, _ := store.HashPassword("alice-pw")
	if err := st.SetUserPassword(ctx, alice.ID, hash); err != nil {
		t.Fatal(err)
	}
	aliceCookie := login(t, ts, testAlice, "alice-pw")
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin", nil)
	req.AddCookie(aliceCookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), testBob) {
		t.Fatalf("admin page: %d", resp.StatusCode)
	}
	form := url.Values{"id": []string{bob.ID}, "disabled": []string{"1"}}
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/admin/disable",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(aliceCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("disable: %d", resp.StatusCode)
	}
	resp, err = client.PostForm(ts.URL+"/login",
		url.Values{userField: []string{testBob}, pwField: []string{testBobPw}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled login must be 401: %d", resp.StatusCode)
	}
}

// assertNewKeyBanner checks that the endpoint + header form is offered first.
func assertNewKeyBanner(t *testing.T, body string) {
	t.Helper()
	for _, want := range []string{`data-copy="http://proxy.local/mcp"`, "Authorization: Bearer mak_",
		"claude mcp add --transport http", "Only for clients that accept just a URL"} {
		if !strings.Contains(body, want) {
			t.Fatalf("new-key banner missing %q", want)
		}
	}
}
