package webui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func TestSessionCookieIsSecureOnlyOnHTTPS(t *testing.T) {
	for base, want := range map[string]bool{"http://proxy.local": false, "https://proxy.example": true} {
		st, ts := newTestUI(t, func(c *config.Config) { c.BaseURL = base })
		seedUser(t, st, testAlice, "pw")
		if got := login(t, ts, testAlice, "pw").Secure; got != want {
			t.Fatalf("%s: Secure=%v, want %v", base, got, want)
		}
	}
}

func TestLogoutInvalidatesACopiedCookie(t *testing.T) {
	st, ts := newTestUI(t)
	seedUser(t, st, testAlice, "pw")
	cookie := login(t, ts, testAlice, "pw")
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/logout", nil)
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.AddCookie(cookie)
	resp, err = noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("cookie still opens the portal after logout: %d", resp.StatusCode)
	}
}

func TestRepeatedFailedLoginsLockTheUser(t *testing.T) {
	st, ts := newTestUI(t)
	seedUser(t, st, testAlice, "pw")
	post := func(pw string) int {
		resp, err := noRedirectClient().PostForm(ts.URL+"/login", url.Values{userField: {testAlice}, pwField: {pw}})
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for range maxFailedLogins {
		if code := post("wrong"); code != http.StatusUnauthorized {
			t.Fatalf("wrong password: %d", code)
		}
	}
	if code := post("pw"); code != http.StatusTooManyRequests {
		t.Fatalf("locked user logged in with status %d, want 429", code)
	}
}

// failSessionCutoff makes every write of users.sessions_since fail.
func failSessionCutoff(t *testing.T, st *store.Store) {
	t.Helper()
	if _, err := st.DB().Exec(`CREATE TRIGGER fail_cutoff BEFORE UPDATE OF sessions_since ON users
BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatal(err)
	}
}

func TestLogoutReportsFailedSessionCutoff(t *testing.T) {
	st, ts := newTestUI(t)
	seedUser(t, st, testAlice, "pw")
	cookie := login(t, ts, testAlice, "pw")
	failSessionCutoff(t, st)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/logout", nil)
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("logout that could not end other sessions: want 500, got %d", resp.StatusCode)
	}
}

func TestPasswordChangeIsAtomic(t *testing.T) {
	st, ts := newLinkUI(t, "https://idp/token")
	cookie := login(t, ts, testBob, linkPw)
	failSessionCutoff(t, st)
	form := url.Values{"current": {linkPw}, pwField: {newPw}, pw2Field: {newPw}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/settings/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", resp.StatusCode)
	}
	login(t, ts, testBob, linkPw)
}
