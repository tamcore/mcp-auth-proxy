package webui

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
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
