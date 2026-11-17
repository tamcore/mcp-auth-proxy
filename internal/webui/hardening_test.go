package webui

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
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

func TestUnknownAndRealUsernamesFailAlike(t *testing.T) {
	st, ts := newTestUI(t)
	seedUser(t, st, testAlice, "pw")
	sequence := func(user string) string {
		codes := make([]string, 0, maxFailedLogins+1)
		for range maxFailedLogins + 1 {
			resp, err := noRedirectClient().PostForm(ts.URL+"/login", url.Values{userField: {user}, pwField: {"wrong"}})
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			codes = append(codes, fmt.Sprint(resp.StatusCode))
		}
		return strings.Join(codes, ",")
	}
	want := sequence(testAlice)
	for _, name := range []string{"ghost", "ghost2"} {
		if got := sequence(name); got != want {
			t.Fatalf("%s: %s, real user: %s; the responses reveal which names exist", name, got, want)
		}
	}
}

func TestConcurrentWrongLoginsStayWithinTheLimit(t *testing.T) {
	st, ts := newTestUI(t)
	seedUser(t, st, testAlice, "pw")
	const tries = 20
	codes := make(chan int, tries)
	var wg sync.WaitGroup
	for range tries {
		wg.Go(func() {
			resp, err := noRedirectClient().PostForm(ts.URL+"/login", url.Values{userField: {testAlice}, pwField: {"wrong"}})
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Body.Close()
			codes <- resp.StatusCode
		})
	}
	wg.Wait()
	close(codes)
	passed := 0
	for c := range codes {
		if c != http.StatusTooManyRequests {
			passed++
		}
	}
	if passed > maxFailedLogins {
		t.Fatalf("%d concurrent wrong passwords were checked, limit is %d", passed, maxFailedLogins)
	}
}
