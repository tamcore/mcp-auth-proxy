package webui

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

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
	form := url.Values{currentField: {linkPw}, pwField: {newPw}, pw2Field: {newPw}}
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

func TestInviteResetLogsOutOldSessions(t *testing.T) {
	st, ts := newTestUI(t)
	u := seedUser(t, st, testAlice, "pw")
	old := login(t, ts, testAlice, "pw")
	token, err := st.CreateInvite(context.Background(), u.ID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{pwField: {newPw}, pw2Field: {newPw}}
	resp, err := noRedirectClient().PostForm(ts.URL+"/invite/"+token, form)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	fresh := sessionCookie(resp)
	if resp.StatusCode != http.StatusFound || fresh == nil {
		t.Fatalf("invite: %d cookie=%v", resp.StatusCode, fresh)
	}
	if code, _ := settingsBody(t, ts, fresh); code != http.StatusOK {
		t.Fatalf("the invite's own session must work: %d", code)
	}
	if code, _ := settingsBody(t, ts, old); code != http.StatusFound {
		t.Fatalf("sessions from before the reset must be logged out: %d", code)
	}
}

func TestFailedRevokeIsReported(t *testing.T) {
	st, ts := newLinkUI(t, "https://idp/token")
	uid := linkUserID
	key := &store.Key{ID: "k_rev", Kind: store.KeyKindStatic, Label: "rev", SecretHash: "h_rev",
		Upstreams: []string{testEcho}, TTLSeconds: 60, CreatedAt: time.Now().UTC(), UserID: &uid}
	if err := st.CreateKey(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`CREATE TRIGGER fail_revoke BEFORE UPDATE OF revoked_at ON keys
BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatal(err)
	}
	code, _ := postForm(t, ts, login(t, ts, testBob, linkPw), "/portal/key/revoke", url.Values{"id": {key.ID}})
	if code != http.StatusInternalServerError {
		t.Fatalf("failed revoke: want 500, got %d", code)
	}
}
