package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

const (
	pw2Field      = "password2"
	disabledField = "disabled"
)

func TestFailedInvitePasswordKeepsTheInvite(t *testing.T) {
	st, ts := newTestUI(t)
	ctx := context.Background()
	bob := &store.User{ID: "u_member", Username: testBob, CreatedAt: time.Now().UTC()}
	if err := st.CreateUser(ctx, bob); err != nil {
		t.Fatal(err)
	}
	token, err := st.CreateInvite(ctx, bob.ID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", 80) // bcrypt rejects passwords over 72 bytes
	code, _ := postForm(t, ts, nil, "/invite/"+token, url.Values{pwField: {long}, pw2Field: {long}})
	if code != http.StatusBadRequest {
		t.Fatalf("too long password: want 400, got %d", code)
	}
	resp, err := http.Get(ts.URL + "/invite/" + token)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a failed password set burned the invite: %d", resp.StatusCode)
	}
}

func TestAdminCannotDisableThemselvesOrTheLastAdmin(t *testing.T) {
	st, ts := newTestUI(t)
	ctx := context.Background()
	now := time.Now().UTC()
	hash, _ := store.HashPassword("pw")
	alice := &store.User{ID: "u_admin", Username: testAlice, Admin: true, PasswordHash: hash, CreatedAt: now}
	bob := &store.User{ID: "u_member", Username: testBob, PasswordHash: hash, CreatedAt: now}
	for _, u := range []*store.User{alice, bob} {
		if err := st.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	cookie := login(t, ts, testAlice, "pw")
	disable := func(id string) int {
		code, _ := postForm(t, ts, cookie, "/admin/disable", url.Values{"id": {id}, disabledField: {"1"}})
		return code
	}
	if code := disable(alice.ID); code != http.StatusBadRequest {
		t.Fatalf("self-disable: want 400, got %d", code)
	}
	if u, _ := st.UserByID(ctx, alice.ID); u.Disabled {
		t.Fatal("the only admin was disabled")
	}
	if code := disable(bob.ID); code != http.StatusFound {
		t.Fatalf("disabling another user: want 302, got %d", code)
	}
}

func TestPasskeyLoginRequiresUserVerification(t *testing.T) {
	_, ts := newTestUI(t, func(c *config.Config) { c.BaseURL = "https://proxy.example" })
	code, body := postForm(t, ts, nil, "/login/passkey/begin", nil)
	if code != http.StatusOK || !strings.Contains(body, `"userVerification":"required"`) {
		t.Fatalf("passkey login must require user verification: %d %s", code, body)
	}
}

func TestFullCeremonyMapDropsTheOldestInsteadOfRefusing(t *testing.T) {
	c := &ceremonies{m: map[string]ceremony{}}
	for range maxCeremonies {
		c.m[strings.Repeat("x", len(c.m)+1)] = ceremony{deadline: time.Now().Add(time.Duration(len(c.m)+1) * time.Second)}
	}
	if err := c.start(httptest.NewRecorder(), &webauthn.SessionData{}, ""); err != nil {
		t.Fatalf("a flood must not lock out a new login: %v", err)
	}
	if _, ok := c.m["x"]; ok || len(c.m) != maxCeremonies {
		t.Fatalf("the oldest ceremony must make room: %d entries", len(c.m))
	}
}
