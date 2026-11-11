package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func TestSessionRejectedAfterCutoffOrDisable(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := st.CreateUser(ctx, &store.User{ID: "u_s", Username: "s", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	clock := now
	s := NewSessions([]byte("0123456789abcdef0123456789abcdef"), func() time.Time { return clock })
	req := func(cookie string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: cookie})
		return r
	}
	old := s.Issue("s")
	if _, ok := s.User(req(old), st); !ok {
		t.Fatal("fresh session must be valid")
	}
	clock = now.Add(time.Minute)
	if err := st.SetSessionsSince(ctx, "u_s", clock); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.User(req(old), st); ok {
		t.Fatal("session issued before the cutoff must be rejected")
	}
	fresh := s.Issue("s")
	if _, ok := s.User(req(fresh), st); !ok {
		t.Fatal("session issued at the cutoff must be valid")
	}
	// A login in the same second as a password change, before the cutoff.
	if err := st.SetSessionsSince(ctx, "u_s", clock.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	u, _ := st.UserByID(ctx, "u_s")
	if _, ok := s.User(req(s.IssueFor(u)), st); !ok {
		t.Fatal("a login right after a password change must be valid")
	}
	if err := st.SetUserDisabled(ctx, "u_s", true); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.User(req(fresh), st); ok {
		t.Fatal("a disabled user's session must be rejected")
	}
}
