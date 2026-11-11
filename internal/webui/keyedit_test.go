package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func postKeyUpstreams(t *testing.T, ts *httptest.Server, cookie *http.Cookie, id string, ups ...string) int {
	t.Helper()
	form := url.Values{"id": {id}, upstreamField: ups}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/portal/key/upstreams", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestEditKeyUpstreams(t *testing.T) {
	st, ts := newLinkUI(t, "https://idp/token")
	ctx := context.Background()
	uid := linkUserID
	key := &store.Key{ID: "k_edit", Kind: store.KeyKindStatic, Label: "edit-me", SecretHash: "h_edit",
		Upstreams: []string{testEcho}, TTLSeconds: 60, CreatedAt: time.Now().UTC(), UserID: &uid}
	if err := st.CreateKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	bob := login(t, ts, testBob, linkPw)
	alice := login(t, ts, testAlice, linkPw)

	if body := portalBody(t, ts, bob); !strings.Contains(body, "Edit servers") || !strings.Contains(body, "never") {
		t.Fatal("key row must offer Edit servers and show activity (never used)")
	}
	if code := postKeyUpstreams(t, ts, alice, key.ID, testEcho); code != http.StatusNotFound {
		t.Fatalf("another user's key: want 404, got %d", code)
	}
	if code := postKeyUpstreams(t, ts, bob, key.ID, "private-oauth"); code != http.StatusBadRequest {
		t.Fatalf("upstream not available to bob: want 400, got %d", code)
	}
	if code := postKeyUpstreams(t, ts, bob, key.ID, testEcho, garmin); code != http.StatusSeeOther {
		t.Fatalf("update: want 303, got %d", code)
	}
	got, _ := st.KeyByID(ctx, key.ID)
	if strings.Join(got.Upstreams, ",") != testEcho+","+garmin {
		t.Fatalf("upstreams not updated: %v", got.Upstreams)
	}
	if err := st.RevokeKey(ctx, key.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if code := postKeyUpstreams(t, ts, bob, key.ID, testEcho); code != http.StatusNotFound {
		t.Fatalf("revoked key: want 404, got %d", code)
	}
}

func TestRemoveRevokedKeyAndAuthzExpiry(t *testing.T) {
	st, ts := newLinkUI(t, "https://idp/token")
	ctx := context.Background()
	uid := linkUserID
	now := time.Now().UTC()
	key := &store.Key{ID: "k_rm", Kind: store.KeyKindStatic, Label: "remove-me", SecretHash: "h_rm",
		Upstreams: []string{testEcho}, TTLSeconds: 60, CreatedAt: now, UserID: &uid}
	if err := st.CreateKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	bob := login(t, ts, testBob, linkPw)
	if !strings.Contains(portalBody(t, ts, bob), "not authorized") {
		t.Fatal("key without session must show not authorized")
	}
	until := now.Add(2 * time.Hour)
	sess := &store.Session{KeyID: key.ID, CreatedAt: now, ExpiresAt: until, Origin: "otp"}
	if err := st.UpsertSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(portalBody(t, ts, bob), "authorized until "+until.Format("2006-01-02 15:04 UTC")) {
		t.Fatal("key with session must show when the authorization expires")
	}
	remove := func(cookie *http.Cookie) int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/portal/key/delete",
			strings.NewReader(url.Values{"id": {key.ID}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		resp, err := noRedirectClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := remove(bob); code != http.StatusNotFound {
		t.Fatalf("active key removal: want 404, got %d", code)
	}
	if err := st.RevokeKey(ctx, key.ID, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(portalBody(t, ts, bob), `action="/portal/key/delete"`) {
		t.Fatal("revoked key must offer Remove")
	}
	if code := remove(login(t, ts, testAlice, linkPw)); code != http.StatusNotFound {
		t.Fatalf("foreign key removal: want 404, got %d", code)
	}
	if code := remove(bob); code != http.StatusSeeOther {
		t.Fatalf("revoked key removal: want 303, got %d", code)
	}
	if _, err := st.KeyByID(ctx, key.ID); err != store.ErrNotFound {
		t.Fatalf("key must be gone: %v", err)
	}
}

func TestEndKeySession(t *testing.T) {
	st, ts := newLinkUI(t, "https://idp/token")
	ctx := context.Background()
	uid := linkUserID
	now := time.Now().UTC()
	key := &store.Key{ID: "k_end", Kind: store.KeyKindStatic, Label: "end-me", SecretHash: "h_end",
		Upstreams: []string{testEcho}, TTLSeconds: 60, CreatedAt: now, UserID: &uid}
	if err := st.CreateKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	sess := &store.Session{KeyID: key.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour), Origin: "otp"}
	if err := st.UpsertSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	bob := login(t, ts, testBob, linkPw)
	if !strings.Contains(portalBody(t, ts, bob), `action="/portal/key/end-session"`) {
		t.Fatal("authorized key must offer End session")
	}
	end := func(cookie *http.Cookie) int {
		code, _ := postForm(t, ts, cookie, "/portal/key/end-session", url.Values{"id": {key.ID}})
		return code
	}
	if code := end(login(t, ts, testAlice, linkPw)); code != http.StatusNotFound {
		t.Fatalf("foreign key: want 404, got %d", code)
	}
	if code := end(bob); code != http.StatusSeeOther {
		t.Fatalf("end session: want 303, got %d", code)
	}
	if _, err := st.GetSession(ctx, key.ID, now); err != store.ErrNotFound {
		t.Fatalf("session must be gone: %v", err)
	}
	if got, _ := st.KeyByID(ctx, key.ID); got.Revoked() {
		t.Fatal("ending the session must not revoke the key")
	}
}
