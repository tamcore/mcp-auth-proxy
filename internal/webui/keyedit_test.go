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
