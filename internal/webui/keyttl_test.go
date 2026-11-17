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

func postStatus(t *testing.T, ts *httptest.Server, cookie *http.Cookie, path string, form url.Values) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestParseKeyTTL(t *testing.T) {
	for in, want := range map[string]int64{"": 0, " ": 0, "4h": 14400, "90m": 5400, "1m": 60, "168h": 604800} {
		if got, err := parseKeyTTL(in); err != nil || got != want {
			t.Errorf("parseKeyTTL(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"abc", "-1h", "0s", "59s", "169h", "4"} {
		if _, err := parseKeyTTL(in); err == nil {
			t.Errorf("parseKeyTTL(%q): want error", in)
		}
	}
}

func TestCreateKeyWithTTL(t *testing.T) {
	st, ts := newTestUI(t)
	seedUser(t, st, testAlice, "pw-alice")
	cookie := login(t, ts, testAlice, "pw-alice")
	create := func(label, ttl string) int {
		form := url.Values{labelField: {label}, upstreamField: {testEcho}, "ttl": {ttl}}
		return postStatus(t, ts, cookie, "/portal/key", form)
	}

	if code := create("bad", "forever"); code != http.StatusBadRequest {
		t.Fatalf("invalid ttl: want 400, got %d", code)
	}
	if code := create("short", "30m"); code != http.StatusOK {
		t.Fatalf("create with ttl: want 200, got %d", code)
	}
	if code := create("default", ""); code != http.StatusOK {
		t.Fatalf("create without ttl: want 200, got %d", code)
	}
	keys, err := st.ListKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, k := range keys {
		got[k.Label] = k.TTLSeconds
	}
	if len(got) != 2 || got["short"] != 1800 || got["default"] != 0 {
		t.Fatalf("ttl seconds: %v", got)
	}
	body := portalBody(t, ts, cookie)
	if !strings.Contains(body, "session 30m") || !strings.Contains(body, "session 8h (default)") {
		t.Fatal("portal must show the custom and the default session TTL")
	}
}

func TestEditKeyTTL(t *testing.T) {
	st, ts := newLinkUI(t, "https://idp/token")
	ctx := context.Background()
	uid := linkUserID
	key := &store.Key{ID: "k_ttl", Kind: store.KeyKindStatic, Label: "ttl-me", SecretHash: "h_ttl",
		Upstreams: []string{testEcho}, CreatedAt: time.Now().UTC(), UserID: &uid}
	if err := st.CreateKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	bob := login(t, ts, testBob, linkPw)
	alice := login(t, ts, testAlice, linkPw)
	edit := func(c *http.Cookie, ttl string) int {
		return postStatus(t, ts, c, "/portal/key/ttl", url.Values{"id": {key.ID}, "ttl": {ttl}})
	}
	ttlOf := func() int64 {
		k, err := st.KeyByID(ctx, key.ID)
		if err != nil {
			t.Fatal(err)
		}
		return k.TTLSeconds
	}

	if code := edit(alice, "2h"); code != http.StatusNotFound {
		t.Fatalf("another user's key: want 404, got %d", code)
	}
	if code := edit(bob, "2 hours"); code != http.StatusBadRequest {
		t.Fatalf("invalid ttl: want 400, got %d", code)
	}
	if code := edit(bob, "2h"); code != http.StatusSeeOther || ttlOf() != 7200 {
		t.Fatalf("set: code %d, ttl %d", code, ttlOf())
	}
	if code := edit(bob, ""); code != http.StatusSeeOther || ttlOf() != 0 {
		t.Fatalf("reset: code %d, ttl %d", code, ttlOf())
	}
	if err := st.RevokeKey(ctx, key.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if code := edit(bob, "2h"); code != http.StatusNotFound {
		t.Fatalf("revoked key: want 404, got %d", code)
	}
}
