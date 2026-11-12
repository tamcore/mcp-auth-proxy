package webui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

// fakeNtfy answers /v1/health and accepts publishes.
func fakeNtfy(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health" {
			_, _ = w.Write([]byte(`{"healthy":true}`))
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func postForm(t *testing.T, ts *httptest.Server, cookie *http.Cookie, path string, form url.Values) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

const (
	urlField    = "url"
	secretTopic = "secret_topic"
	secretToken = "tk_secret"
)

func TestNotifySettings(t *testing.T) {
	st, ts := newLinkUI(t, "https://idp/token")
	ctx := context.Background()
	ntfy := fakeNtfy(t)
	bob := login(t, ts, testBob, linkPw)
	if !strings.Contains(portalBody(t, ts, bob), "No push target") {
		t.Fatal("portal must say that no push target is set")
	}
	code, body := postForm(t, ts, bob, "/portal/notify", url.Values{urlField: {"https://example.invalid"}, "topic": {"t"}})
	if code != http.StatusBadRequest || !strings.Contains(body, "could not reach") {
		t.Fatalf("unreachable server: %d", code)
	}
	if _, err := st.GetUserNotify(ctx, linkUserID); err != store.ErrNotFound {
		t.Fatal("an invalid target must not be stored")
	}
	form := url.Values{urlField: {ntfy.URL}, "topic": {secretTopic}, "token": {secretToken}}
	if code, _ := postForm(t, ts, bob, "/portal/notify", form); code != http.StatusSeeOther {
		t.Fatalf("save: %d", code)
	}
	n, err := st.GetUserNotify(ctx, linkUserID)
	if err != nil || n.Topic != secretTopic || n.Token != secretToken {
		t.Fatalf("saved target: %+v %v", n, err)
	}
	_, page := settingsBody(t, ts, bob)
	if !strings.Contains(page, ntfy.URL) || !strings.Contains(page, `value="`+secretTopic+`"`) ||
		strings.Contains(page, secretToken) {
		t.Fatal("settings must show server and topic but never the token")
	}
	if strings.Contains(portalBody(t, ts, bob), "No push target") {
		t.Fatal("portal hint must disappear once a target is set")
	}
	assertNotifyKeepAndRemove(t, st, ts, bob, ntfy.URL)
}

func TestPendingRequestsInPortal(t *testing.T) {
	st, ts, g := newTestUIGate(t)
	ctx := context.Background()
	bob := seedUser(t, st, testBob, "secret-pw")
	key := &store.Key{ID: "k_pend", Kind: store.KeyKindStatic, Label: "pending-key", SecretHash: "h_pend",
		Upstreams: []string{testEcho}, TTLSeconds: 60, CreatedAt: time.Now().UTC(), UserID: &bob.ID}
	if err := st.CreateKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	cookie := login(t, ts, testBob, "secret-pw")
	if strings.Contains(portalBody(t, ts, cookie), `data-testid="pending"`) {
		t.Fatal("no pending card without requests")
	}
	if _, err := g.Block(ctx, key, "echo__echo"); err != nil {
		t.Fatal(err)
	}
	pending, err := st.PendingChallengesForUser(ctx, bob.ID, time.Now().UTC())
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending: %+v %v", pending, err)
	}
	code, _ := g.PendingCode(pending[0].ID)
	page := portalBody(t, ts, cookie)
	for _, want := range []string{`data-testid="pending"`, "pending-key", "echo__echo", code,
		"/approve/" + pending[0].ID + "?sig=", "/deny/" + pending[0].ID + "?sig="} {
		if !strings.Contains(page, want) {
			t.Fatalf("pending card missing %q", want)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/portal/pending", nil)
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var ids struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ids); err != nil || len(ids.IDs) != 1 || ids.IDs[0] != pending[0].ID {
		t.Fatalf("pending ids: %+v %v", ids, err)
	}
}

// assertNotifyKeepAndRemove re-saves with blank secrets, then removes the target.
func assertNotifyKeepAndRemove(t *testing.T, st *store.Store, ts *httptest.Server, bob *http.Cookie, ntfyURL string) {
	t.Helper()
	ctx := context.Background()
	keep := url.Values{urlField: {ntfyURL}}
	if code, _ := postForm(t, ts, bob, "/portal/notify", keep); code != http.StatusSeeOther {
		t.Fatalf("re-save with blank topic/token must keep them: %d", code)
	}
	if n, _ := st.GetUserNotify(ctx, linkUserID); n.Topic != secretTopic || n.Token != secretToken {
		t.Fatalf("blank fields must keep the stored values: %+v", n)
	}
	if code, _ := postForm(t, ts, bob, "/portal/notify/delete", url.Values{}); code != http.StatusSeeOther {
		t.Fatalf("remove: %d", code)
	}
	if _, err := st.GetUserNotify(ctx, linkUserID); err != store.ErrNotFound {
		t.Fatal("target must be removed")
	}
}
