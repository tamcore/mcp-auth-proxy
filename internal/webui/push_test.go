package webui

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
	"github.com/tamcore/mcp-auth-proxy/internal/webpush"
)

type fakeDevices struct {
	fail error
	sent []string
}

func (f *fakeDevices) PublicKey() string { return "BPUBLIC" }

func (f *fakeDevices) Send(_ context.Context, sub *store.PushSubscription, _ webpush.Payload) error {
	f.sent = append(f.sent, sub.Endpoint)
	return f.fail
}

func subscribeBody(endpoint string) []byte {
	enc := base64.RawURLEncoding.EncodeToString
	b, _ := json.Marshal(map[string]any{
		"endpoint": endpoint, "label": "Firefox on Linux",
		"keys": map[string]string{"p256dh": enc(append([]byte{4}, make([]byte, 64)...)), "auth": enc(make([]byte, 16))},
	})
	return b
}

func postSubscribe(t *testing.T, base string, cookie *http.Cookie, body []byte) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/portal/push/subscribe", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestPushSubscribeTestsBeforeSaving(t *testing.T) {
	st, ts, _, web := newTestWebUI(t)
	dev := &fakeDevices{}
	web.Devices = dev
	alice := seedUser(t, st, testAlice, "pw-alice")
	cookie := login(t, ts, testAlice, "pw-alice")
	ctx := context.Background()

	for name, body := range map[string][]byte{
		"plain http":  subscribeBody("http://push.example/x"),
		"credentials": subscribeBody("https://u:p@push.example/x"),
		"bad keys":    []byte(`{"endpoint":"https://push.example/x","keys":{"p256dh":"!!","auth":"x"}}`),
		"not json":    []byte(`endpoint=x`),
	} {
		if code := postSubscribe(t, ts.URL, cookie, body); code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, code)
		}
	}
	if len(dev.sent) != 0 {
		t.Fatal("invalid subscriptions must not be contacted")
	}
	dev.fail = errors.New("push service answered 403")
	if code := postSubscribe(t, ts.URL, cookie, subscribeBody("https://push.example/x")); code != http.StatusBadRequest {
		t.Fatalf("failed test push: want 400, got %d", code)
	}
	if subs, _ := st.ListPushSubscriptions(ctx, alice.ID); len(subs) != 0 {
		t.Fatal("a subscription whose test push failed must not be stored")
	}
	dev.fail = nil
	if code := postSubscribe(t, ts.URL, cookie, subscribeBody("https://push.example/x")); code != http.StatusOK {
		t.Fatalf("subscribe: want 200, got %d", code)
	}
	subs, _ := st.ListPushSubscriptions(ctx, alice.ID)
	if len(subs) != 1 || subs[0].Label != "Firefox on Linux" {
		t.Fatalf("stored: %+v", subs)
	}
	_, body := settingsBody(t, ts, cookie)
	if !strings.Contains(body, "Firefox on Linux") || !strings.Contains(body, "BPUBLIC") {
		t.Fatal("settings must list the device and carry the public key")
	}
	seedUser(t, st, testBob, "pw-bob")
	del := url.Values{"id": {subs[0].ID}}
	bob := login(t, ts, testBob, "pw-bob")
	if code := postStatus(t, ts, bob, "/portal/push/delete", del); code != http.StatusNotFound {
		t.Fatalf("foreign delete: want 404, got %d", code)
	}
	if code := postStatus(t, ts, cookie, "/portal/push/delete", del); code != http.StatusSeeOther {
		t.Fatalf("delete: want 303, got %d", code)
	}
	if subs, _ := st.ListPushSubscriptions(ctx, alice.ID); len(subs) != 0 {
		t.Fatal("device not removed")
	}
}

func TestPushSubscribeUnavailableWithoutSender(t *testing.T) {
	st, ts := newTestUI(t)
	seedUser(t, st, testAlice, "pw-alice")
	cookie := login(t, ts, testAlice, "pw-alice")
	if code := postSubscribe(t, ts.URL, cookie, subscribeBody("https://push.example/x")); code != http.StatusNotFound {
		t.Fatalf("want 404 without a sender, got %d", code)
	}
}
