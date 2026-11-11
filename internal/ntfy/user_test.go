package ntfy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

// fakeServer is a minimal ntfy: /v1/health plus JSON publish on /.
type fakeServer struct {
	*httptest.Server
	mu      sync.Mutex
	msgs    []Message
	auth    []string
	healthy bool
	status  int
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{healthy: true, status: http.StatusOK}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health" {
			if !f.healthy {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(`{"healthy":true}`))
			return
		}
		var m Message
		_ = json.NewDecoder(r.Body).Decode(&m)
		f.mu.Lock()
		f.msgs = append(f.msgs, m)
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		f.mu.Unlock()
		w.WriteHeader(f.status)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeServer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.msgs)
}

func TestValidate(t *testing.T) {
	ctx := context.Background()
	f := newFakeServer(t)
	if _, err := Validate(ctx, nil, f.URL, "topic", "tk_x"); err != nil {
		t.Fatalf("healthy loopback server: %v", err)
	}
	if f.count() != 1 || f.msgs[0].Topic != "topic" || f.auth[0] != "Bearer tk_x" {
		t.Fatalf("validation must send one test push with the token: %+v %v", f.msgs, f.auth)
	}
	for name, url := range map[string]string{"plain http": "http://ntfy.example", "no scheme": "ntfy.example",
		"credentials in url": "https://u:p@ntfy.example"} {
		if _, err := Validate(ctx, nil, url, "topic", ""); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
	if _, err := Validate(ctx, nil, f.URL, "", ""); err == nil {
		t.Fatal("empty topic must be rejected")
	}
	f.healthy = false
	if _, err := Validate(ctx, nil, f.URL, "topic", ""); err == nil || !strings.Contains(err.Error(), "ntfy") {
		t.Fatalf("non-ntfy server must be rejected, got %v", err)
	}
	f.healthy, f.status = true, http.StatusForbidden
	if _, err := Validate(ctx, nil, f.URL, "topic", "tk_bad"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("rejected test push must fail with the status, got %v", err)
	}
}

func TestUserNotifierPushesToKeyOwnersTarget(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Now().UTC()
	f := newFakeServer(t)
	for _, uid := range []string{"u_with", "u_without"} {
		if err := st.CreateUser(ctx, &store.User{ID: uid, Username: uid, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		owner := uid
		k := &store.Key{ID: "k_" + uid, Kind: store.KeyKindStatic, Label: uid,
			SecretHash: "h_" + uid, Upstreams: []string{}, TTLSeconds: 60, CreatedAt: now, UserID: &owner}
		if err := st.CreateKey(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	target := &store.UserNotify{UserID: "u_with", URL: f.URL, Topic: "mine", Token: "tk_mine"}
	if err := st.SaveUserNotify(ctx, target); err != nil {
		t.Fatal(err)
	}
	n := NewUserNotifier(st, nil, nil,
		func(id string) string { return "http://p/approve/" + id }, func(id string) string { return "http://p/deny/" + id })
	ch := &store.Challenge{ID: "c1", KeyID: "k_u_with", ToolName: "t", PendingOTP: "12345",
		ExpiresAt: now.Add(time.Minute)}
	if err := n.Notify(ctx, ch, "u_with"); err != nil {
		t.Fatal(err)
	}
	if f.count() != 1 || f.msgs[0].Topic != "mine" || f.auth[0] != "Bearer tk_mine" ||
		!strings.Contains(f.msgs[0].Message, "12345") {
		t.Fatalf("push to owner's target: %+v %v", f.msgs, f.auth)
	}
	ch.KeyID = "k_u_without"
	if err := n.Notify(ctx, ch, "u_without"); err != ErrNoTarget {
		t.Fatalf("user without target: want ErrNoTarget, got %v", err)
	}
	if f.count() != 1 {
		t.Fatal("no push may go out for a user without a target")
	}
}
