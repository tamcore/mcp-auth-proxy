package gate

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

type fakeNotifier struct {
	mu    sync.Mutex
	calls []*store.Challenge
	err   error
}

func (f *fakeNotifier) Notify(_ context.Context, ch *store.Challenge, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, ch)
	return f.err
}

func (f *fakeNotifier) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeNotifier) last() *store.Challenge {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return nil
	}
	return f.calls[len(f.calls)-1]
}

type testEnv struct {
	gate *Gate
	st   *store.Store
	key  *store.Key
	ntf  *fakeNotifier
	now  time.Time
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	key := &store.Key{ID: "k_1", Kind: store.KeyKindStatic, Label: "laptop", SecretHash: "h",
		Upstreams: []string{"echo"}, TTLSeconds: 28800, CreatedAt: now}
	if err := st.CreateKey(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	ntf := &fakeNotifier{}
	idCounter := 0
	g := New(Options{
		Store:         st,
		Digits:        5,
		Expiry:        3 * time.Minute,
		MaxAttempts:   3,
		RenotifyFloor: 30 * time.Second,
		DefaultTTL:    8 * time.Hour,
		BaseURL:       "http://proxy.local",
		SignSecret:    []byte("0123456789abcdef0123456789abcdef"),
		Notifier:      ntf,
		Now:           func() time.Time { return now },
		NewID: func() string {
			idCounter++
			return "c" + string(rune('0'+idCounter))
		},
	})
	return &testEnv{gate: g, st: st, key: key, ntf: ntf, now: now}
}

func (e *testEnv) advance(d time.Duration) {
	base := e.now
	e.gate.now = func() time.Time { return base.Add(d) }
}

func TestBlockCreatesChallengeAndPushes(t *testing.T) {
	e := newTestEnv(t)
	msg, err := e.gate.Block(context.Background(), e.key, "echo__echo")
	if err != nil {
		t.Fatal(err)
	}
	if e.ntf.count() != 1 {
		t.Fatalf("want 1 push, got %d", e.ntf.count())
	}
	ch := e.ntf.last()
	if len(ch.PendingOTP) != 5 {
		t.Fatalf("otp length %d", len(ch.PendingOTP))
	}
	for _, want := range []string{`"echo__echo"`, `"laptop"`, "5-digit", "auth"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("contract message missing %q: %s", want, msg)
		}
	}
	if e.gate.Check(context.Background(), "k_1") {
		t.Fatal("blocked key must not have a session")
	}
}

func TestBlockRenotifyFloor(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.gate.Block(ctx, e.key, "echo__echo"); err != nil {
		t.Fatal(err)
	}
	// Within the 30s floor: no second push, same message shape.
	e.advance(10 * time.Second)
	if _, err := e.gate.Block(ctx, e.key, "echo__echo"); err != nil {
		t.Fatal(err)
	}
	if e.ntf.count() != 1 {
		t.Fatalf("floor violated: %d pushes", e.ntf.count())
	}
	// Past the floor: new challenge supersedes, second push.
	e.advance(31 * time.Second)
	if _, err := e.gate.Block(ctx, e.key, "echo__echo"); err != nil {
		t.Fatal(err)
	}
	if e.ntf.count() != 2 {
		t.Fatalf("want 2 pushes after floor, got %d", e.ntf.count())
	}
}

func TestBlockPushFailureVariant(t *testing.T) {
	e := newTestEnv(t)
	e.ntf.err = errors.New("ntfy down")
	msg, err := e.gate.Block(context.Background(), e.key, "echo__echo")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "may have failed") {
		t.Fatalf("want push-failure variant, got: %s", msg)
	}
}

func TestVerifyWrongThenCorrect(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.gate.Block(ctx, e.key, "echo__echo"); err != nil {
		t.Fatal(err)
	}
	otp := e.ntf.last().PendingOTP
	wrong := "00000"
	if wrong == otp {
		wrong = "11111"
	}
	if _, err := e.gate.Verify(ctx, e.key, wrong); !errors.Is(err, ErrWrongCode) {
		t.Fatalf("want ErrWrongCode, got %v", err)
	}
	exp, err := e.gate.Verify(ctx, e.key, otp)
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Equal(e.now.Add(8 * time.Hour)) {
		t.Fatalf("session expiry %v", exp)
	}
	if !e.gate.Check(ctx, "k_1") {
		t.Fatal("session not live after verify")
	}
	msg := AuthorizedMessage(exp)
	if !strings.Contains(msg, "Session authorized until") ||
		!strings.Contains(msg, "Retry the tool call you were blocked on.") {
		t.Fatalf("bad success message: %s", msg)
	}
}

func TestVerifyAttemptsExhaust(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.gate.Block(ctx, e.key, "t"); err != nil {
		t.Fatal(err)
	}
	otp := e.ntf.last().PendingOTP
	wrong := "99999"
	if wrong == otp {
		wrong = "88888"
	}
	for i := 0; i < 2; i++ {
		if _, err := e.gate.Verify(ctx, e.key, wrong); !errors.Is(err, ErrWrongCode) {
			t.Fatalf("attempt %d: want ErrWrongCode, got %v", i, err)
		}
	}
	if _, err := e.gate.Verify(ctx, e.key, wrong); !errors.Is(err, ErrExhausted) {
		t.Fatalf("want ErrExhausted, got %v", err)
	}
	// Even the correct code fails now.
	if _, err := e.gate.Verify(ctx, e.key, otp); !errors.Is(err, ErrNoChallenge) && !errors.Is(err, ErrExhausted) {
		t.Fatalf("after exhaustion want no usable challenge, got %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.gate.Block(ctx, e.key, "t"); err != nil {
		t.Fatal(err)
	}
	otp := e.ntf.last().PendingOTP
	e.advance(4 * time.Minute)
	if _, err := e.gate.Verify(ctx, e.key, otp); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestVerifyNoChallenge(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.gate.Verify(context.Background(), e.key, "12345"); !errors.Is(err, ErrNoChallenge) {
		t.Fatalf("want ErrNoChallenge, got %v", err)
	}
}

func TestApproveDenySignature(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.gate.Block(ctx, e.key, "echo__echo"); err != nil {
		t.Fatal(err)
	}
	ch := e.ntf.last()
	id := ch.ID
	// Bad / missing sig -> ErrBadSignature.
	if err := e.gate.Approve(ctx, id, ""); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("missing sig: %v", err)
	}
	if err := e.gate.Approve(ctx, id, "deadbeef"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong sig: %v", err)
	}
	sig := e.gate.sig(id)
	if len(sig) != 64 || strings.ToLower(sig) != sig {
		t.Fatalf("sig must be lowercase hex sha256, got %q", sig)
	}
	if err := e.gate.Deny(ctx, id, sig); err != nil {
		t.Fatal(err)
	}
	got, _ := e.st.ChallengeByID(ctx, id)
	if got.Status != store.ChallengeDenied {
		t.Fatalf("status %s", got.Status)
	}
	if e.gate.Check(ctx, "k_1") {
		t.Fatal("deny must not grant a session")
	}
	// Approve on a fresh challenge grants a session with origin approve.
	e2 := newTestEnv(t)
	if _, err := e2.gate.Block(ctx, e2.key, "t"); err != nil {
		t.Fatal(err)
	}
	ch2 := e2.ntf.last()
	if err := e2.gate.Approve(ctx, ch2.ID, e2.gate.sig(ch2.ID)); err != nil {
		t.Fatal(err)
	}
	if !e2.gate.Check(ctx, "k_1") {
		t.Fatal("approve must grant a session")
	}
	sess, err := e2.st.GetSession(ctx, "k_1", e2.now)
	if err != nil || sess.Origin != store.OriginApprove {
		t.Fatalf("session origin: %+v %v", sess, err)
	}
	// Double approve is not pending anymore.
	if err := e2.gate.Approve(ctx, ch2.ID, e2.gate.sig(ch2.ID)); !errors.Is(err, ErrNotPending) {
		t.Fatalf("want ErrNotPending, got %v", err)
	}
}

func TestApproveURLShape(t *testing.T) {
	e := newTestEnv(t)
	u := e.gate.ApproveURL("abc")
	if !strings.HasPrefix(u, "http://proxy.local/approve/abc?sig=") {
		t.Fatalf("approve url: %s", u)
	}
	d := e.gate.DenyURL("abc")
	if !strings.HasPrefix(d, "http://proxy.local/deny/abc?sig=") {
		t.Fatalf("deny url: %s", d)
	}
}
