package webpush

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

// device is a browser's side of a subscription: its key pair and auth secret.
type device struct {
	priv *ecdh.PrivateKey
	auth []byte
}

func newDevice(t *testing.T) *device {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	_, _ = rand.Read(auth)
	return &device{priv: priv, auth: auth}
}

func (d *device) subscription(endpoint string) *store.PushSubscription {
	enc := base64.RawURLEncoding.EncodeToString
	return &store.PushSubscription{ID: "ps_" + endpoint[len(endpoint)-1:], UserID: "u_1", Endpoint: endpoint,
		P256dh: enc(d.priv.PublicKey().Bytes()), Auth: enc(d.auth), Label: "test", CreatedAt: time.Now().UTC()}
}

// decrypt opens an RFC 8291 aes128gcm body as the receiving browser would.
func (d *device) decrypt(t *testing.T, body []byte) []byte {
	t.Helper()
	salt, rs, idLen := body[:16], binary.BigEndian.Uint32(body[16:20]), int(body[20])
	asPublic, ct := body[21:21+idLen], body[21+idLen:]
	if rs < 18 {
		t.Fatalf("record size %d", rs)
	}
	pub, err := ecdh.P256().NewPublicKey(asPublic)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := d.priv.ECDH(pub)
	if err != nil {
		t.Fatal(err)
	}
	info := "WebPush: info\x00" + string(d.priv.PublicKey().Bytes()) + string(asPublic)
	ikm := must(hkdf.Key(sha256.New, secret, d.auth, info, 32))
	cek := must(hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16))
	nonce := must(hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12))
	block := must(aes.NewCipher(cek))
	gcm := must(cipher.NewGCM(block))
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	plain = bytes.TrimRight(plain, "\x00")
	return plain[:len(plain)-1] // drop the 0x02 last-record delimiter
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// pushService records requests and answers each endpoint path with a status.
type pushService struct {
	mu     sync.Mutex
	status map[string]int
	got    map[string]*http.Request
	bodies map[string][]byte
}

func (p *pushService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.got[r.URL.Path], p.bodies[r.URL.Path] = r, body
	code := p.status[r.URL.Path]
	if code == 0 {
		code = http.StatusCreated
	}
	w.WriteHeader(code)
}

func newPushService(t *testing.T, status map[string]int) (*pushService, *httptest.Server) {
	t.Helper()
	ps := &pushService{status: status, got: map[string]*http.Request{}, bodies: map[string][]byte{}}
	srv := httptest.NewServer(ps)
	t.Cleanup(srv.Close)
	return ps, srv
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	u := &store.User{ID: "u_1", Username: "u1", CreatedAt: time.Now().UTC()}
	if err := st.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestPushEncryptsForEveryDeviceAndDropsGoneOnes(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	ps, srv := newPushService(t, map[string]int{"/gone": http.StatusGone, "/broken": http.StatusInternalServerError})
	keys, err := EnsureKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	devs := map[string]*device{}
	for _, p := range []string{"/a", "/gone", "/broken"} {
		devs[p] = newDevice(t)
		if err := st.SavePushSubscription(ctx, devs[p].subscription(srv.URL+p)); err != nil {
			t.Fatal(err)
		}
	}
	s := New(st, srv.Client(), keys, "https://proxy.example", nil)
	msg := Payload{Title: "MCP auth request", Body: "code 12345", Approve: "https://proxy.example/approve/c1?sig=x"}

	sent, err := s.Push(ctx, "u_1", msg)
	if sent != 1 || err == nil {
		t.Fatalf("want 1 delivered and an error for /broken, got %d, %v", sent, err)
	}
	var got Payload
	if err := json.Unmarshal(devs["/a"].decrypt(t, ps.bodies["/a"]), &got); err != nil || got != msg {
		t.Fatalf("payload: %+v %v", got, err)
	}
	req := ps.got["/a"]
	auth := req.Header.Get("Authorization")
	if req.Header.Get("Content-Encoding") != "aes128gcm" || !strings.HasPrefix(auth, "vapid t=") ||
		!strings.Contains(auth, "k="+keys.Public) || req.Header.Get("TTL") == "" {
		t.Fatalf("headers: %v", req.Header)
	}
	subs, _ := st.ListPushSubscriptions(ctx, "u_1")
	if len(subs) != 2 {
		t.Fatalf("410 must drop only that subscription, left: %d", len(subs))
	}
}

func TestEnsureKeysPersistsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	a, err := EnsureKeys(dir)
	if err != nil || a.Public == "" || a.Private == "" {
		t.Fatalf("generate: %+v %v", a, err)
	}
	b, err := EnsureKeys(dir)
	if err != nil || a != b {
		t.Fatal("keys must be stable across restarts")
	}
	fi, err := os.Stat(filepath.Join(dir, KeysFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", fi.Mode(), err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeysFile), []byte(`{"public":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureKeys(dir); err == nil {
		t.Fatal("an incomplete key file must be rejected")
	}
}

func TestSendReportsUnreachableServiceAndBadKeys(t *testing.T) {
	keys, err := EnsureKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(nil, nil, keys, "admin@proxy.example", nil)
	if s.PublicKey() != keys.Public {
		t.Fatal("PublicKey must expose the VAPID public key")
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	sub := newDevice(t).subscription(srv.URL + "/x")
	if err := s.Send(context.Background(), sub, Payload{Title: "t"}); err == nil || errors.Is(err, errGone) {
		t.Fatalf("unreachable push service: want a transport error, got %v", err)
	}
	sub.P256dh = "not-a-key"
	if err := s.Send(context.Background(), sub, Payload{Title: "t"}); err == nil {
		t.Fatal("a malformed device key must fail")
	}
}

func TestEnsureKeysRejectsUnreadableDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	if _, err := EnsureKeys(dir); err == nil {
		t.Fatal("a missing state dir must fail")
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, KeysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureKeys(dir); err == nil {
		t.Fatal("a key path that is a directory must fail")
	}
}
