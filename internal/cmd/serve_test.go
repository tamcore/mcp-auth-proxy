package cmd

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	for range 100 {
		if c, err := net.Dial("tcp", addr); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never listened", addr)
}

func TestASlowServerDoesNotDelayTheOthersShutdown(t *testing.T) {
	release, entered := make(chan struct{}), make(chan struct{})
	defer close(release)
	slow := newHTTPServer(freeAddr(t), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	}))
	other := newHTTPServer(freeAddr(t), http.NotFoundHandler())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveUntilDone(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), 2*time.Second, slow, other)
	}()
	waitListening(t, slow.Addr)
	waitListening(t, other.Addr)
	go func() { _, _ = http.Get("http://" + slow.Addr) }()
	<-entered
	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		c, err := net.Dial("tcp", other.Addr)
		if err != nil {
			break
		}
		_ = c.Close()
		if time.Now().After(deadline) {
			t.Fatal("the other server kept listening while the slow one drained")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := <-done; err == nil {
		t.Fatal("the slow server's missed deadline must be reported")
	}
}

func TestStateDirIsTightenedToOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := restrictStateDir(dir, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("state dir mode %04o, want 0700", perm)
	}
}

func TestStateDirNotOwnedIsLoggedNotFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns everything")
	}
	var log bytes.Buffer
	if err := restrictStateDir("/usr", slog.New(slog.NewTextHandler(&log, nil))); err != nil {
		t.Fatalf("a volume root owned by someone else (fsGroup) must not stop start-up: %v", err)
	}
	if !strings.Contains(log.String(), "state dir") {
		t.Fatalf("the open state dir must be logged: %q", log.String())
	}
}

func TestStateDirIsTightenedBeforeTheStoreOpens(t *testing.T) {
	cfg := &config.Config{StateDir: t.TempDir()}
	if err := os.Chmod(cfg.StateDir, 0o777); err != nil {
		t.Fatal(err)
	}
	var modeAtOpen os.FileMode
	st, err := openState(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(ctx context.Context, c *config.Config) (*store.Store, error) {
			if fi, err := os.Stat(c.StateDir); err == nil {
				modeAtOpen = fi.Mode().Perm()
			}
			return openStore(ctx, c)
		})
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if modeAtOpen != 0o700 {
		t.Fatalf("the store opened in a state dir with mode %04o; another user could swap the database", modeAtOpen)
	}
}

func TestMissingStateDirIsCreatedOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := restrictStateDir(dir, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("a new state dir must be 0700: %v %v", fi, err)
	}
}
