package cmd

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"
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
