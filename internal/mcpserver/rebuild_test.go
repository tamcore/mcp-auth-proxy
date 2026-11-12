package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestFailingUpstreamIsNotAskedOnEveryRequest(t *testing.T) {
	var hits atomic.Int32
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(down.Close)
	p, _, key := newTestProxy(t, down.URL)
	ctx := context.Background()
	for range 5 {
		if _, err := p.ServerFor(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	first := hits.Load()
	if first == 0 {
		t.Fatal("upstream never asked")
	}
	for range 5 {
		_, _ = p.ServerFor(ctx, key)
	}
	if hits.Load() != first {
		t.Fatalf("a failing upstream was asked again on every request: %d then %d hits", first, hits.Load())
	}
}
