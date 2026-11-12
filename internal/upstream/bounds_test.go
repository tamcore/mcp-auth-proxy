package upstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

const (
	unusedAuthorize = "http://unused/authorize"
	testClientID    = "cid"
)

func TestOversizedUpstreamResponseIsCut(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "Application/JSON; charset=utf-8")
		chunk := []byte(strings.Repeat("x", 1<<20))
		for range maxResponseBytes>>20 + 1 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer big.Close()
	u := NewFromConfig(config.UpstreamConfig{Name: "big", URL: big.URL}, nil, big.Client(), nil)
	resp, err := u.httpClientWithAuth().Post(big.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, err = io.Copy(io.Discard, resp.Body)
	if _, ok := errors.AsType[*http.MaxBytesError](err); !ok {
		t.Fatalf("an oversized response must fail with MaxBytesError, got %v", err)
	}
}

func TestRefreshIsSkippedWhenAnotherRequestAlreadyRotated(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	var refreshes atomic.Int32
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		refreshes.Add(1)
		w.WriteHeader(http.StatusBadRequest) // the old refresh token was already used
	}))
	defer tokenSrv.Close()
	cfg := config.UpstreamConfig{Name: "rot", URL: "http://unused", OAuth: &config.UpstreamOAuthConfig{
		AuthorizeURL: unusedAuthorize, TokenURL: tokenSrv.URL, ClientID: testClientID}}
	rotated := &store.UpstreamToken{Upstream: "rot", AccessToken: "at-new", RefreshToken: "rt-new"}
	if err := st.SaveUpstreamToken(ctx, rotated); err != nil {
		t.Fatal(err)
	}
	rt := &authRoundTripper{up: &Upstream{cfg: cfg, store: st, httpc: tokenSrv.Client()}}
	if err := rt.refresh(ctx, "at-old"); err != nil {
		t.Fatalf("a token rotated by another request must be used, not refreshed again: %v", err)
	}
	if refreshes.Load() != 0 {
		t.Fatal("refresh hit the token endpoint although the stored token was already newer")
	}
}

func TestStreamedAnswersAreNotCapped(t *testing.T) {
	sse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		chunk := []byte("data: " + strings.Repeat("x", 1<<20) + "\n\n")
		for range maxResponseBytes>>20 + 1 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer sse.Close()
	u := NewFromConfig(config.UpstreamConfig{Name: "sse", URL: sse.URL}, nil, sse.Client(), nil)
	resp, err := u.httpClientWithAuth().Post(sse.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("a long SSE answer (progress, subscriptions) must not be cut: %v", err)
	}
}

func TestSeparateInstancesNeverSpendOneRefreshTokenTwice(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	var spent sync.Map
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if _, used := spent.LoadOrStore(r.PostForm.Get("refresh_token"), true); used {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-new","refresh_token":"rt-new","token_type":"Bearer","expires_in":3600}`))
	}))
	defer tokenSrv.Close()
	cfg := config.UpstreamConfig{Name: "rot2", URL: "http://unused", OAuth: &config.UpstreamOAuthConfig{
		AuthorizeURL: unusedAuthorize, TokenURL: tokenSrv.URL, ClientID: testClientID}}
	old := &store.UpstreamToken{Upstream: "rot2", AccessToken: "at-old", RefreshToken: "rt-old"}
	if err := st.SaveUpstreamToken(ctx, old); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	for range 2 {
		rt := &authRoundTripper{up: &Upstream{cfg: cfg, store: st, httpc: tokenSrv.Client()}}
		go func() { errs <- rt.refresh(ctx, "at-old") }()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("a second instance spent the rotated refresh token again: %v", err)
		}
	}
}
