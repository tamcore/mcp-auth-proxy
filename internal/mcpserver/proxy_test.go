package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/gate"
	"github.com/tamcore/mcp-auth-proxy/internal/metrics"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
	"github.com/tamcore/mcp-auth-proxy/internal/upstream"
)

const (
	echoToolName = "echo"
	otpArg       = "otp"
)

type fakeNotifier struct {
	mu    sync.Mutex
	calls []*store.Challenge
}

func (f *fakeNotifier) Notify(_ context.Context, ch *store.Challenge, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, ch)
	return nil
}

func (f *fakeNotifier) last() *store.Challenge {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

// echoUpstream serves one MCP tool "echo" over streamable HTTP.
func echoUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "echo-upstream", Version: "dev"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: echoToolName, Description: "echo text"},
		func(_ context.Context, _ *mcp.CallToolRequest, in struct {
			Text string `json:"text"`
		}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "echo: " + in.Text}},
			}, nil, nil
		})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true})
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

func newTestProxy(t *testing.T, upstreamURL string) (*Proxy, *fakeNotifier, *store.Key) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	key := &store.Key{ID: "k_1", Kind: store.KeyKindStatic, Label: "laptop", SecretHash: "h",
		Upstreams: []string{"echo"}, TTLSeconds: 28800, CreatedAt: now}
	if err := st.CreateKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	ntf := &fakeNotifier{}
	g := gate.New(gate.Options{
		Store: st, Digits: 5, Expiry: 3 * time.Minute, MaxAttempts: 3,
		RenotifyFloor: 30 * time.Second, DefaultTTL: 8 * time.Hour,
		BaseURL: "http://proxy.local", SignSecret: []byte("0123456789abcdef0123456789abcdef"),
		Notifier: ntf, Now: func() time.Time { return now },
		NewID: func() string { return "c1" },
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pool := upstream.NewPool([]config.UpstreamConfig{{Name: "echo", URL: upstreamURL}}, st, nil, logger)
	m := metrics.New(nil, nil, nil)
	proxy := New(Options{Pool: pool, Store: st, Gate: g, Metrics: m, Logger: logger, AuditEnabled: true})
	return proxy, ntf, key
}

func connectClient(t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	go func() { _, _ = srv.Connect(context.Background(), st, nil) }()
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	sess, err := c.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func callText(t *testing.T, sess *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	txt := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			txt = tc.Text
		}
	}
	return txt, res.IsError
}

func TestProxyGateFlow(t *testing.T) {
	ts := echoUpstream(t)
	proxy, ntf, key := newTestProxy(t, ts.URL)
	srv, err := proxy.ServerFor(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	sess := connectClient(t, srv)

	res, err := sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	if !names["echo__"+echoToolName] || !names[AuthToolName] {
		t.Fatalf("tools: %v", names)
	}

	msg, isErr := callText(t, sess, "echo__"+echoToolName, map[string]any{"text": "hi"})
	if !isErr || !strings.Contains(msg, "requires a one-time code") || !strings.Contains(msg, `"echo__`+echoToolName+`"`) {
		t.Fatalf("blocked message: %q (isErr=%v)", msg, isErr)
	}
	otp := ntf.last().PendingOTP

	msg, isErr = callText(t, sess, AuthToolName, map[string]any{otpArg: "00000"})
	if !isErr || !strings.Contains(msg, "Wrong") {
		t.Fatalf("wrong otp: %q", msg)
	}
	msg, isErr = callText(t, sess, AuthToolName, map[string]any{otpArg: otp})
	if isErr || !strings.Contains(msg, "Session authorized until") {
		t.Fatalf("auth: %q (isErr=%v)", msg, isErr)
	}
	msg, isErr = callText(t, sess, "echo__"+echoToolName, map[string]any{"text": "hi"})
	if isErr || !strings.Contains(msg, "echo: hi") {
		t.Fatalf("retry after auth: %q (isErr=%v)", msg, isErr)
	}
	assertLastSuccess(t, proxy, key.ID)
	assertGateFlowMetrics(t, proxy, key.Label)
}

func assertLastSuccess(t *testing.T, p *Proxy, keyID string) {
	t.Helper()
	if got, err := p.store.KeyByID(context.Background(), keyID); err != nil || got.LastSuccessAt == nil {
		t.Fatalf("successful call must set last_success_at: %+v %v", got, err)
	}
}

func TestServerRebuiltWhenKeyUpstreamsChange(t *testing.T) {
	proxy, _, key := newTestProxy(t, echoUpstream(t).URL)
	ctx := context.Background()
	first, err := proxy.ServerFor(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := proxy.ServerFor(ctx, key); again != first {
		t.Fatal("unchanged key must reuse the cached server")
	}
	changed := *key
	changed.Upstreams = nil
	srv, err := proxy.ServerFor(ctx, &changed)
	if err != nil || srv == first {
		t.Fatalf("changed upstreams must rebuild the server: %v", err)
	}
	res, err := connectClient(t, srv).ListTools(ctx, nil)
	if err != nil || len(res.Tools) != 1 || res.Tools[0].Name != AuthToolName {
		t.Fatalf("rebuilt server tools: %+v %v", res, err)
	}
}

func TestAuthToolSchema(t *testing.T) {
	ts := echoUpstream(t)
	proxy, _, key := newTestProxy(t, ts.URL)
	srv, err := proxy.ServerFor(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	sess := connectClient(t, srv)
	res, err := sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		if tool.Name != AuthToolName {
			continue
		}
		schema, ok := tool.InputSchema.(map[string]any)
		if !ok {
			t.Fatalf("input schema type %T", tool.InputSchema)
		}
		props := schema["properties"].(map[string]any)
		otp := props["otp"].(map[string]any)
		if otp["minLength"].(float64) != 3 || otp["maxLength"].(float64) != 8 {
			t.Fatalf("otp schema: %v", otp)
		}
		req := schema["required"].([]any)
		if len(req) != 1 || req[0].(string) != "otp" {
			t.Fatalf("required: %v", req)
		}
		return
	}
	t.Fatal("auth tool not found")
}

func TestAuditEntryIsLogged(t *testing.T) {
	p, _, key := newTestProxy(t, echoUpstream(t).URL)
	ctx := context.Background()
	uid := "u_audit"
	if err := p.store.CreateUser(ctx, &store.User{ID: uid, Username: "auditor", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	key.UserID = &uid
	var buf bytes.Buffer
	p.logger = slog.New(slog.NewJSONHandler(&buf, nil))
	p.audit(ctx, key, "echo__echo", json.RawMessage(`{"text":"hi"}`), &mcp.CallToolResult{})
	for _, want := range []string{`"msg":"tool call"`, `"tool":"echo__echo"`, `"user_id":"u_audit"`, `"key_id":"k_1"`,
		`"arguments":"{\"text\":\"hi\"}"`} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("audit log missing %s: %s", want, buf.String())
		}
	}
}
