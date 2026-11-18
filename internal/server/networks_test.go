package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

const (
	netToken = "mak_networks"
	echoName = "echo"
	pong     = "pong"
)

func echoUpstreamURL(t *testing.T) string {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: echoName, Version: "dev"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: echoName}, func(context.Context, *mcp.CallToolRequest, struct{}) (
		*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: pong}}}, nil, nil
	})
	ts := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true}))
	t.Cleanup(ts.Close)
	return ts.URL
}

func networkServer(t *testing.T, proxies string, allowed, trusted []netip.Prefix) *httptest.Server {
	t.Helper()
	up := echoUpstreamURL(t)
	srv := newTestSrvLogged(t, nil, func(c *config.Config) {
		c.Upstreams = []config.UpstreamConfig{{Name: echoName, URL: up}}
		if proxies != "" {
			c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix(proxies)}
		}
	})
	key := &store.Key{ID: "k_net", Kind: store.KeyKindStatic, Label: "claude-cli", SecretHash: store.HashSecret(netToken),
		Upstreams: []string{echoName}, TTLSeconds: 60, CreatedAt: time.Now().UTC(),
		AllowedCIDRs: allowed, TrustedCIDRs: trusted}
	if err := srv.store.CreateKey(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

type xffTransport string

func (x xffTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if x != "" {
		r.Header.Set("X-Forwarded-For", string(x))
	}
	return http.DefaultTransport.RoundTrip(r)
}

func callEcho(t *testing.T, ts *httptest.Server, xff string) string {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	sess, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint: ts.URL + "/mcp/" + netToken, HTTPClient: &http.Client{Transport: xffTransport(xff)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "echo__echo"})
	if err != nil {
		t.Fatal(err)
	}
	return res.Content[0].(*mcp.TextContent).Text
}

func TestTrustedNetworkSkipsGate(t *testing.T) {
	loop := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	if got := callEcho(t, networkServer(t, "", nil, loop), ""); got != pong {
		t.Fatalf("trusted peer must skip the gate, got %q", got)
	}
	if got := callEcho(t, networkServer(t, "", nil, nil), ""); !strings.Contains(got, "one-time code") {
		t.Fatalf("untrusted call must be gated, got %q", got)
	}
}

func TestTrustedNetworkBehindProxy(t *testing.T) {
	laptop := []netip.Prefix{netip.MustParsePrefix("192.168.69.211/32")}
	ts := networkServer(t, "127.0.0.0/8", nil, laptop)
	if got := callEcho(t, ts, "192.168.69.211"); got != pong {
		t.Fatalf("laptop behind trusted proxy must skip the gate, got %q", got)
	}
	if got := callEcho(t, ts, "192.168.69.211, 10.42.1.44"); !strings.Contains(got, "one-time code") {
		t.Fatalf("forged leftmost entry must not skip the gate, got %q", got)
	}
	direct := networkServer(t, "", nil, laptop)
	if got := callEcho(t, direct, "192.168.69.211"); !strings.Contains(got, "one-time code") {
		t.Fatalf("X-Forwarded-For from an untrusted peer must be ignored, got %q", got)
	}
}

func TestAllowedNetworksRefuseOthers(t *testing.T) {
	ts := networkServer(t, "", []netip.Prefix{netip.MustParsePrefix("192.168.69.0/24")}, nil)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp/"+netToken, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	loop := networkServer(t, "", []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, nil)
	if got := callEcho(t, loop, ""); !strings.Contains(got, "one-time code") {
		t.Fatalf("allowed network still needs the gate, got %q", got)
	}
}
