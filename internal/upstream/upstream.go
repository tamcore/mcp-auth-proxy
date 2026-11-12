// Package upstream owns the pool of MCP clients to the configured upstream
// servers. Connections are lazy, tool listing happens at connect time, and calls
// are forwarded with the client's own arguments. Static headers and OAuth token
// injection (with refresh-and-persist) wrap HTTP upstreams.
package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
	"github.com/tamcore/mcp-auth-proxy/internal/version"
)

// ErrUnknownUpstream is returned when a name is not configured.
var ErrUnknownUpstream = errors.New("upstream: unknown upstream")

// Upstream is one connected (or lazily connectable) MCP server.
type Upstream struct {
	cfg     config.UpstreamConfig
	store   *store.Store
	httpc   *http.Client
	logger  *slog.Logger
	owner   string
	mu      sync.Mutex
	client  *mcp.Client
	session *mcp.ClientSession
	tools   []mcp.Tool
}

// Pool is the set of configured upstreams by name.
type Pool struct {
	ups   map[string]*Upstream
	order []string
}

// NewPool builds the pool from config. No connections are opened yet.
func NewPool(cfgs []config.UpstreamConfig, st *store.Store, httpc *http.Client, logger *slog.Logger) *Pool {
	p := &Pool{ups: map[string]*Upstream{}}
	for _, c := range cfgs {
		p.ups[c.Name] = NewFromConfig(c, st, httpc, logger)
		p.order = append(p.order, c.Name)
	}
	return p
}

// WithOwner returns a fresh, unconnected copy of u whose OAuth tokens belong
// to the given user.
func (u *Upstream) WithOwner(userID string) *Upstream {
	return &Upstream{cfg: u.cfg, store: u.store, httpc: u.httpc, logger: u.logger, owner: userID}
}

// OAuth reports whether the upstream authenticates with per-user OAuth tokens.
func (u *Upstream) OAuth() bool { return u.cfg.OAuth != nil }

// NewFromConfig builds a single Upstream from a config (also used for
// database-defined per-user upstreams).
func NewFromConfig(c config.UpstreamConfig, st *store.Store, httpc *http.Client, logger *slog.Logger) *Upstream {
	if logger == nil {
		logger = slog.Default()
	}
	return &Upstream{cfg: c, store: st, httpc: httpc, logger: logger}
}

// Names returns the upstream names in config order.
func (p *Pool) Names() []string { return p.order }

// Get returns the upstream by name.
func (p *Pool) Get(name string) (*Upstream, error) {
	u, ok := p.ups[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownUpstream, name)
	}
	return u, nil
}

// Config returns the config of a named upstream.
func (p *Pool) Config(name string) (config.UpstreamConfig, error) {
	u, err := p.Get(name)
	if err != nil {
		return config.UpstreamConfig{}, err
	}
	return u.cfg, nil
}

// Connect lazily connects and lists tools. It is idempotent.
func (u *Upstream) Connect(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.session != nil {
		return nil
	}
	transport := u.transport()
	client := mcp.NewClient(version.Implementation(), nil)
	sess, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return fmt.Errorf("upstream %s: connect: %w", u.cfg.Name, err)
	}
	res, err := sess.ListTools(ctx, nil)
	if err != nil {
		_ = sess.Close()
		return fmt.Errorf("upstream %s: list tools: %w", u.cfg.Name, err)
	}
	u.client = client
	u.session = sess
	for _, t := range res.Tools {
		u.tools = append(u.tools, *t)
	}
	u.logger.Info("upstream connected", "upstream", u.cfg.Name, "tools", len(res.Tools))
	return nil
}

func (u *Upstream) transport() mcp.Transport {
	if u.cfg.URL != "" {
		hc := u.httpClientWithAuth()
		return &mcp.StreamableClientTransport{Endpoint: u.cfg.URL, HTTPClient: hc}
	}
	cmd := exec.Command(u.cfg.Command[0], u.cfg.Command[1:]...)
	return &mcp.CommandTransport{Command: cmd}
}

func (u *Upstream) httpClientWithAuth() *http.Client {
	base := http.DefaultTransport
	if u.httpc != nil {
		if tr, ok := u.httpc.Transport.(*http.Transport); ok {
			base = tr
		}
	}
	rt := &authRoundTripper{base: base, up: u, header: http.Header{}}
	for k, v := range u.cfg.Headers {
		rt.header.Set(k, v)
	}
	return &http.Client{Transport: rt}
}

// Tools returns the upstream's tool list, connecting if needed.
// Close ends the upstream session (and a stdio child process), if any.
func (u *Upstream) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.session == nil {
		return nil
	}
	err := u.session.Close()
	u.session, u.client, u.tools = nil, nil, nil
	return err
}

func (u *Upstream) Tools(ctx context.Context) ([]mcp.Tool, error) {
	if err := u.Connect(ctx); err != nil {
		return nil, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]mcp.Tool(nil), u.tools...), nil
}

// Call forwards a tool call with the client's own raw arguments.
func (u *Upstream) Call(ctx context.Context, name string, args json.RawMessage) (*mcp.CallToolResult, error) {
	if err := u.Connect(ctx); err != nil {
		return nil, err
	}
	u.mu.Lock()
	sess := u.session
	u.mu.Unlock()
	if sess == nil {
		return nil, fmt.Errorf("upstream %s: not connected", u.cfg.Name)
	}
	params := &mcp.CallToolParams{Name: name}
	if len(args) > 0 {
		var m map[string]any
		if err := json.Unmarshal(args, &m); err != nil {
			return nil, fmt.Errorf("upstream %s: decode arguments: %w", u.cfg.Name, err)
		}
		params.Arguments = m
	}
	res, err := sess.CallTool(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("upstream %s: call %s: %w", u.cfg.Name, name, err)
	}
	return res, nil
}

// Status reports whether the upstream is connected and how many tools it has.
func (u *Upstream) Status(ctx context.Context) (connected bool, tools int, err error) {
	u.mu.Lock()
	connected = u.session != nil
	tools = len(u.tools)
	u.mu.Unlock()
	if !connected {
		err = u.Connect(ctx)
		if err == nil {
			u.mu.Lock()
			connected = true
			tools = len(u.tools)
			u.mu.Unlock()
		}
	}
	return connected, tools, err
}
