// Package mcpserver builds the per-key MCP server that fronts the upstreams:
// every upstream tool is exposed namespaced as {upstream}__{tool}, tools/list is
// ungated, and every tools/call except the `auth` tool is gated by the gate.
package mcpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tamcore/mcp-auth-proxy/internal/gate"
	"github.com/tamcore/mcp-auth-proxy/internal/metrics"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
	"github.com/tamcore/mcp-auth-proxy/internal/upstream"
	"github.com/tamcore/mcp-auth-proxy/internal/version"
)

// NamespaceSep separates upstream and tool names in proxied tool names.
const NamespaceSep = "__"

// AuthToolName is the ungated authorization tool.
const AuthToolName = "auth"

// Proxy builds and caches one MCP server per key.
type Proxy struct {
	pool    *upstream.Pool
	store   *store.Store
	gate    *gate.Gate
	metrics *metrics.Metrics
	logger  *slog.Logger

	auditEnabled bool
	logResponses bool

	mu      sync.Mutex
	servers map[string]cachedServer
	userUps map[string]map[string]*upstream.Upstream
}

// Options configures the proxy.
type Options struct {
	Pool         *upstream.Pool
	Store        *store.Store
	Gate         *gate.Gate
	Metrics      *metrics.Metrics
	Logger       *slog.Logger
	AuditEnabled bool
	LogResponses bool
}

// New builds the proxy.
func New(o Options) *Proxy {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Proxy{
		pool: o.Pool, store: o.Store, gate: o.Gate, metrics: o.Metrics, logger: o.Logger,
		auditEnabled: o.AuditEnabled, logResponses: o.LogResponses,
		servers: map[string]cachedServer{}, userUps: map[string]map[string]*upstream.Upstream{},
	}
}

// cachedServer is a built per-key server and the upstream list it was built
// for; a key whose upstreams changed since is rebuilt.
type cachedServer struct {
	srv       *mcp.Server
	upstreams string
}

// ServerFor returns the cached per-key MCP server, building it on first use.
func (p *Proxy) ServerFor(ctx context.Context, key *store.Key) (*mcp.Server, error) {
	sig := strings.Join(key.Upstreams, "\x00")
	p.mu.Lock()
	c, ok := p.servers[key.ID]
	p.mu.Unlock()
	if ok && c.upstreams == sig {
		return c.srv, nil
	}
	srv, complete := p.build(ctx, key)
	if complete {
		p.mu.Lock()
		p.servers[key.ID] = cachedServer{srv: srv, upstreams: sig}
		p.mu.Unlock()
	}
	return srv, nil
}

// build assembles the key's server. A failing upstream only drops its own
// tools; the result is then incomplete and not cached, so it is retried.
func (p *Proxy) build(ctx context.Context, key *store.Key) (*mcp.Server, bool) {
	srv := mcp.NewServer(version.Implementation(), nil)
	p.addAuthTool(srv, key)
	complete := true
	for _, name := range key.Upstreams {
		if err := p.addUpstreamTools(ctx, srv, key, name); err != nil {
			p.logger.Warn("upstream unavailable for key", "key", key.ID, "upstream", name, "error", err)
			complete = false
		}
	}
	return srv, complete
}

func (p *Proxy) addUpstreamTools(ctx context.Context, srv *mcp.Server, key *store.Key, name string) error {
	u, err := p.resolveUpstream(ctx, key, name)
	if err != nil {
		return err
	}
	tools, err := u.Tools(ctx)
	if errors.Is(err, upstream.ErrNoToken) {
		return fmt.Errorf("mcpserver: upstream %s is not linked for this user; link it in the web portal: %w", name, err)
	}
	if err != nil {
		return fmt.Errorf("mcpserver: upstream %s: %w", name, err)
	}
	for _, t := range tools {
		tool := t
		srv.AddTool(&mcp.Tool{
			Name:        name + NamespaceSep + tool.Name,
			Description: tool.Description,
			InputSchema: tool.InputSchema,
		}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return p.callProxied(ctx, key, name, tool.Name, req.Params.Arguments)
		})
	}
	return nil
}

// resolveUpstream finds a named upstream for a key: the key owner's own
// database upstreams win over same-named global ones, and a global OAuth
// upstream runs with the key owner's own token.
func (p *Proxy) resolveUpstream(ctx context.Context, key *store.Key, name string) (*upstream.Upstream, error) {
	if key.UserID == nil {
		return p.pool.Get(name)
	}
	cache, err := p.userCache(ctx, *key.UserID)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if u, ok := cache[name]; ok {
		return u, nil
	}
	u, err := p.pool.Get(name)
	if err != nil || !u.OAuth() {
		return u, err
	}
	owned := u.WithOwner(*key.UserID)
	cache[name] = owned
	return owned, nil
}

// userCache returns the user's upstream cache, seeded with their database
// upstreams on first use.
func (p *Proxy) userCache(ctx context.Context, userID string) (map[string]*upstream.Upstream, error) {
	p.mu.Lock()
	cache, ok := p.userUps[userID]
	p.mu.Unlock()
	if ok {
		return cache, nil
	}
	ups, err := p.store.RunnableUserUpstreams(ctx, userID)
	if err != nil {
		return nil, err
	}
	cache = map[string]*upstream.Upstream{}
	for _, row := range ups {
		cache[row.Name] = upstream.NewFromConfig(row.Config(), p.store, nil, p.logger)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.userUps[userID]; ok {
		return existing, nil
	}
	p.userUps[userID] = cache
	return cache, nil
}

// audit records one proxied call for the portal audit log.
func (p *Proxy) audit(ctx context.Context, key *store.Key,
	toolName string, args json.RawMessage, res *mcp.CallToolResult) {
	if !p.auditEnabled || key.UserID == nil {
		return
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return
	}
	e := &store.AuditEntry{
		ID:        "a_" + hex.EncodeToString(id),
		UserID:    *key.UserID,
		KeyID:     key.ID,
		KeyLabel:  key.Label,
		ToolName:  toolName,
		Arguments: string(args),
		CreatedAt: time.Now().UTC(),
	}
	if p.logResponses && res != nil {
		if b, err := json.Marshal(res.Content); err == nil {
			s := string(b)
			e.Response = &s
		}
	}
	attrs := []any{"user_id", e.UserID, "key_id", e.KeyID, "key", e.KeyLabel, "tool", e.ToolName,
		"arguments", e.Arguments, "is_error", res != nil && res.IsError}
	if e.Response != nil {
		attrs = append(attrs, "response", *e.Response)
	}
	p.logger.Info("tool call", attrs...)
	if err := p.store.AppendAudit(ctx, e); err != nil {
		p.logger.Error("append audit", "error", err)
	}
}

func (p *Proxy) callProxied(ctx context.Context, key *store.Key,
	upstreamName, toolName string, args json.RawMessage) (*mcp.CallToolResult, error) {
	fullName := upstreamName + NamespaceSep + toolName
	if !p.gate.Check(ctx, key.ID) {
		msg, err := p.gate.Block(ctx, key, fullName)
		if err != nil {
			p.logger.Error("gate block failed", "key", key.ID, "tool", fullName, "error", err)
			p.metrics.ToolBlocked()
			return errorResult("Blocked: authorization could not be started. Retry the call."), nil
		}
		p.metrics.ToolBlocked()
		return errorResult(msg), nil
	}
	u, err := p.resolveUpstream(ctx, key, upstreamName)
	if err != nil {
		p.metrics.ToolUpstreamError()
		msg := fmt.Sprintf("Tool %q failed: upstream %q is not configured.", fullName, upstreamName)
		return errorResult(msg), nil
	}
	res, err := u.Call(ctx, toolName, args)
	if err != nil {
		// Sanitized: name the upstream and tool, never headers, URLs, or payloads.
		p.logger.Error("upstream call failed", "upstream", upstreamName, "tool", toolName, "error", err)
		p.metrics.ToolUpstreamError()
		return errorResult(fmt.Sprintf("Tool %q failed on upstream %q.", fullName, upstreamName)), nil
	}
	p.metrics.ToolAllowed()
	p.audit(ctx, key, fullName, args, res)
	if !res.IsError {
		if err := p.store.MarkKeySuccess(ctx, key.ID, time.Now().UTC()); err != nil {
			p.logger.Warn("mark key success", "key", key.ID, "error", err)
		}
	}
	return res, nil
}

// AuthInput is the auth tool's argument: one required otp string, 3..8 chars.
type AuthInput struct {
	OTP string `json:"otp"`
}

// AuthOutput is the auth tool's structured output.
type AuthOutput struct {
	Message string `json:"message"`
}

// authInputSchema is the published JSON Schema for the auth tool: otp is a
// required string with minLength 3 and maxLength 8.
var authInputSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"otp": map[string]any{
			"type":        "string",
			"minLength":   3,
			"maxLength":   8,
			"description": "The one-time code from the owner's phone notification or web portal",
		},
	},
	"required":             []string{"otp"},
	"additionalProperties": false,
}

func (p *Proxy) addAuthTool(srv *mcp.Server, key *store.Key) {
	srv.AddTool(&mcp.Tool{
		Name: AuthToolName,
		Description: "Authorize this session with the one-time code from the owner's phone notification or web portal. " +
			"After success, retry the tool call you were blocked on.",
		InputSchema: authInputSchema,
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var in AuthInput
		if err := json.Unmarshal(req.Params.Arguments, &in); err != nil {
			return errorResult("Invalid arguments: `otp` (string, 3-8 chars) is required."), nil
		}
		if len(in.OTP) < 3 || len(in.OTP) > 8 {
			return errorResult("Invalid arguments: `otp` must be 3-8 characters."), nil
		}
		return p.callAuth(ctx, key, in.OTP)
	})
}

func (p *Proxy) callAuth(ctx context.Context, key *store.Key, otp string) (*mcp.CallToolResult, error) {
	expiry, err := p.gate.Verify(ctx, key, otp)
	if err == nil {
		p.metrics.ToolGranted()
		p.metrics.AuthGranted()
		return textResult(gate.AuthorizedMessage(expiry)), nil
	}
	msg := authFailureMessage(err)
	switch {
	case errors.Is(err, gate.ErrWrongCode):
		p.metrics.ToolWrongCode()
		p.metrics.AuthWrongCode()
	case errors.Is(err, gate.ErrExhausted):
		p.metrics.ToolWrongCode()
		p.metrics.AuthExhausted()
	case errors.Is(err, gate.ErrExpired):
		p.metrics.AuthExpired()
	default:
		p.metrics.AuthNoChallenge()
	}
	return errorResult(msg), nil
}

func authFailureMessage(err error) string {
	switch {
	case errors.Is(err, gate.ErrWrongCode):
		return "Wrong one-time code. Ask the owner for the current code (phone notification or web portal) " +
			"and call `auth` again."
	case errors.Is(err, gate.ErrExhausted):
		return "No attempts left for this code. Retry the blocked tool call to receive a fresh code."
	case errors.Is(err, gate.ErrExpired):
		return "The one-time code expired. Retry the blocked tool call to receive a fresh code."
	default:
		return "No pending authorization request. Retry the tool call you were blocked on to receive a code."
	}
}

func textResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}

func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}
