package mcpserver

import (
	"context"
	"net/netip"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tamcore/mcp-auth-proxy/internal/metrics"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

type trustedClientKey struct{}

// WithTrustedClient marks a request from one of its key's trusted networks;
// its tool calls skip the one-time code.
func WithTrustedClient(ctx context.Context, addr netip.Addr) context.Context {
	return context.WithValue(ctx, trustedClientKey{}, addr)
}

// gateBlocked returns the blocked result when the call needs a one-time code.
func (p *Proxy) gateBlocked(ctx context.Context, key *store.Key, who metrics.Who,
	upstreamName, toolName string) *mcp.CallToolResult {
	fullName := upstreamName + NamespaceSep + toolName
	if addr, ok := ctx.Value(trustedClientKey{}).(netip.Addr); ok {
		p.logger.Info("gate skipped: trusted network", "key", key.ID, "tool", fullName, "client", addr.String())
		return nil
	}
	if p.gate.Check(ctx, key.ID) {
		return nil
	}
	p.metrics.ToolCall(who, upstreamName, toolName, metrics.ToolBlocked, 0)
	msg, err := p.gate.Block(ctx, key, fullName)
	if err != nil {
		p.logger.Error("gate block failed", "key", key.ID, "tool", fullName, "error", err)
		return errorResult("Blocked: authorization could not be started. Retry the call.")
	}
	return errorResult(msg)
}
