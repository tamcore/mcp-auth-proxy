// Package version holds the build values GoReleaser injects with
// -X github.com/tamcore/mcp-auth-proxy/internal/version.Version=... (and .Commit).
package version

import "github.com/modelcontextprotocol/go-sdk/mcp"

// Injected build values; the only package-level vars the repo rules allow here.
var (
	Version = "dev"
	Commit  = "none"
)

// Implementation is how the proxy names itself to clients and upstreams.
func Implementation() *mcp.Implementation {
	return &mcp.Implementation{Name: "mcp-auth-proxy", Version: Version}
}
