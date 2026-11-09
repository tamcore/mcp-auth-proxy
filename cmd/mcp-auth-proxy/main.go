// Command mcp-auth-proxy is a personal MCP auth proxy. The main package is thin;
// all logic lives in internal/.
package main

import "github.com/tamcore/mcp-auth-proxy/internal/cmd"

// Injected at release time by GoReleaser via -X main.version / -X main.commit.
var (
	version = "dev"
	commit  = "none"
)

func main() { cmd.Execute(cmd.BuildInfo{Version: version, Commit: commit}) }
