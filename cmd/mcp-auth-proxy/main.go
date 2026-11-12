// Command mcp-auth-proxy is a personal MCP auth proxy. The main package is thin;
// all logic lives in internal/.
package main

import "github.com/tamcore/mcp-auth-proxy/internal/cmd"

func main() { cmd.Execute() }
