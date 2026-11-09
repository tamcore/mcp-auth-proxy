// Package cmd holds the cobra commands of mcp-auth-proxy.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Execute runs the root command.
func Execute() {
	root := &cobra.Command{
		Use:   "mcp-auth-proxy",
		Short: "Personal MCP auth proxy: one endpoint, per-client keys, one-time-code gates",
		Long: "mcp-auth-proxy fronts several MCP servers behind one endpoint. Every AI client gets its own " +
			"key and MCP URL, and every tool call is gated behind a one-time code pushed to the owner's phone.",
	}
	root.PersistentFlags().String("config", "", "path to YAML config file (env MCP_PROXY_CONFIG)")
	root.AddCommand(newServeCmd(), newKeyCmd(), newUpstreamCmd(), newDoctorCmd(), newDevEchoCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
