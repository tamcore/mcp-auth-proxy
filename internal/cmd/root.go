// Package cmd holds the cobra commands of mcp-auth-proxy.
package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// BuildInfo carries the injected build values. It is a package-level var because
// it is exactly the "injected build value" case the repo rules allow.
var Build = BuildInfo{Version: "dev", Commit: "none"}

// BuildInfo is the version/commit pair injected by the linker at release time.
type BuildInfo struct {
	Version string
	Commit  string
}

// Execute runs the root command.
func Execute(b BuildInfo) {
	Build = b
	root := &cobra.Command{
		Use:   "mcp-auth-proxy",
		Short: "Personal MCP auth proxy: one endpoint, per-client keys, one-time-code gates",
		Long: "mcp-auth-proxy fronts several MCP servers behind one endpoint. Every AI client gets its own " +
			"key and MCP URL, and every tool call is gated behind a one-time code pushed to the owner's phone.",
	}
	root.SilenceUsage = true // runtime errors are not usage errors
	root.PersistentFlags().String("config", "", "path to YAML config file (env MCP_PROXY_CONFIG)")
	root.RunE = func(cmd *cobra.Command, args []string) error {
		return errors.New("no command given; try: serve, key, upstream, doctor, dev-echo, version")
	}
	root.AddCommand(newServeCmd(), newKeyCmd(), newUpstreamCmd(), newDoctorCmd(), newDevEchoCmd(), newVersionCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the build version and commit",
		Run: func(cmd *cobra.Command, args []string) {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "mcp-auth-proxy %s (commit %s)\n", Build.Version, Build.Commit)
		},
	}
}
