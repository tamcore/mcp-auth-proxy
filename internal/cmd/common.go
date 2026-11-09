package cmd

import (
	"context"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

// configPath reads the --config flag.
func configPath(cmd *cobra.Command) string {
	p, _ := cmd.Flags().GetString("config")
	if p == "" {
		p = os.Getenv("MCP_PROXY_CONFIG")
	}
	return p
}

// loadConfig loads and validates the configuration.
func loadConfig(cmd *cobra.Command) (*config.Config, error) {
	return config.Load(configPath(cmd))
}

// newLogger builds the JSON-to-stderr logger. stdout stays reserved for MCP
// frames and machine-readable command output.
func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// openStore opens (and migrates) the state database.
func openStore(ctx context.Context, cfg *config.Config) (*store.Store, error) {
	return store.Open(ctx, cfg.StateDir+"/proxy.db")
}
