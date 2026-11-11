package cmd

import (
	"context"
	"errors"
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

// loadConfig loads and validates the configuration. A config file is required:
// --config, MCP_PROXY_CONFIG, or ./config.yaml must exist.
func loadConfig(cmd *cobra.Command) (*config.Config, error) {
	p := configPath(cmd)
	if p == "" {
		if _, err := os.Stat("config.yaml"); err == nil {
			p = "config.yaml"
		}
	}
	if p == "" {
		return nil, errors.New("no config file: pass --config, set MCP_PROXY_CONFIG, or create ./config.yaml")
	}
	return config.Load(p)
}

// newLogger builds the JSON-to-stderr logger. stdout stays reserved for MCP
// frames and machine-readable command output.
func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// newServeLogger logs to stdout: serve has no machine-readable output, and
// container log pipelines expect the service log there.
func newServeLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// openStore opens (and migrates) the state database.
func openStore(ctx context.Context, cfg *config.Config) (*store.Store, error) {
	return store.Open(ctx, cfg.StateDir+"/proxy.db")
}
