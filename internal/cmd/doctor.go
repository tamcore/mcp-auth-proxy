package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check config, state dir, secret permissions, upstreams, and users",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDoctor(cmd)
		},
	}
}

func runDoctor(cmd *cobra.Command) error {
	failed := false
	check := func(name string, err error) {
		if err != nil {
			failed = true
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "FAIL\t%s: %v\n", name, err)
			return
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "PASS\t%s\n", name)
	}
	cfg, err := loadConfig(cmd)
	check("config", err)
	if err != nil {
		return err
	}
	check("state dir", store.CheckSignSecretPerms(cfg.StateDir))
	check("upstreams", upstreamSanity(cfg))
	check("users", usersSanity(cfg))
	if failed {
		return fmt.Errorf("doctor: one or more checks failed")
	}
	return nil
}

func usersSanity(cfg *config.Config) error {
	if len(cfg.Users) == 0 {
		return fmt.Errorf("no users configured; add `users: [alice, ...]` or the web UI has no logins")
	}
	return nil
}

func upstreamSanity(cfg *config.Config) error {
	if len(cfg.Upstreams) == 0 {
		return fmt.Errorf("no upstreams configured")
	}
	return nil
}
