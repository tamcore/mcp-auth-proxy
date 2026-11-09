package cmd

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/tamcore/mcp-auth-proxy/internal/upstream"
)

func newUpstreamCmd() *cobra.Command {
	c := &cobra.Command{Use: "upstream", Short: "Inspect and link upstream MCP servers"}
	c.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List configured upstreams",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			for _, u := range cfg.Upstreams {
				src := u.URL
				if src == "" {
					src = "command: " + fmt.Sprintf("%v", u.Command)
				}
				oauth := ""
				if u.OAuth != nil {
					oauth = " (oauth)"
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s%s\n", u.Name, src, oauth)
			}
			return nil
		},
	}, &cobra.Command{
		Use:   "status",
		Short: "Connect to each upstream and report tool counts",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			st, err := openStore(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			pool := upstream.NewPool(cfg.Upstreams, st, nil, newLogger())
			for _, name := range pool.Names() {
				u, _ := pool.Get(name)
				_, tools, err := u.Status(cmd.Context())
				if err != nil {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\tERROR: %v\n", name, err)
					continue
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\tconnected\ttools=%d\n", name, tools)
			}
			return nil
		},
	}, &cobra.Command{
		Use:   "link <name>",
		Short: "Run the one-time interactive OAuth linking flow for an upstream",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			st, err := openStore(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			pool := upstream.NewPool(cfg.Upstreams, st, nil, newLogger())
			u, err := pool.Get(args[0])
			if err != nil {
				return err
			}
			return u.Link(cmd.Context(), upstream.LinkOptions{
				Stdout:      cmd.OutOrStdout(),
				OpenBrowser: openBrowser,
			})
		},
	})
	return c
}

func openBrowser(url string) error {
	return exec.Command("xdg-open", url).Start()
}
