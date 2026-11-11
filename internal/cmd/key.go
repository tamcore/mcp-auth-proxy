package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/identity"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func newKeyCmd() *cobra.Command {
	c := &cobra.Command{Use: "key", Short: "Manage client API keys"}
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a static key (token is shown exactly once)",
		RunE: func(cmd *cobra.Command, args []string) error {
			label, _ := cmd.Flags().GetString("label")
			ups, _ := cmd.Flags().GetString("upstreams")
			ttl, _ := cmd.Flags().GetDuration("ttl")
			user, _ := cmd.Flags().GetString("user")
			asJSON, _ := cmd.Flags().GetBool("json")
			return runKeyCreate(cmd, label, ups, ttl, user, asJSON)
		},
	}
	create.Flags().String("label", "", "human-readable label (required)")
	create.Flags().String("upstreams", "", "comma-separated upstream names (default: all)")
	create.Flags().Duration("ttl", 0, "session TTL override (default: config session_ttl)")
	create.Flags().String("user", "", "username to bind the key to (from config users)")
	create.Flags().Bool("json", false, "machine-readable output")
	_ = create.MarkFlagRequired("label")
	c.AddCommand(create, &cobra.Command{
		Use:   "list",
		Short: "List keys (no token material)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyList(cmd)
		},
	}, &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke a key (kills its session and pending challenge)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyRevoke(cmd, args[0])
		},
	})
	return c
}

func runKeyCreate(cmd *cobra.Command, label, ups string, ttl time.Duration, user string, asJSON bool) error {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}
	st, err := openStore(cmd.Context(), cfg)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	names := cfg.UpstreamNames()
	if ups != "" {
		names = strings.Split(ups, ",")
		for i := range names {
			names[i] = strings.TrimSpace(names[i])
		}
	}
	if ttl <= 0 {
		ttl = cfg.SessionTTL
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	token := identity.StaticPrefix + hex.EncodeToString(raw)
	key := &store.Key{
		ID:         "k_" + hex.EncodeToString(raw[:8]),
		Kind:       store.KeyKindStatic,
		Label:      label,
		SecretHash: store.HashSecret(token),
		Upstreams:  names,
		TTLSeconds: int64(ttl / time.Second),
		CreatedAt:  time.Now().UTC(),
	}
	if user != "" {
		u, err := st.UserByName(cmd.Context(), user)
		if err != nil {
			return fmt.Errorf("user %q: %w", user, err)
		}
		key.UserID = &u.ID
		for _, n := range names {
			if !upstreamAllowed(cfg, u.Username, n) {
				return fmt.Errorf("upstream %q is not available to user %q", n, user)
			}
		}
	}
	if err := st.CreateKey(cmd.Context(), key); err != nil {
		return err
	}
	mcpURL := strings.TrimRight(cfg.BaseURL, "/") + "/mcp/" + token
	out := map[string]string{
		"id":          key.ID,
		"label":       key.Label,
		"token":       token,
		"mcp_url":     mcpURL,
		"bearer":      "Authorization: Bearer " + token,
		"upstreams":   strings.Join(names, ","),
		"session_ttl": ttl.String(),
	}
	if asJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Created key %s (%s)\n", key.ID, key.Label)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Token (shown once): %s\n", token)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "MCP URL:           %s\n", mcpURL)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Bearer:            Authorization: Bearer %s\n", token)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Upstreams:         %s\n", strings.Join(names, ","))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Session TTL:       %s\n", ttl)
	return nil
}

func upstreamAllowed(cfg *config.Config, username, name string) bool {
	for _, u := range cfg.Upstreams {
		if u.Name == name {
			return u.Allows(username)
		}
	}
	return false
}

func runKeyList(cmd *cobra.Command) error {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}
	st, err := openStore(cmd.Context(), cfg)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	keys, err := st.ListKeys(cmd.Context())
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no keys")
		return nil
	}
	for _, k := range keys {
		state := "active"
		if k.Revoked() {
			state = "revoked"
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\tupstreams=%s\tttl=%ds\t%s\n",
			k.ID, k.Kind, k.Label, strings.Join(k.Upstreams, ","), k.TTLSeconds, state)
	}
	return nil
}

func runKeyRevoke(cmd *cobra.Command, id string) error {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}
	st, err := openStore(cmd.Context(), cfg)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if _, err := st.KeyByID(cmd.Context(), id); err != nil {
		return fmt.Errorf("key %s: %w", id, err)
	}
	if err := st.RevokeKey(cmd.Context(), id, time.Now().UTC()); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "revoked %s\n", id)
	return nil
}
