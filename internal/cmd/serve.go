package cmd

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/gate"
	"github.com/tamcore/mcp-auth-proxy/internal/mcpserver"
	"github.com/tamcore/mcp-auth-proxy/internal/metrics"
	"github.com/tamcore/mcp-auth-proxy/internal/ntfy"
	"github.com/tamcore/mcp-auth-proxy/internal/server"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
	"github.com/tamcore/mcp-auth-proxy/internal/upstream"
)

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the auth proxy HTTP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd)
		},
	}
}

// gcAudit deletes audit entries older than the configured retention.
func gcAudit(st *store.Store, cfg *config.Config, logger *slog.Logger) {
	n, err := st.DeleteAuditOlderThan(context.Background(), time.Now().Add(-cfg.Audit.Retention))
	if err != nil {
		logger.Error("audit gc", "error", err)
		return
	}
	if n > 0 {
		logger.Info("audit gc removed entries", "count", n)
	}
}

func runServe(cmd *cobra.Command) error {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}
	logger := newServeLogger()
	st, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	for _, m := range st.MigrationsApplied() {
		logger.Info("migration applied", "migration", m, "backup", st.MigrationBackup())
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	secret, err := store.EnsureSignSecret(cfg.StateDir)
	if err != nil {
		return err
	}
	invites, err := st.EnsureConfigUsers(ctx, cfg.Users, cfg.Admins, time.Now().UTC())
	if err != nil {
		return err
	}
	for name, token := range invites {
		logger.Warn("invite link for user without password (replaces earlier links)",
			"user", name, "url", strings.TrimRight(cfg.BaseURL, "/")+"/invite/"+token)
	}
	if cfg.LegacyNtfy {
		logger.Warn("config: the global ntfy block is ignored; every user sets their own push target in the portal")
	}
	gcAudit(st, cfg, logger)
	httpClient := &http.Client{Timeout: 30 * time.Second}
	g := gate.New(gate.Options{
		Store:         st,
		Digits:        cfg.OTP.Digits,
		Expiry:        cfg.OTP.Expiry,
		MaxAttempts:   cfg.OTP.Attempts,
		RenotifyFloor: cfg.OTP.RenotifyFloor,
		DefaultTTL:    cfg.SessionTTL,
		BaseURL:       cfg.BaseURL,
		SignSecret:    secret,
	})
	m := metrics.New(nil)
	g.OnChallenge = m.Challenge
	g.SetNotifier(ntfy.NewUserNotifier(st, httpClient, logger, g.ApproveURL, g.DenyURL))
	pool := upstream.NewPool(cfg.Upstreams, st, httpClient, logger)
	proxy := mcpserver.New(mcpserver.Options{
		Pool: pool, Store: st, Gate: g, Metrics: m, Logger: logger,
		AuditEnabled: cfg.Audit.Enabled, LogResponses: cfg.Audit.LogResponses,
	})
	srv, err := server.New(ctx, cfg, st, g, proxy, m, secret, logger)
	if err != nil {
		return err
	}
	app := newHTTPServer(cfg.ListenAddr, srv.Handler())
	ops := newHTTPServer(cfg.OpsListenAddr, srv.OpsHandler())
	logger.Info("starting", "addr", cfg.ListenAddr, "ops_addr", cfg.OpsListenAddr, "base_url", cfg.BaseURL)
	return serveUntilDone(ctx, logger, app, ops)
}

// newHTTPServer bounds how long a client may take to send a request and keep
// an idle connection. No WriteTimeout: it would cut streamed MCP responses.
func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}

// serveUntilDone runs the servers until ctx ends or one of them fails, then
// shuts all of them down.
func serveUntilDone(ctx context.Context, logger *slog.Logger, srvs ...*http.Server) error {
	errCh := make(chan error, len(srvs))
	for _, s := range srvs {
		go func() {
			logger.Info("listening", "addr", s.Addr)
			errCh <- s.ListenAndServe()
		}()
	}
	var errs []error
	pending := len(srvs)
	select {
	case <-ctx.Done():
	case err := <-errCh:
		pending--
		errs = append(errs, err)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range srvs {
		errs = append(errs, s.Shutdown(shutdownCtx))
	}
	for range pending {
		errs = append(errs, <-errCh)
	}
	for i, err := range errs {
		if errors.Is(err, http.ErrServerClosed) {
			errs[i] = nil
		}
	}
	return errors.Join(errs...)
}
