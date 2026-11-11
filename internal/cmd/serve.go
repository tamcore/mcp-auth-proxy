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
	logger := newLogger()
	st, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
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
	gcAudit(st, cfg, logger)
	httpClient := &http.Client{Timeout: 30 * time.Second}
	var pub ntfy.Publisher
	if cfg.Ntfy.Enabled {
		pub = ntfy.NewHTTPPublisher(cfg.Ntfy.URL, httpClient)
	} else {
		pub = ntfy.NewLogPublisher(logger)
	}
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
	g.SetNotifier(ntfy.NewNotifier(pub, cfg.Ntfy.Topic, g.ApproveURL, g.DenyURL))
	pool := upstream.NewPool(cfg.Upstreams, st, httpClient, logger)
	proxy := mcpserver.New(mcpserver.Options{
		Pool: pool, Store: st, Gate: g, Metrics: m, Logger: logger,
		AuditEnabled: cfg.Audit.Enabled, LogResponses: cfg.Audit.LogResponses,
	})
	srv, err := server.New(ctx, cfg, st, g, proxy, m, secret, logger)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{Addr: cfg.ListenAddr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.ListenAddr, "base_url", cfg.BaseURL)
		errCh <- httpSrv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr := httpSrv.Shutdown(shutdownCtx)
		serveErr := <-errCh
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		return errors.Join(shutdownErr, serveErr)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil // clean shutdown via signal
		}
		return err
	}
}
