package webui

import (
	"log/slog"
	"net/http"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

// WebUI is the login + portal handler set.
type WebUI struct {
	store    *store.Store
	cfg      *config.Config
	sessions *Sessions
	logger   *slog.Logger
}

// New builds the web UI.
func New(st *store.Store, cfg *config.Config, signSecret []byte, logger *slog.Logger) *WebUI {
	return &WebUI{
		store:    st,
		cfg:      cfg,
		sessions: NewSessions(signSecret, nil),
		logger:   logger,
	}
}

// Register wires the web UI routes onto the mux.
func (ui *WebUI) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", ui.handleLoginPage)
	mux.HandleFunc("POST /login", ui.handleLogin)
	mux.HandleFunc("POST /logout", ui.handleLogout)
	mux.HandleFunc("GET /{$}", ui.handlePortal)
	mux.HandleFunc("POST /portal/key", ui.handleCreateKey)
	mux.HandleFunc("POST /portal/key/revoke", ui.handleRevokeKey)
	mux.HandleFunc("POST /portal/upstream", ui.handleAddUpstream)
	mux.HandleFunc("POST /portal/upstream/delete", ui.handleDeleteUpstream)
	mux.HandleFunc("GET /portal/audit", ui.handleAudit)
	mux.HandleFunc("GET /invite/{token}", ui.handleInvitePage)
	mux.HandleFunc("POST /invite/{token}", ui.handleInviteSet)
	mux.HandleFunc("GET /admin", ui.handleAdmin)
	mux.HandleFunc("POST /admin/disable", ui.handleAdminDisable)
	mux.HandleFunc("POST /admin/invite", ui.handleAdminInvite)
}

// Sessions exposes the session verifier for the OAuth authorize gate.
func (ui *WebUI) Sessions() *Sessions { return ui.sessions }

// Store exposes the store for the server package.
func (ui *WebUI) Store() *store.Store { return ui.store }
