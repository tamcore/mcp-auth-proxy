package webui

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/tamcore/mcp-auth-proxy/internal/config"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
	view "github.com/tamcore/mcp-auth-proxy/internal/ui"
)

// WebUI is the login + portal handler set.
type WebUI struct {
	store      *store.Store
	cfg        *config.Config
	sessions   *Sessions
	pages      *view.Renderer
	approvals  Approvals
	links      *pendingLinks
	webauthn   *webauthn.WebAuthn
	ceremonies *ceremonies
	logins     *loginLimiter
	logger     *slog.Logger
}

// New builds the web UI.
func New(st *store.Store, cfg *config.Config, signSecret []byte, pages *view.Renderer,
	approvals Approvals, logger *slog.Logger) *WebUI {
	if logger == nil {
		logger = slog.Default()
	}
	wa, err := newWebAuthn(cfg.BaseURL)
	if err != nil {
		logger.Warn("passkeys disabled", "error", err)
	}
	secure := strings.HasPrefix(cfg.BaseURL, "https://")
	sessions := NewSessions(signSecret, nil)
	sessions.secure = secure
	return &WebUI{
		webauthn:   wa,
		ceremonies: &ceremonies{m: map[string]ceremony{}, secure: secure},
		logins:     newLoginLimiter(nil),
		store:      st,
		cfg:        cfg,
		sessions:   sessions,
		pages:      pages,
		approvals:  approvals,
		links:      &pendingLinks{m: map[string]pendingLink{}},
		logger:     logger,
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
	mux.HandleFunc("POST /portal/key/upstreams", ui.handleKeyUpstreams)
	mux.HandleFunc("POST /portal/key/delete", ui.handleDeleteKey)
	mux.HandleFunc("POST /portal/key/end-session", ui.handleEndKeySession)
	mux.HandleFunc("POST /portal/upstream", ui.handleAddUpstream)
	mux.HandleFunc("POST /portal/upstream/delete", ui.handleDeleteUpstream)
	mux.HandleFunc("GET /portal/audit", ui.handleAudit)
	mux.HandleFunc("GET /invite/{token}", ui.handleInvitePage)
	mux.HandleFunc("POST /invite/{token}", ui.handleInviteSet)
	mux.HandleFunc("GET /admin", ui.handleAdmin)
	mux.HandleFunc("POST /admin/disable", ui.handleAdminDisable)
	mux.HandleFunc("POST /admin/invite", ui.handleAdminInvite)
	mux.HandleFunc("POST /portal/upstream/link", ui.handleUpstreamLink)
	mux.HandleFunc("GET /portal/upstream/callback", ui.handleUpstreamCallback)
	mux.HandleFunc("POST /portal/upstream/unlink", ui.handleUpstreamUnlink)
	mux.HandleFunc("GET /portal/upstream/tools", ui.handleUpstreamTools)
	mux.HandleFunc("POST /portal/notify", ui.handleNotifySave)
	mux.HandleFunc("POST /portal/notify/delete", ui.handleNotifyDelete)
	mux.HandleFunc("GET /portal/pending", ui.handlePendingIDs)
	mux.HandleFunc("GET /settings", ui.handleSettings)
	mux.HandleFunc("POST /settings/password", ui.handlePasswordChange)
	mux.HandleFunc("POST /settings/passkeys/begin", ui.handlePasskeyBegin)
	mux.HandleFunc("POST /settings/passkeys/finish", ui.handlePasskeyFinish)
	mux.HandleFunc("POST /settings/passkeys/delete", ui.handlePasskeyDelete)
	mux.HandleFunc("POST /login/passkey/begin", ui.handleLoginPasskeyBegin)
	mux.HandleFunc("POST /login/passkey/finish", ui.handleLoginPasskeyFinish)
}

// Sessions exposes the session verifier for the OAuth authorize gate.
func (ui *WebUI) Sessions() *Sessions { return ui.sessions }

// Store exposes the store for the server package.
func (ui *WebUI) Store() *store.Store { return ui.store }
