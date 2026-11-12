package webui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/identity"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
	view "github.com/tamcore/mcp-auth-proxy/internal/ui"
)

// allowedUpstreams returns the global config upstreams the user may use.
func (ui *WebUI) allowedUpstreams(username string) []config.UpstreamConfig {
	var out []config.UpstreamConfig
	for _, u := range ui.cfg.Upstreams {
		if u.Allows(username) {
			out = append(out, u)
		}
	}
	return out
}

// ownUpstreamNames returns the names of the user's database upstreams.
func (ui *WebUI) ownUpstreams(r *http.Request, userID string) []*store.UserUpstream {
	ups, err := ui.store.ListUserUpstreams(r.Context(), userID)
	if err != nil {
		ui.logger.Error("list user upstreams", "error", err)
		return nil
	}
	return ups
}

func (ui *WebUI) ownKeys(r *http.Request, userID string) []*store.Key {
	all, err := ui.store.ListKeys(r.Context())
	if err != nil {
		return nil
	}
	var out []*store.Key
	for _, k := range all {
		if k.UserID != nil && *k.UserID == userID {
			out = append(out, k)
		}
	}
	return out
}

func (ui *WebUI) handlePortal(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	ui.renderPortal(w, r, user, "")
}

func (ui *WebUI) renderPortal(w http.ResponseWriter, r *http.Request, user *store.User, newToken string) {
	ui.renderPortalStatus(w, r, user, http.StatusOK, newToken, "")
}

// renderPortalStatus renders the portal with an HTTP status and an optional
// one-off error banner.
func (ui *WebUI) renderPortalStatus(w http.ResponseWriter, r *http.Request, user *store.User,
	status int, newToken, errMsg string) {
	globals := ui.allowedUpstreams(user.Username)
	linked := map[string]bool{}
	for _, u := range globals {
		if u.OAuth != nil {
			_, err := ui.store.GetUpstreamToken(r.Context(), u.Name, user.ID)
			linked[u.Name] = err == nil
		}
	}
	data := portalData(globals, ui.ownUpstreams(r, user.ID), ui.ownKeys(r, user.ID), ui.cfg, newToken, linked)
	data.Error = errMsg
	ui.notifyAndPending(r, user, &data)
	now := time.Now().UTC()
	for i := range data.Keys {
		if sess, err := ui.store.GetSession(r.Context(), data.Keys[i].ID, now); err == nil {
			data.Keys[i].AuthorizedUntil = &sess.ExpiresAt
		}
	}
	ui.pages.Render(w, status, "portal", page("mcp-auth-proxy", user, data))
}

func (ui *WebUI) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable form", http.StatusBadRequest)
		return
	}
	label := strings.TrimSpace(r.PostForm.Get("label"))
	if label == "" {
		label = user.Username + " client"
	}
	names, err := ui.validateChosenUpstreams(r.Context(), user, r.PostForm[upstreamField])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "rng failure", http.StatusInternalServerError)
		return
	}
	token := identity.StaticPrefix + hex.EncodeToString(raw)
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	key := &store.Key{
		ID:         "k_" + hex.EncodeToString(id),
		Kind:       store.KeyKindStatic,
		Label:      label,
		SecretHash: store.HashSecret(token),
		Upstreams:  names,
		TTLSeconds: int64(ui.cfg.SessionTTL / time.Second),
		CreatedAt:  time.Now().UTC(),
		UserID:     &user.ID,
	}
	if err := ui.store.CreateKey(r.Context(), key); err != nil {
		ui.logger.Error("create key", "error", err)
		http.Error(w, "could not create key", http.StatusInternalServerError)
		return
	}
	ui.renderPortal(w, r, user, token)
}

// validateChosenUpstreams checks every chosen name is allowed for the user.
func (ui *WebUI) validateChosenUpstreams(ctx context.Context, user *store.User, chosen []string) ([]string, error) {
	allowed := map[string]bool{}
	for _, u := range ui.allowedUpstreams(user.Username) {
		allowed[u.Name] = true
	}
	for _, u := range ui.ownUpstreamsCtx(ctx, user.ID) {
		allowed[u.Name] = true
	}
	var out []string
	for _, n := range chosen {
		if !allowed[n] {
			return nil, fmt.Errorf("upstream %q is not available to you", n)
		}
		out = append(out, n)
	}
	return out, nil
}

func (ui *WebUI) ownUpstreamsCtx(ctx context.Context, userID string) []*store.UserUpstream {
	ups, err := ui.store.RunnableUserUpstreams(ctx, userID)
	if err != nil {
		return nil
	}
	return ups
}

func (ui *WebUI) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	_ = r.ParseForm()
	id := r.PostForm.Get("id")
	key, err := ui.store.KeyByID(r.Context(), id)
	if err != nil || key.UserID == nil || *key.UserID != user.ID {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_ = ui.store.RevokeKey(r.Context(), id, time.Now().UTC())
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleEndKeySession ends the current authorization of one of the user's
// keys; its next tool call is gated again.
func (ui *WebUI) handleEndKeySession(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	_ = r.ParseForm()
	key, err := ui.store.KeyByID(r.Context(), r.PostForm.Get("id"))
	if err != nil || key.UserID == nil || *key.UserID != user.ID {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := ui.store.DeleteSession(r.Context(), key.ID); err != nil {
		ui.logger.Error("end key session", "key", key.ID, "error", err)
		http.Error(w, "could not end session", http.StatusInternalServerError)
		return
	}
	ui.logger.Info("key session ended", "key", key.ID, "user", user.Username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleDeleteKey removes one of the user's revoked keys; its audit history
// stays.
func (ui *WebUI) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	_ = r.ParseForm()
	id := r.PostForm.Get("id")
	if err := ui.store.DeleteRevokedKey(r.Context(), id, user.ID); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	ui.logger.Info("key removed", "key", id, "user", user.Username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleKeyUpstreams replaces the MCP servers of one of the user's keys.
func (ui *WebUI) handleKeyUpstreams(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable form", http.StatusBadRequest)
		return
	}
	key, err := ui.store.KeyByID(r.Context(), r.PostForm.Get("id"))
	if err != nil || key.UserID == nil || *key.UserID != user.ID || key.Revoked() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	names, err := ui.validateChosenUpstreams(r.Context(), user, r.PostForm[upstreamField])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := ui.store.UpdateKeyUpstreams(r.Context(), key.ID, user.ID, names); err != nil {
		ui.logger.Error("update key upstreams", "key", key.ID, "error", err)
		http.Error(w, "could not update key", http.StatusInternalServerError)
		return
	}
	ui.logger.Info("key upstreams updated", "key", key.ID, "user", user.Username, "upstreams", names)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (ui *WebUI) handleAddUpstream(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.PostForm.Get("name"))
	url := strings.TrimSpace(r.PostForm.Get("url"))
	command := strings.TrimSpace(r.PostForm.Get("command"))
	bearer := strings.TrimSpace(r.PostForm.Get("bearer"))
	if name == "" || (url == "") == (command == "") {
		http.Error(w, "name and exactly one of url/command required", http.StatusBadRequest)
		return
	}
	if command != "" && !user.Admin {
		http.Error(w, "only admins may add stdio command servers", http.StatusForbidden)
		return
	}
	if bearer != "" && url == "" {
		http.Error(w, "a bearer token needs a url", http.StatusBadRequest)
		return
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	up := &store.UserUpstream{
		ID:        "us_" + hex.EncodeToString(id),
		UserID:    user.ID,
		Name:      name,
		URL:       url,
		CreatedAt: time.Now().UTC(),
	}
	if command != "" {
		up.Command = strings.Fields(command)
	}
	if bearer != "" {
		up.Headers = map[string]string{"Authorization": "Bearer " + bearer}
	}
	if url != "" {
		if err := ui.probeMCP(r.Context(), up); err != nil {
			ui.logger.Warn("own upstream is not an MCP server", "user", user.Username, "upstream", name, "error", err)
			http.Error(w, url+" did not answer as an MCP server", http.StatusBadRequest)
			return
		}
	}
	if err := ui.store.CreateUserUpstream(r.Context(), up); err != nil {
		http.Error(w, "could not save upstream (name taken?)", http.StatusBadRequest)
		return
	}
	ui.upstreamsChanged(user.ID)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (ui *WebUI) handleDeleteUpstream(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	_ = r.ParseForm()
	if err := ui.store.DeleteUserUpstream(r.Context(), user.ID, r.PostForm.Get("id")); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	ui.upstreamsChanged(user.ID)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (ui *WebUI) handleAudit(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	entries, err := ui.store.ListAuditForUser(r.Context(), user.ID, 200)
	if err != nil {
		ui.logger.Error("list audit", "error", err)
		http.Error(w, "could not load audit log", http.StatusInternalServerError)
		return
	}
	ui.pages.Render(w, http.StatusOK, "audit", page("audit log", user, view.AuditData{
		Retention: ui.cfg.Audit.Retention.String(),
		Responses: responsesLabel(ui.cfg.Audit),
		Entries:   entries,
	}))
}
