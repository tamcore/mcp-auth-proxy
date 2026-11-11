package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
	"github.com/tamcore/mcp-auth-proxy/internal/upstream"
)

const (
	toolsTimeout  = 20 * time.Second
	errorField    = "error"
	nameField     = "name"
	upstreamField = "upstream"
)

type toolInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// userUpstream builds a fresh instance of the named upstream as the user sees
// it: their own servers win, global OAuth upstreams run with their token.
func (ui *WebUI) userUpstream(ctx context.Context, user *store.User, name string) (*upstream.Upstream, bool) {
	for _, own := range ui.ownUpstreamsCtx(ctx, user.ID) {
		if own.Name == name {
			return upstream.NewFromConfig(own.Config(), ui.store, nil, ui.logger), true
		}
	}
	for _, c := range ui.allowedUpstreams(user.Username) {
		if c.Name == name {
			return upstream.NewFromConfig(c, ui.store, nil, ui.logger).WithOwner(user.ID), true
		}
	}
	return nil, false
}

// handleUpstreamTools returns the tools an upstream exposes to this user.
func (ui *WebUI) handleUpstreamTools(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	name := r.URL.Query().Get(nameField)
	up, ok := ui.userUpstream(r.Context(), user, name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{errorField: "unknown server"})
		return
	}
	defer func() { _ = up.Close() }()
	if up.OAuth() {
		if _, err := ui.store.GetUpstreamToken(r.Context(), name, user.ID); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{errorField: name + " is not linked for your account."})
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), toolsTimeout)
	defer cancel()
	tools, err := up.Tools(ctx)
	if err != nil {
		ui.logger.Warn("list upstream tools", "upstream", name, "user", user.Username, "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{errorField: "Could not reach " + name + "."})
		return
	}
	out := make([]toolInfo, 0, len(tools))
	for _, t := range tools {
		out = append(out, toolInfo{Name: t.Name, Description: t.Description})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tools": out})
}

// handleUpstreamUnlink deletes the user's own token for an OAuth upstream.
func (ui *WebUI) handleUpstreamUnlink(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	_ = r.ParseForm()
	c, ok := ui.oauthUpstream(r.PostForm.Get(nameField), user.Username)
	if !ok {
		http.Error(w, "unknown upstream or no oauth configured", http.StatusNotFound)
		return
	}
	if err := ui.store.DeleteUpstreamToken(r.Context(), c.Name, user.ID); err != nil {
		ui.logger.Error("unlink upstream", "upstream", c.Name, "error", err)
		http.Error(w, "could not unlink", http.StatusInternalServerError)
		return
	}
	ui.logger.Info("upstream unlinked", "upstream", c.Name, "user", user.Username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
