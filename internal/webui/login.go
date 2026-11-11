package webui

import (
	"net/http"
	"strings"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
	view "github.com/tamcore/mcp-auth-proxy/internal/ui"
)

func (ui *WebUI) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := ui.sessions.User(r, ui.store); ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/"
	}
	invites, err := ui.store.PendingInvites(r.Context(), time.Now().UTC())
	if err != nil {
		ui.logger.Error("pending invites", "error", err)
		invites = nil
	}
	base := strings.TrimRight(ui.cfg.BaseURL, "/")
	data := view.LoginData{Next: next}
	for _, inv := range invites {
		data.Invites = append(data.Invites, view.Invite{Username: inv.Username, Link: base + "/invite/" + inv.Token})
	}
	ui.pages.Render(w, http.StatusOK, "login", page("Log in", nil, data))
}

func (ui *WebUI) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable form", http.StatusBadRequest)
		return
	}
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	user, err := ui.store.UserByName(r.Context(), username)
	if err == nil && user.Disabled {
		ui.logger.Warn("login refused: user disabled", "user", username, "remote", r.RemoteAddr)
	} else if err != nil || !store.CheckPassword(user.PasswordHash, password) {
		ui.logger.Warn("failed login", "user", username, "remote", r.RemoteAddr)
	}
	if err != nil || user.Disabled || !store.CheckPassword(user.PasswordHash, password) {
		ui.pages.Render(w, http.StatusUnauthorized, "login", page("Log in", nil, view.LoginData{
			Next:  r.PostForm.Get("next"),
			Error: "Wrong username or password.",
		}))
		return
	}
	ui.logger.Info("login ok", "user", user.Username, "remote", r.RemoteAddr)
	Set(w, ui.sessions.Issue(user.Username))
	next := r.PostForm.Get("next")
	if next == "" {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func (ui *WebUI) handleLogout(w http.ResponseWriter, r *http.Request) {
	Clear(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}
