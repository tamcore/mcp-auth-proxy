package webui

import (
	"net/http"
	"strings"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
	view "github.com/tamcore/mcp-auth-proxy/internal/ui"
)

func (ui *WebUI) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := ui.sessions.User(r, ui.store); ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	next := safeNext(r.URL.Query().Get("next"))
	ui.pages.Render(w, http.StatusOK, "login", page("Log in", nil, view.LoginData{Next: next}))
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
			Next:  safeNext(r.PostForm.Get("next")),
			Error: "Wrong username or password.",
		}))
		return
	}
	ui.logger.Info("login ok", "user", user.Username, "remote", r.RemoteAddr)
	Set(w, ui.sessions.IssueFor(user))
	http.Redirect(w, r, safeNext(r.PostForm.Get("next")), http.StatusFound)
}

func (ui *WebUI) handleLogout(w http.ResponseWriter, r *http.Request) {
	Clear(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// safeNext keeps post-login redirects on this site: only absolute paths,
// never scheme-relative ("//host") or backslash tricks.
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	return next
}
