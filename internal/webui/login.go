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
	if !ui.logins.allowed(username) {
		ui.logger.Warn("login refused: too many failures", "user", username, "remote", r.RemoteAddr)
		ui.loginFailed(w, r, http.StatusTooManyRequests, "Too many failed logins. Try again in a minute.")
		return
	}
	user, err := ui.store.UserByName(r.Context(), username)
	hash := ""
	if err == nil {
		hash = user.PasswordHash
	}
	ok := store.CheckPassword(hash, password)
	if err == nil && user.Disabled {
		ui.logger.Warn("login refused: user disabled", "user", username, "remote", r.RemoteAddr)
	} else if !ok {
		ui.logger.Warn("failed login", "user", username, "remote", r.RemoteAddr)
	}
	if !ok || user.Disabled {
		if err == nil {
			ui.logins.fail(username)
		}
		ui.loginFailed(w, r, http.StatusUnauthorized, "Wrong username or password.")
		return
	}
	ui.logins.reset(username)
	ui.logger.Info("login ok", "user", user.Username, "remote", r.RemoteAddr)
	ui.sessions.Set(w, ui.sessions.IssueFor(user))
	http.Redirect(w, r, safeNext(r.PostForm.Get("next")), http.StatusFound)
}

func (ui *WebUI) loginFailed(w http.ResponseWriter, r *http.Request, status int, msg string) {
	ui.pages.Render(w, status, "login", page("Log in", nil, view.LoginData{
		Next:  safeNext(r.PostForm.Get("next")),
		Error: msg,
	}))
}

// handleLogout ends every web session of the user: the cookie is stateless, so
// a copied cookie would otherwise stay valid until it expires.
func (ui *WebUI) handleLogout(w http.ResponseWriter, r *http.Request) {
	if user, ok := ui.sessions.User(r, ui.store); ok {
		cutoff := time.Unix(ui.sessions.now().Unix()+1, 0).UTC() // cookies carry whole seconds
		if err := ui.store.SetSessionsSince(r.Context(), user.ID, cutoff); err != nil {
			ui.logger.Error("logout: end sessions", "user", user.Username, "error", err)
		}
	}
	ui.sessions.Clear(w)
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
