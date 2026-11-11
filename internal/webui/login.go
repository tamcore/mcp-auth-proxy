package webui

import (
	"net/http"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page("mcp-auth-proxy login", loginBody(next, ""))))
}

func (ui *WebUI) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable form", http.StatusBadRequest)
		return
	}
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	user, err := ui.store.UserByName(r.Context(), username)
	if err != nil || user.Disabled || !store.CheckPassword(user.PasswordHash, password) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(page("mcp-auth-proxy login", loginBody(r.PostForm.Get("next"),
			`<p class="err">Wrong username or password.</p>`))))
		return
	}
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

func loginBody(next, errMsg string) string {
	return `<h1>mcp-auth-proxy</h1>
<div class="card" style="max-width:22rem"><form method="post" action="/login">
<input type="hidden" name="next" value="` + esc(next) + `">
<label>Username <input type="text" name="username" required autocomplete="username"></label>
<label>Password <input type="password" name="password" required autocomplete="current-password"></label>
` + errMsg + `<button type="submit">Log in</button></form></div>`
}
