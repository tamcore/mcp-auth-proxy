package webui

import (
	"net/http"
	"strings"
	"time"

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
	invites, err := ui.store.PendingInvites(r.Context(), time.Now().UTC())
	if err != nil {
		ui.logger.Error("pending invites", "error", err)
		invites = nil
	}
	base := strings.TrimRight(ui.cfg.BaseURL, "/")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page("mcp-auth-proxy login", loginBody(next, "", base, invites))))
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
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(page("mcp-auth-proxy login", loginBody(r.PostForm.Get("next"),
			`<p class="err">Wrong username or password.</p>`, "", nil))))
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

func loginBody(next, errMsg, base string, invites []store.PendingInvite) string {
	var b strings.Builder
	b.WriteString("<h1>mcp-auth-proxy</h1>\n")
	b.WriteString(`<div class="card" style="max-width:22rem"><form method="post" action="/login">` + "\n")
	b.WriteString(`<input type="hidden" name="next" value="` + esc(next) + `">` + "\n")
	b.WriteString(`<label>Username <input type="text" name="username" required autocomplete="username"></label>` + "\n")
	b.WriteString(`<label>Password <input type="password" name="password" ` +
		`required autocomplete="current-password"></label>` + "\n")
	b.WriteString(errMsg + `<button type="submit">Log in</button></form></div>` + "\n")
	if len(invites) > 0 {
		b.WriteString(`<div class="card"><h2>Pending invites</h2>` + "\n")
		b.WriteString(`<p class="muted">Users who have not set a password yet. ` +
			`The link logs them in and lets them choose one.</p><ul>` + "\n")
		for _, inv := range invites {
			link := base + "/invite/" + inv.Token
			b.WriteString(`<li><strong>` + esc(inv.Username) + `</strong> — ` +
				`<a href="` + esc(link) + `">set password</a> <code>` + esc(link) + `</code></li>` + "\n")
		}
		b.WriteString(`</ul></div>` + "\n")
	}
	return b.String()
}
