package webui

import (
	"net/http"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

// handleInvitePage serves the set-your-password form for a valid invite token.
func (ui *WebUI) handleInvitePage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !ui.validInvite(r, token) {
		http.Error(w, "invite link is invalid, expired, or already used", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page("set your password", inviteBody(token, ""))))
}

// handleInviteSet consumes the invite, sets the password, and logs the user in.
func (ui *WebUI) handleInviteSet(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable form", http.StatusBadRequest)
		return
	}
	pw := r.PostForm.Get("password")
	pw2 := r.PostForm.Get("password2")
	if len(pw) < 8 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		msg := `<p class="err">Password must be at least 8 characters.</p>`
		_, _ = w.Write([]byte(page("set your password", inviteBody(token, msg))))
		return
	}
	if pw != pw2 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(page("set your password", inviteBody(token, `<p class="err">Passwords do not match.</p>`))))
		return
	}
	user, err := ui.store.ConsumeInvite(r.Context(), token, time.Now().UTC())
	if err != nil {
		http.Error(w, "invite link is invalid, expired, or already used", http.StatusNotFound)
		return
	}
	hash, err := store.HashPassword(pw)
	if err != nil {
		http.Error(w, "could not set password", http.StatusInternalServerError)
		return
	}
	if err := ui.store.SetUserPassword(r.Context(), user.ID, hash); err != nil {
		http.Error(w, "could not set password", http.StatusInternalServerError)
		return
	}
	Set(w, ui.sessions.Issue(user.Username))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (ui *WebUI) validInvite(r *http.Request, token string) bool {
	// Peek without consuming: a token is valid if a pending, unexpired row exists.
	hash := store.HashSecret(token)
	var expires, used any
	err := ui.store.DB().QueryRowContext(r.Context(),
		`SELECT expires_at, used_at FROM invites WHERE token_hash = ?`, hash).Scan(&expires, &used)
	if err != nil || used != nil {
		return false
	}
	exp, perr := store.ParseTime(expires.(string))
	return perr == nil && time.Now().UTC().Before(exp)
}

func inviteBody(token, msg string) string {
	return `<h1>Set your password</h1>
<div class="card" style="max-width:22rem"><form method="post" action="/invite/` + esc(token) + `">
<label>Password <input type="password" name="password" required minlength="8" autocomplete="new-password"></label>
<label>Repeat <input type="password" name="password2" required minlength="8" autocomplete="new-password"></label>
` + msg + `<button type="submit">Set password and log in</button></form></div>`
}
