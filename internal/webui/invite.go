package webui

import (
	"net/http"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
	view "github.com/tamcore/mcp-auth-proxy/internal/ui"
)

// handleInvitePage serves the set-your-password form for a valid invite token.
func (ui *WebUI) handleInvitePage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !ui.validInvite(r, token) {
		http.Error(w, "invite link is invalid, expired, or already used", http.StatusNotFound)
		return
	}
	ui.renderInvite(w, http.StatusOK, token, "")
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
		ui.renderInvite(w, http.StatusBadRequest, token, "Password must be at least 8 characters.")
		return
	}
	if pw != pw2 {
		ui.renderInvite(w, http.StatusBadRequest, token, "Passwords do not match.")
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

func (ui *WebUI) renderInvite(w http.ResponseWriter, status int, token, errMsg string) {
	ui.pages.Render(w, status, "invite", page("Set your password", nil, view.InviteData{Token: token, Error: errMsg}))
}
