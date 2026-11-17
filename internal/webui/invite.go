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
	if len(pw) < minPasswordLen {
		ui.renderInvite(w, http.StatusBadRequest, token, "Password must be at least 8 characters.")
		return
	}
	if pw != pw2 {
		ui.renderInvite(w, http.StatusBadRequest, token, "Passwords do not match.")
		return
	}
	if len(pw) > maxPasswordBytes {
		ui.renderInvite(w, http.StatusBadRequest, token, "Password must have at most 72 bytes.")
		return
	}
	// Check the token before bcrypt: this endpoint is unauthenticated.
	if !ui.validInvite(r, token) {
		http.Error(w, "invite link is invalid, expired, or already used", http.StatusNotFound)
		return
	}
	hash, busy, err := ui.hashPassword(r.Context(), pw)
	if busy {
		http.Error(w, "busy, try again", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		http.Error(w, "could not set password", http.StatusInternalServerError)
		return
	}
	// A reset logs out older sessions; this browser's cookie is issued at the cutoff.
	cutoff := time.Unix(time.Now().Unix()+1, 0).UTC()
	user, err := ui.store.ConsumeInvite(r.Context(), token, hash, time.Now().UTC(), cutoff)
	if err != nil {
		http.Error(w, "invite link is invalid, expired, or already used", http.StatusNotFound)
		return
	}
	ui.sessions.Set(w, ui.sessions.issueAt(user.Username, cutoff))
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
