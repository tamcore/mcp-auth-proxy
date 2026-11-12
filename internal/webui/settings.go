package webui

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
	view "github.com/tamcore/mcp-auth-proxy/internal/ui"
)

const minPasswordLen = 8

func (ui *WebUI) handleSettings(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	ui.renderSettings(w, r, user, http.StatusOK, "", r.URL.Query().Get("done"))
}

// settingsFlash maps a ?done= value to its banner; unknown values show none.
func settingsFlash(done string) string {
	return map[string]string{
		"password":       "Password changed. Your other browser sessions are logged out.",
		"passkey":        "Passkey added.",
		"passkey-delete": "Passkey removed.",
		"notify":         "Push target saved. A test push was sent.",
	}[done]
}

// renderSettings shows password, passkeys and push target with an optional
// error or success banner.
func (ui *WebUI) renderSettings(w http.ResponseWriter, r *http.Request, user *store.User,
	status int, errMsg, done string) {
	d := view.SettingsData{Error: errMsg, Flash: settingsFlash(done), PasskeysEnabled: ui.webauthn != nil}
	n, err := ui.store.GetUserNotify(r.Context(), user.ID)
	switch {
	case err == nil:
		d.NotifyURL, d.NotifyTopic = n.URL, n.Topic
	case !errors.Is(err, store.ErrNotFound):
		ui.logger.Error("load push target", "user", user.Username, "error", err)
	}
	pks, err := ui.store.ListPasskeys(r.Context(), user.ID)
	if err != nil {
		ui.logger.Error("list passkeys", "user", user.Username, "error", err)
	}
	for _, p := range pks {
		d.Passkeys = append(d.Passkeys, view.PasskeyView{
			ID: base64.RawURLEncoding.EncodeToString(p.ID), Name: p.Name, Created: p.CreatedAt, LastUsed: p.LastUsedAt,
		})
	}
	ui.pages.Render(w, status, "settings", page("Settings", user, d))
}

// handlePasswordChange sets a new password after checking the current one and
// logs out every other browser session of the user.
func (ui *WebUI) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable form", http.StatusBadRequest)
		return
	}
	pw := r.PostForm.Get("password")
	switch {
	case !store.CheckPassword(user.PasswordHash, r.PostForm.Get("current")):
		ui.logger.Warn("password change: wrong current password", "user", user.Username, "remote", r.RemoteAddr)
		ui.renderSettings(w, r, user, http.StatusBadRequest, "The current password is wrong.", "")
		return
	case len(pw) < minPasswordLen:
		ui.renderSettings(w, r, user, http.StatusBadRequest, "The new password must have at least 8 characters.", "")
		return
	case pw != r.PostForm.Get("password2"):
		ui.renderSettings(w, r, user, http.StatusBadRequest, "The new passwords do not match.", "")
		return
	}
	// Cookies carry whole seconds: the cutoff is the next second, and this
	// browser's new cookie is issued exactly at it.
	cutoff := time.Unix(time.Now().Unix()+1, 0).UTC()
	hash, err := store.HashPassword(pw)
	if err == nil {
		err = ui.store.SetUserPassword(r.Context(), user.ID, hash)
	}
	if err == nil {
		err = ui.store.SetSessionsSince(r.Context(), user.ID, cutoff)
	}
	if err != nil {
		ui.logger.Error("change password", "user", user.Username, "error", err)
		http.Error(w, "could not change password", http.StatusInternalServerError)
		return
	}
	ui.logger.Info("password changed", "user", user.Username)
	ui.sessions.Set(w, ui.sessions.issueAt(user.Username, cutoff))
	http.Redirect(w, r, "/settings?done=password", http.StatusSeeOther)
}
