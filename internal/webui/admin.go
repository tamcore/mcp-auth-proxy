package webui

import (
	"net/http"
	"strings"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
	view "github.com/tamcore/mcp-auth-proxy/internal/ui"
)

// requireAdmin redirects non-admins to the portal.
func (ui *WebUI) requireAdmin(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return nil, false
	}
	if !user.Admin {
		http.Redirect(w, r, "/", http.StatusFound)
		return nil, false
	}
	return user, true
}

func (ui *WebUI) handleAdmin(w http.ResponseWriter, r *http.Request) {
	admin, ok := ui.requireAdmin(w, r)
	if !ok {
		return
	}
	ui.renderAdmin(w, r, admin, http.StatusOK, "", "")
}

func (ui *WebUI) handleAdminDisable(w http.ResponseWriter, r *http.Request) {
	admin, ok := ui.requireAdmin(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	id := r.PostForm.Get("id")
	disabled := r.PostForm.Get("disabled") == "1"
	if disabled && id == admin.ID {
		http.Error(w, "you cannot disable yourself", http.StatusBadRequest)
		return
	}
	if err := ui.store.SetUserDisabled(r.Context(), id, disabled); err != nil {
		http.Error(w, "could not update user", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// handleAdminInvite mints a fresh invite link for a user and shows it once.
func (ui *WebUI) handleAdminInvite(w http.ResponseWriter, r *http.Request) {
	admin, ok := ui.requireAdmin(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	user, err := ui.store.UserByID(r.Context(), r.PostForm.Get("id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	token, err := ui.store.CreateInvite(r.Context(), user.ID, time.Now().UTC())
	if err != nil {
		http.Error(w, "could not create invite", http.StatusInternalServerError)
		return
	}
	link := strings.TrimRight(ui.cfg.BaseURL, "/") + "/invite/" + token
	ui.renderAdmin(w, r, admin, http.StatusOK, link, "")
}

// renderAdmin shows users and OAuth upstreams. invite and errMsg are one-off
// banners.
func (ui *WebUI) renderAdmin(w http.ResponseWriter, r *http.Request, admin *store.User,
	status int, invite, errMsg string) {
	users, err := ui.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, "could not list users", http.StatusInternalServerError)
		return
	}
	data := view.AdminData{Users: users, Invite: invite, Error: errMsg}
	ui.pages.Render(w, status, "admin", page("Admin", admin, data))
}
