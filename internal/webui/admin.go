package webui

import (
	"net/http"
	"strings"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
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
	users, err := ui.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, "could not list users", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page("admin", adminBody(admin, users, ""))))
}

func (ui *WebUI) handleAdminDisable(w http.ResponseWriter, r *http.Request) {
	if _, ok := ui.requireAdmin(w, r); !ok {
		return
	}
	_ = r.ParseForm()
	id := r.PostForm.Get("id")
	disabled := r.PostForm.Get("disabled") == "1"
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
	users, _ := ui.store.ListUsers(r.Context())
	link := strings.TrimRight(ui.cfg.BaseURL, "/") + "/invite/" + token
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page("admin", adminBody(admin, users, link))))
}

func adminBody(admin *store.User, users []*store.User, newInvite string) string {
	var b strings.Builder
	b.WriteString(`<h1>Admin</h1>
<div class="card row"><span>Logged in as <strong>` + esc(admin.Username) + `</strong> (admin)</span>
<a href="/">back to portal</a></div>`)
	if newInvite != "" {
		b.WriteString(`<div class="card"><strong>Invite link — show it once and hand it over:</strong><br>
<code>` + esc(newInvite) + `</code><br><span class="muted">single-use, expires in 7 days</span></div>`)
	}
	b.WriteString(`<div class="card"><h2>Users</h2>
<table><tr><th>user</th><th>role</th><th>state</th><th>actions</th></tr>`)
	for _, u := range users {
		role := "user"
		if u.Admin {
			role = "admin"
		}
		state := "active"
		if u.Disabled {
			state = "disabled"
		}
		b.WriteString("<tr><td>" + esc(u.Username) + "</td><td>" + role + "</td><td>" + state + "</td><td>")
		dis := "disable"
		val := "1"
		if u.Disabled {
			dis = "enable"
			val = "0"
		}
		b.WriteString(`<form class="inline" method="post" action="/admin/disable">` +
			`<input type="hidden" name="id" value="` + esc(u.ID) + `">` +
			`<input type="hidden" name="disabled" value="` + val + `">` +
			`<button class="ghost">` + dis + `</button></form> `)
		b.WriteString(`<form class="inline" method="post" action="/admin/invite">` +
			`<input type="hidden" name="id" value="` + esc(u.ID) + `">` +
			`<button class="ghost">new invite link</button></form>`)
		b.WriteString("</td></tr>")
	}
	b.WriteString(`</table>
<p class="muted">Admins are toggled only in the config file (admins list). A disabled user
cannot log in and their API keys stop working immediately.</p></div>`)
	return b.String()
}
