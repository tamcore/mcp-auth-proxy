package webui

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/ntfy"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
	view "github.com/tamcore/mcp-auth-proxy/internal/ui"
)

// Approvals is what the portal needs from the gate to show pending requests.
type Approvals interface {
	PendingCode(id string) (string, bool)
	ApproveURL(id string) string
	DenyURL(id string) string
}

// handleNotifySave validates and stores the user's ntfy push target. Blank
// topic/token keep the stored values, so they never have to be shown again.
func (ui *WebUI) handleNotifySave(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable form", http.StatusBadRequest)
		return
	}
	topic := strings.TrimSpace(r.PostForm.Get("topic"))
	token := strings.TrimSpace(r.PostForm.Get("token"))
	if prev, err := ui.store.GetUserNotify(r.Context(), user.ID); err == nil {
		if topic == "" {
			topic = prev.Topic
		}
		if token == "" {
			token = prev.Token
		}
	}
	base, err := ntfy.Validate(r.Context(), nil, r.PostForm.Get("url"), topic, token)
	if err != nil {
		ui.renderSettings(w, r, user, http.StatusBadRequest, "Push target not saved: "+err.Error(), "")
		return
	}
	n := &store.UserNotify{UserID: user.ID, URL: base, Topic: topic, Token: token}
	if err := ui.store.SaveUserNotify(r.Context(), n); err != nil {
		ui.logger.Error("save push target", "user", user.Username, "error", err)
		http.Error(w, "could not save push target", http.StatusInternalServerError)
		return
	}
	ui.logger.Info("push target saved", "user", user.Username, "url", base)
	http.Redirect(w, r, "/settings?done=notify", http.StatusSeeOther)
}

func (ui *WebUI) handleNotifyDelete(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	if err := ui.store.DeleteUserNotify(r.Context(), user.ID); err != nil {
		http.Error(w, "could not remove push target", http.StatusInternalServerError)
		return
	}
	ui.logger.Info("push target removed", "user", user.Username)
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// handlePendingIDs lets the portal poll for new or resolved requests.
func (ui *WebUI) handlePendingIDs(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	pending, err := ui.store.PendingChallengesForUser(r.Context(), user.ID, time.Now().UTC())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{errorField: "could not list requests"})
		return
	}
	ids := make([]string, 0, len(pending))
	for _, p := range pending {
		ids = append(ids, p.ID)
	}
	writeJSON(w, http.StatusOK, map[string][]string{"ids": ids})
}

// notifyAndPending fills the push target status and the pending requests.
func (ui *WebUI) notifyAndPending(r *http.Request, user *store.User, d *view.PortalData) {
	if _, err := ui.store.GetUserNotify(r.Context(), user.ID); errors.Is(err, store.ErrNotFound) {
		d.NoPushTarget = true
	}
	if ui.approvals == nil {
		return
	}
	pending, err := ui.store.PendingChallengesForUser(r.Context(), user.ID, time.Now().UTC())
	if err != nil {
		ui.logger.Error("list pending requests", "user", user.Username, "error", err)
		return
	}
	for _, p := range pending {
		code, _ := ui.approvals.PendingCode(p.ID)
		d.Pending = append(d.Pending, view.Pending{
			ID: p.ID, Key: p.KeyLabel, Tool: p.ToolName, Expires: p.ExpiresAt, Code: code,
			ApproveURL: ui.approvals.ApproveURL(p.ID), DenyURL: ui.approvals.DenyURL(p.ID),
		})
	}
}
