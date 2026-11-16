package webui

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	minKeyTTL = time.Minute
	maxKeyTTL = 7 * 24 * time.Hour
)

var errKeyTTL = errors.New("session TTL must be a duration between 1m and 168h, e.g. 4h or 90m")

// parseKeyTTL turns the optional form value into ttl_seconds; 0 follows session_ttl.
func parseKeyTTL(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < minKeyTTL || d > maxKeyTTL {
		return 0, errKeyTTL
	}
	return int64(d / time.Second), nil
}

// formatTTL renders a duration without zero minute/second tails (8h, 1h30m).
func formatTTL(d time.Duration) string {
	s := d.String()
	s = strings.TrimSuffix(s, "0s")
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// handleKeyTTL sets or clears the session TTL of one of the user's keys.
func (ui *WebUI) handleKeyTTL(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable form", http.StatusBadRequest)
		return
	}
	key, err := ui.store.KeyByID(r.Context(), r.PostForm.Get("id"))
	if err != nil || key.UserID == nil || *key.UserID != user.ID || key.Revoked() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	ttl, err := parseKeyTTL(r.PostForm.Get("ttl"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := ui.store.UpdateKeyTTL(r.Context(), key.ID, user.ID, ttl); err != nil {
		ui.logger.Error("update key ttl", "key", key.ID, "error", err)
		http.Error(w, "could not update key", http.StatusInternalServerError)
		return
	}
	ui.logger.Info("key session ttl updated", "key", key.ID, "user", user.Username, "ttl_seconds", ttl)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
