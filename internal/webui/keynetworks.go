package webui

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"unicode"

	"github.com/tamcore/mcp-auth-proxy/internal/clientip"
)

const maxKeyNetworks = 32

// parseNetworks reads a comma- or space-separated list of CIDRs or addresses.
func parseNetworks(s string) ([]netip.Prefix, error) {
	entries := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(entries) > maxKeyNetworks {
		return nil, fmt.Errorf("at most %d networks per list", maxKeyNetworks)
	}
	return clientip.ParsePrefixes(entries)
}

func formatNetworks(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}

// handleKeyNetworks sets the allowed and trusted networks of one of the user's keys.
func (ui *WebUI) handleKeyNetworks(w http.ResponseWriter, r *http.Request) {
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
	allowed, err := parseNetworks(r.PostForm.Get("allowed"))
	if err != nil {
		http.Error(w, "allowed networks: "+err.Error(), http.StatusBadRequest)
		return
	}
	trusted, err := parseNetworks(r.PostForm.Get("trusted"))
	if err != nil {
		http.Error(w, "pre-authorized networks: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := ui.store.UpdateKeyNetworks(r.Context(), key.ID, user.ID, allowed, trusted); err != nil {
		ui.logger.Error("update key networks", "key", key.ID, "error", err)
		http.Error(w, "could not update key", http.StatusInternalServerError)
		return
	}
	ui.logger.Info("key networks updated", "key", key.ID, "user", user.Username,
		"allowed", formatNetworks(allowed), "trusted", formatNetworks(trusted))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
