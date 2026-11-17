package webui

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
	view "github.com/tamcore/mcp-auth-proxy/internal/ui"
	"github.com/tamcore/mcp-auth-proxy/internal/webpush"
)

// Devices sends Web Push messages; nil disables device subscriptions.
type Devices interface {
	PublicKey() string
	Send(ctx context.Context, sub *store.PushSubscription, p webpush.Payload) error
}

const (
	maxSubscribeBytes = 4096
	maxEndpointLen    = 1024
	maxDeviceLabel    = 80
	p256PointLen      = 65
	pushAuthLen       = 16
)

type subscribeRequest struct {
	Endpoint string `json:"endpoint"`
	Label    string `json:"label"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
}

// validate checks the browser's PushSubscription shape; the test push then
// proves the endpoint is a push service.
func (s subscribeRequest) validate() error {
	u, err := url.Parse(s.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(s.Endpoint) > maxEndpointLen {
		return errors.New("the push endpoint must be an https URL")
	}
	p, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s.Keys.P256dh, "="))
	if err != nil || len(p) != p256PointLen || p[0] != 4 {
		return errors.New("invalid p256dh key")
	}
	a, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s.Keys.Auth, "="))
	if err != nil || len(a) != pushAuthLen {
		return errors.New("invalid auth secret")
	}
	return nil
}

func deviceLabel(raw string) string {
	l := strings.TrimSpace(raw)
	if l == "" || !utf8.ValidString(l) {
		return "Browser"
	}
	if r := []rune(l); len(r) > maxDeviceLabel {
		l = string(r[:maxDeviceLabel])
	}
	return l
}

// handlePushSubscribe stores this browser's subscription once a test push
// through it succeeds.
func (ui *WebUI) handlePushSubscribe(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	if ui.Devices == nil {
		http.NotFound(w, r)
		return
	}
	var req subscribeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSubscribeBytes)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{errorField: "unreadable subscription"})
		return
	}
	if err := req.validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{errorField: err.Error()})
		return
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	sub := &store.PushSubscription{ID: "ps_" + hex.EncodeToString(id), UserID: user.ID, Endpoint: req.Endpoint,
		P256dh: req.Keys.P256dh, Auth: req.Keys.Auth, Label: deviceLabel(req.Label), CreatedAt: time.Now().UTC()}
	test := webpush.Payload{Title: "mcp-auth-proxy", Body: "Push notifications are on for this device."}
	if err := ui.Devices.Send(r.Context(), sub, test); err != nil {
		ui.logger.Warn("push subscription rejected: test push failed", "user", user.Username, "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{errorField: "test push failed: " + err.Error()})
		return
	}
	if err := ui.store.SavePushSubscription(r.Context(), sub); err != nil {
		ui.logger.Error("save push subscription", "user", user.Username, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{errorField: "could not save the device"})
		return
	}
	ui.logger.Info("push device added", "user", user.Username, "subscription", sub.ID, "label", sub.Label)
	writeJSON(w, http.StatusOK, map[string]string{"id": sub.ID})
}

// pushDevices fills the Web Push part of the settings page.
func (ui *WebUI) pushDevices(r *http.Request, user *store.User, d *view.SettingsData) {
	if ui.Devices == nil {
		return
	}
	d.PushKey = ui.Devices.PublicKey()
	subs, err := ui.store.ListPushSubscriptions(r.Context(), user.ID)
	if err != nil {
		ui.logger.Error("list push devices", "user", user.Username, "error", err)
	}
	for _, s := range subs {
		d.PushDevices = append(d.PushDevices, view.PushDevice{ID: s.ID, Label: s.Label, Created: s.CreatedAt})
	}
}

func (ui *WebUI) handlePushDelete(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	_ = r.ParseForm()
	id := r.PostForm.Get("id")
	if err := ui.store.DeletePushSubscription(r.Context(), id, user.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "could not remove the device", http.StatusInternalServerError)
		return
	}
	ui.logger.Info("push device removed", "user", user.Username, "subscription", id)
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}
