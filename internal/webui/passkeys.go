package webui

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

const (
	ceremonyCookie = "mcp_proxy_webauthn"
	ceremonyTTL    = 5 * time.Minute
	passkeyNameMax = 60
)

// newWebAuthn derives the relying party from base_url: the host is the RP ID,
// scheme://host[:port] the only accepted origin.
func newWebAuthn(baseURL string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Hostname() == "" {
		return nil, errors.New("webui: base_url has no host for passkeys")
	}
	return webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "mcp-auth-proxy",
		RPOrigins:     []string{u.Scheme + "://" + u.Host},
	})
}

// passkeyUser adapts a store user and their credentials to webauthn.User.
// The user handle is the opaque user ID.
type passkeyUser struct {
	user  *store.User
	creds []webauthn.Credential
}

func (p *passkeyUser) WebAuthnID() []byte                         { return []byte(p.user.ID) }
func (p *passkeyUser) WebAuthnName() string                       { return p.user.Username }
func (p *passkeyUser) WebAuthnDisplayName() string                { return p.user.Username }
func (p *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return p.creds }

func (ui *WebUI) loadPasskeyUser(r *http.Request, user *store.User) (*passkeyUser, error) {
	pks, err := ui.store.ListPasskeys(r.Context(), user.ID)
	if err != nil {
		return nil, err
	}
	pu := &passkeyUser{user: user}
	for _, p := range pks {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(p.Credential), &c); err != nil {
			return nil, err
		}
		pu.creds = append(pu.creds, c)
	}
	return pu, nil
}

type ceremony struct {
	data     webauthn.SessionData
	userID   string
	deadline time.Time
}

// ponytail: in-memory, lost on restart; the user just starts again.
type ceremonies struct {
	mu     sync.Mutex
	m      map[string]ceremony
	secure bool
}

// start stores a ceremony and sets the cookie that names it.
func (c *ceremonies) start(w http.ResponseWriter, data *webauthn.SessionData, userID string) error {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	id := base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now()
	c.mu.Lock()
	for k, v := range c.m {
		if now.After(v.deadline) {
			delete(c.m, k)
		}
	}
	c.m[id] = ceremony{data: *data, userID: userID, deadline: now.Add(ceremonyTTL)}
	c.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: ceremonyCookie, Value: id, Path: "/", MaxAge: int(ceremonyTTL / time.Second),
		HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteStrictMode})
	return nil
}

// finish removes and returns the request's ceremony if it is live and belongs
// to userID ("" for passkey login).
func (c *ceremonies) finish(r *http.Request, userID string) (*webauthn.SessionData, bool) {
	ck, err := r.Cookie(ceremonyCookie)
	if err != nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cer, ok := c.m[ck.Value]
	delete(c.m, ck.Value)
	if !ok || cer.userID != userID || time.Now().After(cer.deadline) {
		return nil, false
	}
	return &cer.data, true
}

func (ui *WebUI) passkeysOff(w http.ResponseWriter) bool {
	if ui.webauthn == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{errorField: "passkeys are not available"})
		return true
	}
	return false
}

// handlePasskeyBegin starts registering a discoverable passkey.
func (ui *WebUI) handlePasskeyBegin(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok || ui.passkeysOff(w) {
		return
	}
	pu, err := ui.loadPasskeyUser(r, user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{errorField: "could not load passkeys"})
		return
	}
	creation, data, err := ui.webauthn.BeginRegistration(pu,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(webauthn.Credentials(pu.creds).CredentialDescriptors()))
	if err == nil {
		err = ui.ceremonies.start(w, data, user.ID)
	}
	if err != nil {
		ui.logger.Error("begin passkey registration", "user", user.Username, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{errorField: "could not start"})
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

// handlePasskeyFinish verifies the attestation and stores the passkey.
func (ui *WebUI) handlePasskeyFinish(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok || ui.passkeysOff(w) {
		return
	}
	data, ok := ui.ceremonies.finish(r, user.ID)
	pu, err := ui.loadPasskeyUser(r, user)
	if !ok || err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{errorField: "registration expired; start again"})
		return
	}
	cred, err := ui.webauthn.FinishRegistration(pu, *data, r)
	if err != nil {
		ui.logger.Warn("passkey registration rejected", "user", user.Username, "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{errorField: "the passkey could not be verified"})
		return
	}
	raw, err := json.Marshal(cred)
	if err == nil {
		err = ui.store.AddPasskey(r.Context(), &store.Passkey{ID: cred.ID, UserID: user.ID,
			Name: passkeyName(r.URL.Query().Get("name")), Credential: string(raw), CreatedAt: time.Now().UTC()})
	}
	if err != nil {
		ui.logger.Error("store passkey", "user", user.Username, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{errorField: "could not save the passkey"})
		return
	}
	ui.logger.Info("passkey added", "user", user.Username)
	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/settings?done=passkey"})
}

func passkeyName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "Passkey"
	}
	if r := []rune(name); len(r) > passkeyNameMax {
		return string(r[:passkeyNameMax])
	}
	return name
}

func (ui *WebUI) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	_ = r.ParseForm()
	id, err := base64.RawURLEncoding.DecodeString(r.PostForm.Get("id"))
	if err != nil || ui.store.DeletePasskey(r.Context(), user.ID, id) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	ui.logger.Info("passkey removed", "user", user.Username)
	http.Redirect(w, r, "/settings?done=passkey-delete", http.StatusSeeOther)
}

// handleLoginPasskeyBegin starts a discoverable (username-less) login.
func (ui *WebUI) handleLoginPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	if ui.passkeysOff(w) {
		return
	}
	assertion, data, err := ui.webauthn.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err == nil {
		err = ui.ceremonies.start(w, data, "")
	}
	if err != nil {
		ui.logger.Error("begin passkey login", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{errorField: "could not start"})
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

// handleLoginPasskeyFinish verifies the assertion and logs the user in.
func (ui *WebUI) handleLoginPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	if ui.passkeysOff(w) {
		return
	}
	data, ok := ui.ceremonies.finish(r, "")
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{errorField: "login expired; try again"})
		return
	}
	found, cred, err := ui.webauthn.FinishPasskeyLogin(func(_, userHandle []byte) (webauthn.User, error) {
		u, err := ui.store.UserByID(r.Context(), string(userHandle))
		if err != nil || u.Disabled {
			return nil, errors.New("unknown or disabled user")
		}
		return ui.loadPasskeyUser(r, u)
	}, *data, r)
	if err != nil || cred.Authenticator.CloneWarning {
		ui.logger.Warn("passkey login rejected", "remote", r.RemoteAddr, "error", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{errorField: "passkey not accepted"})
		return
	}
	user := found.(*passkeyUser).user
	if raw, err := json.Marshal(cred); err == nil {
		if err := ui.store.MarkPasskeyUsed(r.Context(), cred.ID, string(raw), time.Now().UTC()); err != nil {
			ui.logger.Warn("mark passkey used", "user", user.Username, "error", err)
		}
	}
	ui.logger.Info("login ok", "user", user.Username, "method", "passkey", "remote", r.RemoteAddr)
	ui.sessions.Set(w, ui.sessions.IssueFor(user))
	writeJSON(w, http.StatusOK, map[string]string{"redirect": safeNext(r.URL.Query().Get("next"))})
}
