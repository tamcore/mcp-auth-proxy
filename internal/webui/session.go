// Package webui is the multi-user web interface: username+password login with
// a signed session cookie, and a portal where a logged-in user manages their
// API keys, their own upstream MCP servers, and sees their audit log.
package webui

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

// SessionCookie is the name of the signed login cookie.
const SessionCookie = "mcp_proxy_session"

// sessionTTL is how long a web login stays valid.
const sessionTTL = 24 * time.Hour

// Sessions signs and verifies login cookies. The cookie value is
// base64(username).expiryUnix.hex(hmac-sha256(secret, payload)).
type Sessions struct {
	secret []byte
	now    func() time.Time
}

// NewSessions builds the cookie signer.
func NewSessions(secret []byte, now func() time.Time) *Sessions {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Sessions{secret: secret, now: now}
}

func (s *Sessions) sign(payload string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// Issue creates a cookie value for the user.
func (s *Sessions) Issue(username string) string {
	expiry := s.now().Add(sessionTTL).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(username)) + "." + strconv.FormatInt(expiry, 10)
	return payload + "." + s.sign(payload)
}

// Verify checks a cookie value and returns the username.
func (s *Sessions) Verify(value string) (string, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(s.sign(payload)), []byte(parts[2])) {
		return "", false
	}
	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || s.now().Unix() > expiry {
		return "", false
	}
	name, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	return string(name), true
}

// User resolves the request's session cookie to a store user.
func (s *Sessions) User(r *http.Request, st *store.Store) (*store.User, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil, false
	}
	name, ok := s.Verify(c.Value)
	if !ok {
		return nil, false
	}
	u, err := st.UserByName(r.Context(), name)
	if err != nil {
		return nil, false
	}
	return u, true
}

// Set writes the login cookie.
func Set(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    value,
		Path:     "/",
		Expires:  time.Now().Add(sessionTTL),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Clear expires the login cookie.
func Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
}

// Require redirects unauthenticated browser requests to /login.
func (s *Sessions) Require(w http.ResponseWriter, r *http.Request, st *store.Store) (*store.User, bool) {
	u, ok := s.User(r, st)
	if !ok {
		http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusFound)
		return nil, false
	}
	return u, true
}
