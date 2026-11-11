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
	return s.issueAt(username, s.now())
}

// IssueFor creates a login cookie for user that is never older than the
// user's session cutoff, so a login right after a password change holds.
func (s *Sessions) IssueFor(user *store.User) string {
	t := s.now()
	if user.SessionsSince != nil && t.Before(*user.SessionsSince) {
		t = *user.SessionsSince
	}
	return s.issueAt(user.Username, t)
}

// issueAt creates a cookie value that counts as issued at t.
func (s *Sessions) issueAt(username string, t time.Time) string {
	expiry := t.Add(sessionTTL).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(username)) + "." + strconv.FormatInt(expiry, 10)
	return payload + "." + s.sign(payload)
}

// Verify checks a cookie value and returns the username.
func (s *Sessions) Verify(value string) (string, bool) {
	name, _, ok := s.verify(value)
	return name, ok
}

// verify also returns when the cookie was issued (expiry minus the TTL).
func (s *Sessions) verify(value string) (string, int64, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return "", 0, false
	}
	payload := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(s.sign(payload)), []byte(parts[2])) {
		return "", 0, false
	}
	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || s.now().Unix() > expiry {
		return "", 0, false
	}
	name, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", 0, false
	}
	return string(name), expiry - int64(sessionTTL/time.Second), true
}

// User resolves the request's session cookie to a store user.
func (s *Sessions) User(r *http.Request, st *store.Store) (*store.User, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil, false
	}
	name, issued, ok := s.verify(c.Value)
	if !ok {
		return nil, false
	}
	u, err := st.UserByName(r.Context(), name)
	if err != nil || u.Disabled {
		return nil, false
	}
	if u.SessionsSince != nil && issued < u.SessionsSince.Unix() {
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
