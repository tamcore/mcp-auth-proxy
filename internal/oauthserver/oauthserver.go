// Package oauthserver is the client-facing OAuth 2.x authorization server:
// authorization-code + PKCE S256 (plain is rejected), exact redirect_uri match,
// only config-registered clients, 10-minute single-use in-memory authorization
// codes, and no refresh tokens in v1. It grants identity only; tool-call
// authorization always goes through the OTP gate.
package oauthserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/identity"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
	"github.com/tamcore/mcp-auth-proxy/internal/ui"
)

// authCode is a single-use, expiring in-memory authorization code.
type authCode struct {
	clientID      string
	redirectURI   string
	codeChallenge string
	keyID         string
	expiresAt     time.Time
}

// Server is the client-facing authorization server.
type Server struct {
	store  *store.Store
	cfg    *config.Config
	now    func() time.Time
	rand   io.Reader
	logger *slog.Logger
	pages  *ui.Renderer

	mu    sync.Mutex
	codes map[string]*authCode

	// CurrentUser resolves the logged-in web user for consent; set by the
	// server package. Nil means single-user mode (no user binding).
	CurrentUser func(*http.Request) *store.User
}

// New builds the AS. Clients are seeded into the store from config.
func New(ctx context.Context, st *store.Store, cfg *config.Config, pages *ui.Renderer,
	logger *slog.Logger) (*Server, error) {
	s := &Server{
		store:  st,
		cfg:    cfg,
		now:    func() time.Time { return time.Now().UTC() },
		rand:   rand.Reader,
		logger: logger,
		pages:  pages,
		codes:  map[string]*authCode{},
	}
	for i := range cfg.OAuth.Clients {
		c := &store.OAuthClient{
			ClientID:     cfg.OAuth.Clients[i].ClientID,
			Name:         cfg.OAuth.Clients[i].Name,
			RedirectURIs: cfg.OAuth.Clients[i].RedirectURIs,
			Confidential: cfg.OAuth.Clients[i].Confidential,
			CreatedAt:    s.now(),
		}
		if err := st.UpsertOAuthClient(ctx, c); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// authorizeParams are the validated query parameters of an authorize request.
type authorizeParams struct {
	clientID      string
	redirectURI   string
	codeChallenge string
	state         string
}

// HandleAuthorize serves GET /oauth/authorize: it validates the request
// fail-closed and renders the honest consent page.
func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	p, err := s.validateAuthorize(r.Context(), r.URL.Query())
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	s.renderConsent(w, r, p)
}

func (s *Server) validateAuthorize(ctx context.Context, q url.Values) (*authorizeParams, error) {
	if q.Get("response_type") != "code" {
		return nil, errors.New("response_type must be code")
	}
	clientID := q.Get("client_id")
	if clientID == "" {
		return nil, errors.New("client_id is required")
	}
	client, err := s.store.OAuthClientByID(ctx, clientID)
	if err != nil {
		return nil, errors.New("unknown client_id")
	}
	redirectURI := q.Get("redirect_uri")
	if !exactMatch(client.RedirectURIs, redirectURI) {
		return nil, errors.New("redirect_uri does not exactly match a registered URI")
	}
	if q.Get("code_challenge_method") != "S256" {
		return nil, errors.New("code_challenge_method must be S256")
	}
	if q.Get("code_challenge") == "" {
		return nil, errors.New("code_challenge is required")
	}
	return &authorizeParams{
		clientID:      clientID,
		redirectURI:   redirectURI,
		codeChallenge: q.Get("code_challenge"),
		state:         q.Get("state"),
	}, nil
}

func exactMatch(registered []string, want string) bool {
	return slices.Contains(registered, want)
}

// HandleConsent serves POST /oauth/consent: on approval it creates the OAuth
// identity key, mints a 10-minute single-use code, and redirects.
func (s *Server) HandleConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "unreadable form")
		return
	}
	p, err := s.validateAuthorize(r.Context(), r.PostForm)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	label := r.PostForm.Get("label")
	if label == "" {
		label = "oauth client " + p.clientID
	}
	key, err := s.createKey(r.Context(), label, r)
	if err != nil {
		s.logger.Error("consent: create key", "error", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "could not create identity")
		return
	}
	code, err := s.mintCode(p, key.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "could not mint code")
		return
	}
	loc, err := url.Parse(p.redirectURI)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "unparsable redirect_uri")
		return
	}
	q := loc.Query()
	q.Set("code", code)
	if p.state != "" {
		q.Set("state", p.state)
	}
	loc.RawQuery = q.Encode()
	http.Redirect(w, r, loc.String(), http.StatusFound)
}

func (s *Server) createKey(ctx context.Context, label string, r *http.Request) (*store.Key, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(s.rand, raw); err != nil {
		return nil, err
	}
	key := &store.Key{
		ID:         "k_" + hex.EncodeToString(raw[:8]),
		Kind:       store.KeyKindOAuth,
		Label:      label,
		SecretHash: store.HashSecret("oauth-identity-" + hex.EncodeToString(raw)),
		Upstreams:  s.cfg.UpstreamNames(),
		TTLSeconds: int64(s.cfg.SessionTTL / time.Second),
		CreatedAt:  s.now(),
	}
	if s.CurrentUser != nil {
		if u := s.CurrentUser(r); u != nil {
			key.UserID = &u.ID
			key.Upstreams = allowedUpstreamNames(s.cfg, u.Username)
		}
	}
	if err := s.store.CreateKey(ctx, key); err != nil {
		return nil, err
	}
	return key, nil
}

// allowedUpstreamNames returns the global upstreams a user may use.
func allowedUpstreamNames(cfg *config.Config, username string) []string {
	var out []string
	for _, u := range cfg.Upstreams {
		if u.Allows(username) {
			out = append(out, u.Name)
		}
	}
	return out
}

func (s *Server) mintCode(p *authorizeParams, keyID string) (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(s.rand, raw); err != nil {
		return "", err
	}
	code := hex.EncodeToString(raw)
	s.mu.Lock()
	for c, ac := range s.codes {
		if !s.now().Before(ac.expiresAt) {
			delete(s.codes, c)
		}
	}
	s.codes[code] = &authCode{
		clientID:      p.clientID,
		redirectURI:   p.redirectURI,
		codeChallenge: p.codeChallenge,
		keyID:         keyID,
		expiresAt:     s.now().Add(s.cfg.OAuth.AuthorizeCodeTTL),
	}
	s.mu.Unlock()
	return code, nil
}

// HandleToken serves POST /oauth/token (form-encoded). It verifies the code,
// PKCE S256, and redirect_uri, then issues a map_ access token.
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "unreadable form")
		return
	}
	f := r.PostForm
	if f.Get("grant_type") != "authorization_code" {
		s.writeError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code")
		return
	}
	code := f.Get("code")
	ac, ok := s.takeCode(code)
	if !ok {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "unknown, used, or expired code")
		return
	}
	if f.Get("client_id") != ac.clientID {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}
	if f.Get("redirect_uri") != ac.redirectURI {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if !verifyPKCE(f.Get("code_verifier"), ac.codeChallenge) {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	token, expires, err := s.issueToken(r.Context(), ac.keyID, ac.clientID)
	if err != nil {
		s.logger.Error("token: issue", "error", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int64(time.Until(expires).Seconds()),
	})
}

// takeCode removes the code (single-use) and checks expiry.
func (s *Server) takeCode(code string) (*authCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.codes[code]
	delete(s.codes, code)
	if !ok || !s.now().Before(ac.expiresAt) {
		return nil, false
	}
	return ac, true
}

func verifyPKCE(verifier, challenge string) bool {
	if verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

func (s *Server) issueToken(ctx context.Context, keyID, clientID string) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(s.rand, raw); err != nil {
		return "", time.Time{}, err
	}
	token := identity.OAuthPrefix + hex.EncodeToString(raw)
	expires := s.now().Add(s.cfg.OAuth.TokenTTL)
	at := &store.AccessToken{
		TokenHash: store.HashSecret(token),
		KeyID:     keyID,
		ClientID:  clientID,
		ExpiresAt: expires,
		CreatedAt: s.now(),
	}
	if err := s.store.CreateAccessToken(ctx, at); err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

func (s *Server) writeError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}
